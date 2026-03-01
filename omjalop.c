/* omjalop.c - rsyslog output module: custom XML → JALoP 2.0 (HTTP)
 *
 * Dependencies: libxml2, libcurl, libuuid
 *
 * Build:
 *   gcc -shared -fPIC -o omjalop.so omjalop.c \
 *       -I/path/to/rsyslog \
 *       -I/path/to/rsyslog/runtime \
 *       -I/path/to/rsyslog/grammar \
 *       -I/usr/include/json-c \
 *       -I/usr/include/libxml2 \
 *       $(pkg-config --cflags --libs libxml-2.0 libcurl) \
 *       -luuid
 *
 * rsyslog.conf:
 *   module(load="/usr/lib/rsyslog/omjalop.so")
 *
 *   template(name="MyXML" type="string" string="<entry>
 *     <timestamp>%TIMESTAMP:::date-rfc3339%</timestamp>
 *     <hostname>%HOSTNAME%</hostname>
 *     <appname>%APP-NAME%</appname>
 *     <procid>%PROCID%</procid>
 *     <msgid>%MSGID%</msgid>
 *     <severity>%syslogseverity-text%</severity>
 *     <facility>%syslogfacility-text%</facility>
 *     <message>%msg%</message>
 *   </entry>\n")
 *
 *   action(type="omjalop"
 *          jalop_url="http://localhost:9000"
 *          jalop_type="log"
 *          tls_cert="/etc/ssl/jalop/client.crt"
 *          tls_key="/etc/ssl/jalop/client.key"
 *          tls_ca="/etc/ssl/jalop/ca.crt"
 *          template="MyXML")
 */

#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <curl/curl.h>

#include "conf.h"
#include "syslogd-types.h"
#include "template.h"
#include "module-template.h"
#include "cfsysline.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omjalop")

DEF_OMOD_STATIC_DATA

/* ------------------------------------------------------------------ */
/* JALoP 2.0 record types                                              */
/* ------------------------------------------------------------------ */
typedef enum {
    JALOP_LOG    = 0,   /* syslog / application log  */
    JALOP_AUDIT  = 1,   /* audit record              */
    JALOP_JOURNAL= 2,   /* journal / binary blob     */
} jalop_rectype_t;

/* ------------------------------------------------------------------ */
/* Instance data (per action{} block)                                  */
/* ------------------------------------------------------------------ */
typedef struct _instanceData {
    uchar           *jalop_url;     /* base URL of JALoP HTTP store   */
    jalop_rectype_t  rectype;       /* log | audit | journal          */
    uchar           *tls_cert;      /* client cert path (optional)    */
    uchar           *tls_key;       /* client key  path (optional)    */
    uchar           *tls_ca;        /* CA bundle   path (optional)    */
    uchar           *tplName;       /* template name                  */
    int              tls_verify;    /* verify peer cert? default 1    */
} instanceData;

typedef struct wrkrInstanceData {
    instanceData *pData;
    CURL         *curl;             /* per-worker curl handle         */
} wrkrInstanceData_t;

/* ------------------------------------------------------------------ */
/* Config parameter descriptors                                        */
/* ------------------------------------------------------------------ */
static struct cnfparamdescr actpdescr[] = {
    { "jalop_url",   eCmdHdlrGetWord, CNFPARAM_REQUIRED },
    { "jalop_type",  eCmdHdlrGetWord, 0 },   /* log|audit|journal, default log */
    { "tls_cert",    eCmdHdlrGetWord, 0 },
    { "tls_key",     eCmdHdlrGetWord, 0 },
    { "tls_ca",      eCmdHdlrGetWord, 0 },
    { "tls_verify",  eCmdHdlrBinary,  0 },
    { "template",    eCmdHdlrGetWord, 0 },
};
static struct cnfparamblk actpblk = {
    CNFPARAMBLK_VERSION,
    sizeof(actpdescr) / sizeof(struct cnfparamdescr),
    actpdescr
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static char *gen_uuid(void) {
    uuid_t uu;
    char  *buf = malloc(37);
    if (!buf) return NULL;
    uuid_generate(uu);
    uuid_unparse_lower(uu, buf);
    return buf;
}

static char *xpath_str(xmlXPathContextPtr ctx, const char *expr,
                        const char *fallback) {
    xmlXPathObjectPtr obj = xmlXPathEvalExpression(
                                (const xmlChar *)expr, ctx);
    if (!obj) return strdup(fallback);
    if (obj->nodesetval && obj->nodesetval->nodeNr > 0) {
        xmlChar *val = xmlNodeGetContent(
                           obj->nodesetval->nodeTab[0]);
        char *ret = strdup(val ? (char *)val : fallback);
        xmlFree(val);
        xmlXPathFreeObject(obj);
        return ret;
    }
    xmlXPathFreeObject(obj);
    return strdup(fallback);
}

static size_t curl_discard(void *ptr, size_t size, size_t nmemb,
                            void *userdata) {
    (void)ptr; (void)userdata;
    return size * nmemb;
}

/* ------------------------------------------------------------------ */
/* Build JALoP 2.0 application-metadata XML                           */
/* ------------------------------------------------------------------ */
static char *build_app_metadata(const char *timestamp,
                                 const char *hostname,
                                 const char *appname,
                                 const char *procid,
                                 const char *msgid,
                                 const char *severity,
                                 const char *facility,
                                 const char *jalop_id,
                                 jalop_rectype_t rectype)
{
    const char *ns = "http://www.jalop.net/jalop/2.0";
    char *meta = NULL;
    int len;

    const char *inner_open  = (rectype == JALOP_LOG)
                                ? "SyslogMetadata"
                                : (rectype == JALOP_AUDIT)
                                    ? "AuditMetadata"
                                    : "JournalMetadata";
    const char *inner_close = inner_open;

    len = asprintf(&meta,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<JALRecord xmlns=\"%s\">\n"
        "  <ApplicationMetadata>\n"
        "    <%s>\n"
        "      <JalEntryId>%s</JalEntryId>\n"
        "      <Timestamp>%s</Timestamp>\n"
        "      <Hostname>%s</Hostname>\n"
        "      <ApplicationName>%s</ApplicationName>\n"
        "      <ProcessID>%s</ProcessID>\n"
        "      <MessageID>%s</MessageID>\n"
        "      <Severity>%s</Severity>\n"
        "      <Facility>%s</Facility>\n"
        "    </%s>\n"
        "  </ApplicationMetadata>\n"
        "</JALRecord>\n",
        ns,
        inner_open,
        jalop_id,
        timestamp,
        hostname,
        appname,
        procid,
        msgid,
        severity,
        facility,
        inner_close);

    if (len < 0) return NULL;
    return meta;
}

/* ------------------------------------------------------------------ */
/* POST one JALoP 2.0 record                                          */
/* ------------------------------------------------------------------ */
static rsRetVal post_jalop_record(wrkrInstanceData_t *pWrkrData,
                                   const char *app_meta,
                                   const char *payload,
                                   const char *jalop_id)
{
    DEFiRet;
    instanceData *pData = pWrkrData->pData;
    CURL         *curl  = pWrkrData->curl;
    char         *url   = NULL;
    struct curl_slist *hdrs = NULL;
    char hdr_buf[256];

    const char *boundary = "jalop2boundary";
    char *body = NULL;
    int   body_len;

    const char *path = (pData->rectype == JALOP_LOG)     ? "/log"
                     : (pData->rectype == JALOP_AUDIT)   ? "/audit"
                                                          : "/journal";
    if (asprintf(&url, "%s%s", (char *)pData->jalop_url, path) < 0)
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);

    body_len = asprintf(&body,
        "--%s\r\n"
        "Content-Type: application/xml\r\n\r\n"
        "%s\r\n"
        "--%s\r\n"
        "Content-Type: application/xml\r\n\r\n"
        "%s\r\n"
        "--%s--\r\n",
        boundary, app_meta,
        boundary, payload,
        boundary);
    if (body_len < 0) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);

    hdrs = curl_slist_append(hdrs, "JAL-Message: log-record");

    snprintf(hdr_buf, sizeof(hdr_buf), "JAL-Id: %s", jalop_id);
    hdrs = curl_slist_append(hdrs, hdr_buf);

    snprintf(hdr_buf, sizeof(hdr_buf),
             "JAL-Application-Metadata-Length: %zu", strlen(app_meta));
    hdrs = curl_slist_append(hdrs, hdr_buf);

    snprintf(hdr_buf, sizeof(hdr_buf),
             "JAL-Payload-Length: %zu", strlen(payload));
    hdrs = curl_slist_append(hdrs, hdr_buf);

    snprintf(hdr_buf, sizeof(hdr_buf),
             "Content-Type: multipart/mixed; boundary=%s", boundary);
    hdrs = curl_slist_append(hdrs, hdr_buf);

    curl_easy_setopt(curl, CURLOPT_URL,            url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,  (long)body_len);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curl_discard);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        10L);

    if (pData->tls_cert)
        curl_easy_setopt(curl, CURLOPT_SSLCERT, (char *)pData->tls_cert);
    if (pData->tls_key)
        curl_easy_setopt(curl, CURLOPT_SSLKEY,  (char *)pData->tls_key);
    if (pData->tls_ca)
        curl_easy_setopt(curl, CURLOPT_CAINFO,  (char *)pData->tls_ca);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
                     pData->tls_verify ? 1L : 0L);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_ERR,
            "omjalop: curl POST failed: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200 && http_code != 204) {
        LogError(0, RS_RET_ERR,
            "omjalop: JALoP store returned HTTP %ld", http_code);
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    }

finalize_it:
    free(url);
    free(body);
    curl_slist_free_all(hdrs);
    RETiRet;
}

/* ------------------------------------------------------------------ */
/* rsyslog module lifecycle                                            */
/* ------------------------------------------------------------------ */

BEGINcreateInstance
CODESTARTcreateInstance
    pData->tls_verify = 1;
ENDcreateInstance

BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
    pWrkrData->pData = pData;
    pWrkrData->curl  = curl_easy_init();
    if (!pWrkrData->curl)
        ABORT_FINALIZE(RS_RET_ERR);
finalize_it:
ENDcreateWrkrInstance

BEGINfreeInstance
CODESTARTfreeInstance
    free(pData->jalop_url);
    free(pData->tls_cert);
    free(pData->tls_key);
    free(pData->tls_ca);
    free(pData->tplName);
ENDfreeInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
    if (pWrkrData->curl)
        curl_easy_cleanup(pWrkrData->curl);
ENDfreeWrkrInstance

BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
    dbgprintf("omjalop target=%s type=%d\n",
              pData->jalop_url, pData->rectype);
ENDdbgPrintInstInfo

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature

/* tryResume — called by rsyslog when an action is suspended           */
BEGINtryResume
CODESTARTtryResume
    /* Always signal OK to retry; curl will fail again if still down  */
    iRet = RS_RET_OK;
ENDtryResume

/* ------------------------------------------------------------------ */
/* doAction — called for every matching log line                       */
/* ------------------------------------------------------------------ */
BEGINdoAction
    instanceData *pData = pWrkrData->pData;
    const char   *xml_in = (const char *)ppString[0];
CODESTARTdoAction

    xmlDocPtr  doc = xmlReadMemory(xml_in, (int)strlen(xml_in),
                                   "rsyslog.xml", NULL,
                                   XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!doc) {
        LogError(0, RS_RET_ERR,
            "omjalop: failed to parse input XML: %s", xml_in);
        ABORT_FINALIZE(RS_RET_ERR);
    }

    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    if (!ctx) { xmlFreeDoc(doc); ABORT_FINALIZE(RS_RET_ERR); }

    char *timestamp = xpath_str(ctx, "/entry/timestamp",  "1970-01-01T00:00:00Z");
    char *hostname  = xpath_str(ctx, "/entry/hostname",   "unknown");
    char *appname   = xpath_str(ctx, "/entry/appname",    "-");
    char *procid    = xpath_str(ctx, "/entry/procid",     "-");
    char *msgid     = xpath_str(ctx, "/entry/msgid",      "-");
    char *severity  = xpath_str(ctx, "/entry/severity",   "notice");
    char *facility  = xpath_str(ctx, "/entry/facility",   "user");

    xmlXPathFreeContext(ctx);

    char *jalop_id = gen_uuid();
    if (!jalop_id) { xmlFreeDoc(doc); ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY); }

    char *app_meta = build_app_metadata(timestamp, hostname, appname,
                                         procid, msgid, severity, facility,
                                         jalop_id, pData->rectype);

    iRet = post_jalop_record(pWrkrData, app_meta, xml_in, jalop_id);

    free(timestamp); free(hostname); free(appname);
    free(procid);    free(msgid);    free(severity);
    free(facility);  free(jalop_id); free(app_meta);
    xmlFreeDoc(doc);

finalize_it:
ENDdoAction

/* ------------------------------------------------------------------ */
/* Config parsing (RainerScript)                                       */
/* ------------------------------------------------------------------ */
BEGINnewActInst
    struct cnfparamvals *pvals;
    int i;
    CODESTARTnewActInst;
    if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }
    CHKiRet(createInstance(&pData));
    pData->tls_verify = 1;  /* set defaults */
    CODE_STD_STRING_REQUESTnewActInst(1);
    for (i = 0; i < actpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;

        if (!strcmp(actpblk.descr[i].name, "jalop_url")) {
            pData->jalop_url = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);

        } else if (!strcmp(actpblk.descr[i].name, "jalop_type")) {
            char *t = es_str2cstr(pvals[i].val.d.estr, NULL);
            if      (!strcasecmp(t, "audit"))   pData->rectype = JALOP_AUDIT;
            else if (!strcasecmp(t, "journal")) pData->rectype = JALOP_JOURNAL;
            else                                pData->rectype = JALOP_LOG;
            free(t);

        } else if (!strcmp(actpblk.descr[i].name, "tls_cert")) {
            pData->tls_cert = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);

        } else if (!strcmp(actpblk.descr[i].name, "tls_key")) {
            pData->tls_key  = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);

        } else if (!strcmp(actpblk.descr[i].name, "tls_ca")) {
            pData->tls_ca   = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);

        } else if (!strcmp(actpblk.descr[i].name, "tls_verify")) {
            pData->tls_verify = (int)pvals[i].val.d.n;

        } else if (!strcmp(actpblk.descr[i].name, "template")) {
            pData->tplName = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        }
    }
    CHKiRet(OMSRsetEntry(*ppOMSR, 0,
        (uchar *)strdup((pData->tplName == NULL) ? "RSYSLOG_FileFormat" : (char *)pData->tplName),
        OMSR_NO_RQD_TPL_OPTS));
    CODE_STD_FINALIZERnewActInst;
    cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINparseSelectorAct
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct

BEGINmodExit
CODESTARTmodExit
    curl_global_cleanup();
    xmlCleanupParser();
ENDmodExit

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit;
    *ipIFVersProvided = CURR_MOD_IF_VERSION;
    curl_global_init(CURL_GLOBAL_ALL);
    xmlInitParser();
ENDmodInit