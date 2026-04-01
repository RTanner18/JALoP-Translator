# JALoP Translator Output Module
omjalop is a custom rsyslog output module that sends log records to a JALoP 2.0 compliant HTTP log store.

It converts rsyslog messages into JALoP records, generates the required ApplicationMetadata, computes SHA-256 payload hashes, optionally signs records using XML Digital Signatures (XMLDSig), and delivers them to a remote HTTP endpoint using multipart/mixed POST requests.

A companion Python utility (jalop_receiver.py) is included to act as a test JALoP HTTP store.

# Setup Walkthrough

## Compile the JALoP Module
Retrieve and generate all required header files to compile the Output Module.\
<small>*Note: this process requires many libraries. Install as needed*</small>
### 1) Cloning and building rsyslog repo
```
git clone https://github.com/rsyslog/rsyslog
cd rsyslog
./autogen.sh
make
```

### 2) Configure Makefile
Set SYSLOG_DIR(line 3) of the omjalop Makefile to point to the root of the built rsyslog repo. This points the module to all required header files to build.

### 3) Make the OM and move to the daemon

At the root of the omjalop repo:
```
make
sudo cp omjalop.so /usr/local/lib/rsyslog/
sudo systemctl restart syslog
```
## rsyslogd Setup
### 1) Append the following to `/etc/rsyslog.conf`
```
template(name="syslog-xml" type="string" string="<entry>\
<timestamp>%TIMESTAMP:::date-rfc3339%</timestamp>\
<hostname>%HOSTNAME%</hostname>\
<appname>%APP-NAME%</appname>\
<procid>%PROCID%</procid>\
<msgid>%MSGID%</msgid>\
<severity>%syslogseverity-text%</severity>\
<facility>%syslogfacility-text%</facility>\
<message>%msg%</message>\
</entry>\n")

template(name="auditd-xml" type="string" string="<entry>\
<timestamp>%TIMESTAMP:::date-rfc3339%</timestamp>\
<hostname>%HOSTNAME%</hostname>\
<appname>auditd</appname>\
<procid>%$!audit_pid%</procid>\
<msgid>%$!audit_msgid%</msgid>\
<severity>info</severity>\
<facility>audit</facility>\
<message>%msg%</message>\
</entry>\n")

if ($msg contains "audit(") then {
    set $!audit_pid = re_extract($msg,"pid=([0-9]+)",0, 1, "-");
    set $!audit_msgid = re_extract($msg, "audit\\([0-9\\.]+:([0-9]+)\\)", 0, 1, "0");
    action(
        type="omjalop"
        jalop_url="http://localhost:9000"
        jalop_type="audit"
        signing_key="/usr/local/lib/rsyslog/private.pem"
        template="auditd-xml"
    )
    stop
}

action(
    type="omjalop"
    jalop_url="http://localhost:9000"
    jalop_type="log"
    signing_key="/usr/local/lib/rsyslog/private.pem"
    template="syslog-xml"
)
```
### 2) Private/Public Key Generation
This generates the key pair for the log signature to verify ownership integrity.

Private key for omjalop:
```
sudo openssl genpkey -algorithm RSA -out /usr/local/lib/rsyslog/private.pem -pkeyopt rsa_keygen_bits:2048
sudo chown syslog:syslog /usr/local/lib/rsyslog/private.pem
sudo chmod 755 /usr/local/lib
sudo chmod 755 /usr/local/lib/rsyslog
sudo chmod 600 /usr/local/lib/rsyslog/private.pem
```

Public key for HTTP receiver:
```
sudo openssl rsa -in /usr/local/lib/rsyslog/private.pem -pubout -out public.pem
```

### 3) Verify config and restart daemon
Verify: 
```
sudo /usr/local/sbin/rsyslogd -N1
```
Then restart:
```
sudo systemctl restart syslog
systemctl status syslog
```

Verify the daemon is active and running.\
<small>*Note: the logs will show a curl POST failed. That is normal behavior as the JALoP reader is not configured yet.*</small>

## auditd Setup

Open config file at `/etc/audit/plugins.d/syslog.conf` and toggle the `active` parameter to `active = yes`

Restart auditd with `sudo systemctl restart auditd`
* This routes copies auditd traffic to the syslog daemon to be converted to XML

## JALoP Receiver Config

JALoP receiver acts as the HTTP endpoint to receive and verify JALoP log integrity. The script can receive logs locally or over the network per requirements. 


## Remaining Stuff to Implement

* Metadata and Payload Reader
* TLS config
* Using the default OS syslog rather than having to clone, recompile, and override the module.



