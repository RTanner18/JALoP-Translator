#!/usr/bin/env python3

import argparse
import base64
import hashlib
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    CRYPTO_OK = True
except Exception:
    CRYPTO_OK = False

DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("utf-8")


def parse_xml_file(path: Path):
    try:
        data = path.read_bytes()
        root = ET.fromstring(data)
        return data, root
    except Exception as exc:
        raise RuntimeError(f"Failed to parse XML file {path}: {exc}") from exc


def get_namespace(tag: str) -> str | None:
    if tag.startswith("{") and "}" in tag:
        return tag[1:].split("}")[0]
    return None


def build_ns(root):
    jal_ns = get_namespace(root.tag)
    ns = {}
    if jal_ns:
        ns["jal"] = jal_ns
    ns["ds"] = DSIG_NS
    return ns


def find_text(parent, path: str, ns=None, default: str = "-") -> str:
    elem = parent.find(path, ns or {})
    if elem is None or elem.text is None:
        return default
    return elem.text.strip()


def detect_metadata_section(root, ns) -> str:
    for name in ("SyslogMetadata", "AuditMetadata", "JournalMetadata"):
        elem = root.find(f".//jal:{name}", ns)
        if elem is not None:
            return name
    return "UnknownMetadata"


def extract_metadata_fields(root):
    ns = build_ns(root)
    section_name = detect_metadata_section(root, ns)

    if section_name == "UnknownMetadata":
        meta = None
    else:
        meta = root.find(f".//jal:{section_name}", ns)

    result = {
        "metadata_type": section_name,
        "jal_entry_id": find_text(meta, "jal:JalEntryId", ns) if meta is not None else "-",
        "timestamp": find_text(meta, "jal:Timestamp", ns) if meta is not None else "-",
        "hostname": find_text(meta, "jal:Hostname", ns) if meta is not None else "-",
        "application_name": find_text(meta, "jal:ApplicationName", ns) if meta is not None else "-",
        "process_id": find_text(meta, "jal:ProcessID", ns) if meta is not None else "-",
        "message_id": find_text(meta, "jal:MessageID", ns) if meta is not None else "-",
        "severity": find_text(meta, "jal:Severity", ns) if meta is not None else "-",
        "facility": find_text(meta, "jal:Facility", ns) if meta is not None else "-",
        "integrity_hash_hex": find_text(root, ".//jal:IntegrityMetadata/jal:Hash", ns, default=""),
        "signature_present": root.find(".//ds:Signature", ns) is not None,
    }
    return result, ns


def extract_payload_fields(payload_root):
    # payload is plain <entry> ... </entry> with no namespace
    return {
        "timestamp": find_text(payload_root, "timestamp"),
        "hostname": find_text(payload_root, "hostname"),
        "appname": find_text(payload_root, "appname"),
        "procid": find_text(payload_root, "procid"),
        "msgid": find_text(payload_root, "msgid"),
        "severity": find_text(payload_root, "severity"),
        "facility": find_text(payload_root, "facility"),
        "message": find_text(payload_root, "message"),
    }


def verify_integrity_hash(metadata_root, metadata_ns, payload_bytes: bytes):
    expected = find_text(metadata_root, ".//jal:IntegrityMetadata/jal:Hash", metadata_ns, default="")
    if not expected:
        return False, expected, ""
    computed = sha256_hex(payload_bytes)
    return expected == computed, expected, computed


def verify_digest_value(metadata_root, metadata_ns, payload_bytes: bytes):
    digest_elem = metadata_root.find(".//ds:Reference/ds:DigestValue", metadata_ns)
    if digest_elem is None or digest_elem.text is None:
        return None, None, None
    expected_b64 = digest_elem.text.strip()
    computed_b64 = sha256_b64(payload_bytes)
    return expected_b64 == computed_b64, expected_b64, computed_b64


def verify_signature(metadata_root, metadata_ns, payload_bytes: bytes, public_key_path: Path):
    sig_elem = metadata_root.find(".//ds:Signature", metadata_ns)
    if sig_elem is None:
        return None, "No ds:Signature present"

    sig_val_elem = sig_elem.find("ds:SignatureValue", metadata_ns)
    if sig_val_elem is None or not sig_val_elem.text:
        return False, "SignatureValue missing"

    if not CRYPTO_OK:
        return None, "cryptography package not installed"

    if not public_key_path.exists():
        return None, f"Public key not found: {public_key_path}"

    try:
        signature_bytes = base64.b64decode(sig_val_elem.text.strip())
        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())

        # Matches your receiver behavior: verify RSA-SHA256 over raw payload bytes
        public_key.verify(
            signature_bytes,
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True, "Signature verified"
    except Exception as exc:
        return False, f"Signature verification failed: {exc}"


def resolve_paths(first_arg: str, second_arg: str | None):
    p1 = Path(first_arg)

    # Case 1: metadata and payload both provided
    if second_arg is not None:
        return Path(first_arg), Path(second_arg)

    # Case 2: metadata path only
    if p1.name.endswith("_metadata.xml"):
        payload_guess = p1.with_name(p1.name.replace("_metadata.xml", "_payload.xml"))
        return p1, payload_guess

    # Case 3: prefix path
    prefix = str(p1)
    metadata = Path(prefix + "_metadata.xml")
    payload = Path(prefix + "_payload.xml")
    return metadata, payload


def print_block(title: str):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Read and verify a JALoP record.")
    parser.add_argument("input1", help="Metadata file path, or record prefix")
    parser.add_argument("input2", nargs="?", help="Optional payload file path")
    parser.add_argument(
        "--public-key",
        default="public.pem",
        help="Path to RSA public key PEM file (default: public.pem)"
    )
    args = parser.parse_args()

    metadata_path, payload_path = resolve_paths(args.input1, args.input2)

    if not metadata_path.exists():
        print(f"ERROR: metadata file not found: {metadata_path}")
        sys.exit(1)

    if not payload_path.exists():
        print(f"ERROR: payload file not found: {payload_path}")
        sys.exit(1)

    metadata_bytes, metadata_root = parse_xml_file(metadata_path)
    payload_bytes, payload_root = parse_xml_file(payload_path)

    meta_fields, ns = extract_metadata_fields(metadata_root)
    payload_fields = extract_payload_fields(payload_root)

    print_block("JALOP RECORD SUMMARY")
    print(f"Metadata file : {metadata_path}")
    print(f"Payload file  : {payload_path}")
    print(f"Metadata type : {meta_fields['metadata_type']}")
    print(f"JAL Entry ID  : {meta_fields['jal_entry_id']}")

    print_block("APPLICATION METADATA")
    print(f"Timestamp     : {meta_fields['timestamp']}")
    print(f"Hostname      : {meta_fields['hostname']}")
    print(f"Application   : {meta_fields['application_name']}")
    print(f"Process ID    : {meta_fields['process_id']}")
    print(f"Message ID    : {meta_fields['message_id']}")
    print(f"Severity      : {meta_fields['severity']}")
    print(f"Facility      : {meta_fields['facility']}")
    print(f"Signature     : {'present' if meta_fields['signature_present'] else 'not present'}")

    print_block("PAYLOAD")
    print(f"Timestamp     : {payload_fields['timestamp']}")
    print(f"Hostname      : {payload_fields['hostname']}")
    print(f"App Name      : {payload_fields['appname']}")
    print(f"Proc ID       : {payload_fields['procid']}")
    print(f"Msg ID        : {payload_fields['msgid']}")
    print(f"Severity      : {payload_fields['severity']}")
    print(f"Facility      : {payload_fields['facility']}")
    print(f"Message       : {payload_fields['message']}")

    print_block("VERIFICATION")

    ok_hash, expected_hash, computed_hash = verify_integrity_hash(metadata_root, ns, payload_bytes)
    print(f"Integrity Hash Expected : {expected_hash}")
    print(f"Integrity Hash Computed : {computed_hash}")
    print(f"Integrity Hash Status   : {'PASS' if ok_hash else 'FAIL'}")

    ok_digest, expected_digest, computed_digest = verify_digest_value(metadata_root, ns, payload_bytes)
    if ok_digest is None:
        print("DigestValue Status      : NOT PRESENT")
    else:
        print(f"DigestValue Expected    : {expected_digest}")
        print(f"DigestValue Computed    : {computed_digest}")
        print(f"DigestValue Status      : {'PASS' if ok_digest else 'FAIL'}")

    sig_ok, sig_msg = verify_signature(
        metadata_root,
        ns,
        payload_bytes,
        Path(args.public_key)
    )
    if sig_ok is None:
        print(f"Signature Status        : SKIPPED ({sig_msg})")
    else:
        print(f"Signature Status        : {'PASS' if sig_ok else 'FAIL'}")
        print(f"Signature Details       : {sig_msg}")

    print_block("FINAL RESULT")
    final_ok = ok_hash and (ok_digest in (True, None)) and (sig_ok in (True, None))
    print("Record Verification     :", "PASS" if final_ok else "FAIL")


if __name__ == "__main__":
    main()
