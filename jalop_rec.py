#!/usr/bin/env python3
"""
jalop_receiver.py - Simple JALoP 2.0 HTTP store receiver

Listens for POST requests from omjalop and saves records to local files.

Usage:
    python3 jalop_receiver.py [port]   (default port: 9000)

Records are saved to ./jalop_records/<type>/<jal-id>.xml
"""
import hashlib
import xml.etree.ElementTree as ET
import http.server
import os
import sys
from datetime import datetime

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
RECORD_DIR = "./jalop_records"
PUBLIC_KEY_PATH = "./public.pem"   # must match signing key

def parse_multipart(content_type, body):
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[len("boundary="):]
            break
    if not boundary:
        return []

    boundary = boundary.encode()
    parts = []
    raw_parts = body.split(b"--" + boundary)
    for raw in raw_parts[1:]:
        if raw.strip() == b"--":
            break
        if raw.startswith(b"\r\n"):
            raw = raw[2:]
        if b"\r\n\r\n" in raw:
            hdr_raw, content = raw.split(b"\r\n\r\n", 1)
            parts.append((hdr_raw.decode(errors="replace"), content))
    return parts

def verify_payload_hash(metadata_xml_bytes, payload_bytes):
    try:
        root = ET.fromstring(metadata_xml_bytes)
        ns = {"jal": root.tag.split("}")[0].strip("{")}
        hash_elem = root.find(".//jal:IntegrityMetadata/jal:Hash", ns)
        if hash_elem is None:
            return (None, None, False)
        expected_hash = hash_elem.text.strip()
        computed_hash = hashlib.sha256(payload_bytes).hexdigest()
        return (expected_hash, computed_hash, expected_hash == computed_hash)
    except Exception as e:
        print(f"  Hash verification error: {e}")
        return (None, None, False)

def verify_signature(metadata_xml_bytes, payload_bytes):
    try:
        root = ET.fromstring(metadata_xml_bytes)
        ns = {"jal": root.tag.split("}")[0].strip("{")}

        sig_elem = root.find(".//jal:IntegrityMetadata/jal:Signature", ns)
        hash_elem = root.find(".//jal:IntegrityMetadata/jal:Hash", ns)

        if sig_elem is None or not sig_elem.text:
            print("No signature present")
            return False

        signature = base64.b64decode(sig_elem.text.strip())
        payload_hash = hash_elem.text.strip()

        data_to_verify = payload_hash.encode()

        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        public_key.verify(
            signature,
            data_to_verify,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return True

    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

class JALoPHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {format % args}")

    def do_POST(self):
        # Determine record type from path
        path = self.path.rstrip("/")
        if path == "/log":
            rec_type = "log"
        elif path == "/audit":
            rec_type = "audit"
        elif path == "/journal":
            rec_type = "journal"
        else:
            self.send_response(404)
            self.end_headers()
            print(f"Unknown path: {self.path}")
            return

        # Read JALoP headers
        jal_id      = self.headers.get("JAL-Id", "unknown")
        jal_message = self.headers.get("JAL-Message", "")
        meta_len    = self.headers.get("JAL-Application-Metadata-Length", "0")
        payload_len = self.headers.get("JAL-Payload-Length", "0")
        content_type = self.headers.get("Content-Type", "")

        print(f"  JAL-Id:      {jal_id}")
        print(f"  JAL-Message: {jal_message}")
        print(f"  Meta-Length: {meta_len}")
        print(f"  Payload-Len: {payload_len}")
        print(f"  Type:        {rec_type}")

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Parse multipart body
        parts = parse_multipart(content_type, body)

        # Save to files
        out_dir = os.path.join(RECORD_DIR, rec_type)
        os.makedirs(out_dir, exist_ok=True)

        safe_id = jal_id.replace("/", "_").replace("\\", "_")

        metadata_bytes = None
        payload_bytes = None

        if len(parts) >= 1:
            metadata_bytes = parts[0][1]
            meta_path = os.path.join(out_dir, f"{safe_id}_metadata.xml")
            with open(meta_path, "wb") as f:
                f.write(parts[0][1])
            print(f"  Saved metadata: {meta_path}")

        if len(parts) >= 2:
            payload_bytes = parts[1][1]
            payload_path = os.path.join(out_dir, f"{safe_id}_payload.xml")
            with open(payload_path, "wb") as f:
                f.write(parts[1][1])
            print(f"  Saved payload:  {payload_path}")

        if len(parts) >= 2:
            expected, computed, ok = verify_payload_hash(
                metadata_bytes,
                payload_bytes
            )
            if not ok:
                self.send_response(400)
                self.end_headers()
                print("  ERROR: payload hash mismatch")
                return

            # Signature check
            if not verify_signature(metadata_bytes, payload_bytes):
                self.send_response(400)
                self.end_headers()
                print("  ERROR: signature verification failed")
                return

            print("  Signature verification OK")

        # Respond 200 OK
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")
        print(f"  -> 200 OK")


def main():
    os.makedirs(RECORD_DIR, exist_ok=True)
    server = http.server.HTTPServer(("0.0.0.0", PORT), JALoPHandler)
    print(f"JALoP receiver listening on port {PORT}")
    print(f"Saving records to {os.path.abspath(RECORD_DIR)}/")
    print(f"Endpoints: POST /log  /audit  /journal")
    print("-" * 50)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()