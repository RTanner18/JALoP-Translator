#!/usr/bin/env python3
"""
jalop_receiver.py - JALoP 2.0 HTTP store receiver

Listens for POST requests from omjalop and saves records to local files.

Usage:
    python3 jalop_receiver.py [port]   (default port: 9000)

Records are saved to ./jalop_records/<type>/<jal-id>_{metadata,payload}.xml
"""
import base64
import hashlib
import http.server
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PORT           = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
RECORD_DIR     = "./jalop_records"
PUBLIC_KEY_PATH = "./public.pem"   # must match the sender's signing key

# ---------------------------------------------------------------------------
# Multipart parsing
# ---------------------------------------------------------------------------

def parse_multipart(content_type: str, body: bytes) -> list[tuple[str, bytes]]:
    """Return a list of (header_str, body_bytes) for each MIME part."""
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[len("boundary="):]
            break
    if not boundary:
        return []

    sep = ("--" + boundary).encode()
    parts: list[tuple[str, bytes]] = []
    for raw in body.split(sep)[1:]:          # skip preamble
        if raw.strip() in (b"--", b"--\r\n"):
            break
        if raw.startswith(b"\r\n"):
            raw = raw[2:]
        if b"\r\n\r\n" in raw:
            hdr_raw, content = raw.split(b"\r\n\r\n", 1)
            # strip trailing \r\n added by multipart framing
            if content.endswith(b"\r\n"):
                content = content[:-2]
            parts.append((hdr_raw.decode(errors="replace"), content))
    return parts

def verify_payload_hash(metadata_xml_bytes: bytes,
                        payload_bytes: bytes) -> tuple[str | None, str | None, bool]:
    """
    Returns (expected_hex, computed_hex, match).
    Reads the hex value from <IntegrityMetadata><Hash>.
    """
    try:
        root = ET.fromstring(metadata_xml_bytes)
        jal_ns = root.tag.split("}")[0].strip("{")
        ns = {"jal": jal_ns}
        hash_elem = root.find(".//jal:IntegrityMetadata/jal:Hash", ns)
        if hash_elem is None:
            print("  [hash] <Hash> element not found in metadata")
            return (None, None, False)
        expected_hex = hash_elem.text.strip()
        computed_hex = hashlib.sha256(payload_bytes).hexdigest()
        return (expected_hex, computed_hex, expected_hex == computed_hex)
    except Exception as exc:
        print(f"  [hash] verification error: {exc}")
        return (None, None, False)

DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

def verify_signature(metadata_xml_bytes: bytes,
                     payload_bytes: bytes) -> bool:
    """
    Returns True iff the XMLDSig signature is present and valid.
    Returns True (with a warning) if no signature is present at all —
    unsigned records are permitted; reject only *bad* signatures.
    """
    try:
        root = ET.fromstring(metadata_xml_bytes)
        ds = f"{{{DSIG_NS}}}"

        sig_elem = root.find(f".//{ds}Signature")
        if sig_elem is None:
            print("  [sig] no ds:Signature present — accepting unsigned record")
            return True

        sig_val_elem = sig_elem.find(f"{ds}SignatureValue")
        if sig_val_elem is None or not sig_val_elem.text:
            print("  [sig] ds:SignatureValue missing")
            return False

        signature_bytes = base64.b64decode(sig_val_elem.text.strip())

        # --- cross-check the ds:DigestValue against the payload ---
        ref_elem = sig_elem.find(f".//{ds}Reference")
        if ref_elem is not None:
            digest_val_elem = ref_elem.find(f"{ds}DigestValue")
            if digest_val_elem is not None and digest_val_elem.text:
                claimed_digest = base64.b64decode(digest_val_elem.text.strip())
                actual_digest  = hashlib.sha256(payload_bytes).digest()
                if claimed_digest != actual_digest:
                    print("  [sig] ds:DigestValue does not match payload SHA-256")
                    return False

        # --- verify RSA-SHA256 over the raw payload bytes ---
        if not os.path.exists(PUBLIC_KEY_PATH):
            print(f"  [sig] public key not found at {PUBLIC_KEY_PATH} — skipping verify")
            return True

        with open(PUBLIC_KEY_PATH, "rb") as fh:
            public_key = serialization.load_pem_public_key(fh.read())

        public_key.verify(
            signature_bytes,
            payload_bytes,         
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return True

    except Exception as exc:
        print(f"  [sig] verification failed: {exc}")
        return False

# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

_EXPECTED_JAL_MESSAGE = {
    "/log":     "log-record",
    "/audit":   "audit-record",
    "/journal": "journal-record",
}

class JALoPHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):  # noqa: N802
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {fmt % args}")

    def _reject(self, code: int, reason: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(reason.encode())
        print(f"  -> {code} {reason}")

    def do_POST(self):  # noqa: N802
        path = self.path.rstrip("/")
        if path not in _EXPECTED_JAL_MESSAGE:
            self._reject(404, f"Unknown path: {path}")
            return

        rec_type = path.lstrip("/")   # "log", "audit", or "journal"

        jal_version = self.headers.get("JAL-Version", "").strip()
        if jal_version != "2.0":
            self._reject(400, f"Missing or wrong JAL-Version: '{jal_version}'")
            return
        
        jal_message = self.headers.get("JAL-Message", "").strip()
        expected_msg = _EXPECTED_JAL_MESSAGE[path]
        if jal_message != expected_msg:
            self._reject(400,
                f"JAL-Message '{jal_message}' wrong for path {path} "
                f"(expected '{expected_msg}')")
            return

        jal_id      = self.headers.get("JAL-Id", "unknown")
        meta_len    = self.headers.get("JAL-Application-Metadata-Length", "0")
        payload_len = self.headers.get("JAL-Payload-Length", "0")
        content_type = self.headers.get("Content-Type", "")

        print(f"  JAL-Id:      {jal_id}")
        print(f"  JAL-Message: {jal_message}")
        print(f"  Meta-Length: {meta_len}")
        print(f"  Payload-Len: {payload_len}")
        print(f"  Type:        {rec_type}")

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        parts = parse_multipart(content_type, body)

        out_dir  = os.path.join(RECORD_DIR, rec_type)
        os.makedirs(out_dir, exist_ok=True)
        safe_id  = jal_id.replace("/", "_").replace("\\", "_")

        metadata_bytes = None
        payload_bytes  = None

        if len(parts) >= 1:
            metadata_bytes = parts[0][1]
            meta_path = os.path.join(out_dir, f"{safe_id}_metadata.xml")
            with open(meta_path, "wb") as fh:
                fh.write(metadata_bytes)
            print(f"  Saved metadata: {meta_path}")

        if len(parts) >= 2:
            payload_bytes = parts[1][1]
            payload_path = os.path.join(out_dir, f"{safe_id}_payload.xml")
            with open(payload_path, "wb") as fh:
                fh.write(payload_bytes)
            print(f"  Saved payload:  {payload_path}")

        if metadata_bytes is not None and payload_bytes is not None:
            expected, computed, ok = verify_payload_hash(metadata_bytes, payload_bytes)
            if not ok:
                print(f"  [hash] expected={expected}")
                print(f"  [hash] computed={computed}")
                self._reject(400, "Payload hash mismatch")
                return
            print(f"  [hash] OK  ({computed})")

            if not verify_signature(metadata_bytes, payload_bytes):
                self._reject(401, "Signature verification failed")
                return
            print("  [sig]  OK")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")
        print("  -> 200 OK")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    os.makedirs(RECORD_DIR, exist_ok=True)
    server = http.server.HTTPServer(("0.0.0.0", PORT), JALoPHandler)
    print(f"JALoP 2.0 receiver listening on port {PORT}")
    print(f"Saving records to {os.path.abspath(RECORD_DIR)}/")
    print(f"Endpoints: POST /log  /audit  /journal")
    print("-" * 50)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()