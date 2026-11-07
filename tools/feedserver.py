#!/usr/bin/env python
# feedserver — stdlib TLS static server for the fork's update-feed root
# (docs/specs/tooling/design.md r2, FR-06; DEC-01 stdlib; DEC-05 manual
#  sandbox tool).
#
# Attribution (NFR-01, DEC-06): concept lineage — serving a controlled
# feed root for offline updater tests — follows the signed-feed harness
# conventions established in docs/specs/routine-hardening (the ECDSA
# P-256 feed + detached .sig). No third-party code; http.server + ssl
# only. Cert generation is NOT reimplemented: the caller supplies a
# cert/key pair (e.g. PowerShell New-SelfSignedCertificate exported as
# PEM, root installed into the guest trust store — see design r2 wiring
# prerequisites).
#
# Usage:
#   python tools/feedserver.py --root <feed-dir> --cert <pem> --key <pem> [--port 443] [--bind 127.0.0.1]
#
# Serves: VERSION, VERSION.sig, and any artifact URLs the manifest names
# (place artifacts in the root, subpaths honored). No directory listing.
# Request log to stderr for the test transcript.
import argparse
import functools
import http.server
import os
import ssl
import sys


class FeedHandler(http.server.SimpleHTTPRequestHandler):
    def list_directory(self, path):
        # DEC-04/SEC-02 posture: the rig environment must not expose an index
        self.send_error(404, "Directory listing forbidden")
        return None


def main():
    ap = argparse.ArgumentParser(description="TLS feed server for offline updater tests")
    ap.add_argument("--root", required=True, help="feed root directory (must contain VERSION + VERSION.sig)")
    ap.add_argument("--cert", required=True, help="TLS cert PEM (leaf, guest-trusted chain)")
    ap.add_argument("--key", required=True, help="TLS key PEM")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--bind", default="127.0.0.1")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"FAIL: feed root missing: {root}")
        return 1
    for required in ("VERSION", "VERSION.sig"):
        if not os.path.isfile(os.path.join(root, required)):
            print(f"FAIL: feed root lacks {required} — the harness is meaningless without the feed pair (fail-closed)")
            return 1
    for f in (args.cert, args.key):
        if not os.path.isfile(f):
            print(f"FAIL: TLS file missing: {f}")
            return 1

    handler = functools.partial(FeedHandler, directory=root)
    httpd = http.server.ThreadingHTTPServer((args.bind, args.port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"feedserver: https://{args.bind}:{args.port} root={root} (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
