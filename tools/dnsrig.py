#!/usr/bin/env python
# dnsrig — fail-closed DNS test rig for the fork's update-feed verification
# (docs/specs/tooling/design.md r2, FR-03/FR-04; DEC-04).
#
# Attribution (NFR-01, DEC-06): the wire-format approach follows the
# MIT-licensed concept lineage of Crypt0s/FakeDns
# (https://github.com/Crypt0s/FakeDns — dormant since 2020) and
# hupe1980/fakedns (https://github.com/hupe1980/fakedns, PyPI, MIT);
# this implementation is stdlib-only and intentionally minimal.
#
# Why the rig exists (decision matrix, design r2 MAJOR-6): a hosts-file
# edit is SIMPLER for a pure positive redirect (Windows resolver consults
# hosts before DNS). The rig's added value: NXDOMAIN-by-default for every
# OTHER name (fail-closed pollution control hosts cannot express),
# per-query transcript logging, resolver-level control for future phases.
#
# Wiring prerequisites (document, design r2): the guest adapter's DNS must
# point at the rig (or a hosts edit must be applied), AND the feed
# server's root certificate must be installed in the guest trust store.
#
# Deliberate limits: UDP/53 only — TCP is never bound (A answers never
# truncate; if a client retries over TCP it fails closed). OPT (EDNS0)
# records are tolerated and ignored. NXDOMAIN default — the rig is NEVER
# a recursive resolver (upstream leaks pollute the test).
#
# Usage:
#   python tools/dnsrig.py --config dnsrig.ini
#   python tools/dnsrig.py --self-test        # loopback assert, CI-safe
import argparse
import configparser
import socket
import struct
import sys


def parse_qname(data, off):
    labels = []
    while off < len(data):
        ln = data[off]
        if ln == 0:
            return ".".join(labels), off + 1
        if ln & 0xC0:  # compression pointer: reject queries with them (clients don't send these)
            raise ValueError("compression pointer in query")
        labels.append(data[off + 1:off + 1 + ln].decode("ascii", errors="replace"))
        off += 1 + ln
    raise ValueError("truncated qname")


def build_response(qid, qname, qtype, ip):
    # header: QR=1, AA=1, RCODE=0; one question, one answer
    header = struct.pack(">HHHHHH", qid, 0x8400, 1, 1, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
    q += struct.pack(">HH", qtype, 1)
    answer_name = b"\xc0\x0c"  # pointer to the question name
    answer = answer_name + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return header + q + answer


def build_nxdomain(qid):
    # header: QR=1, AA=1, RCODE=3 (NXDOMAIN); questions echoed, no answers
    return struct.pack(">HHHHHH", qid, 0x8403, 0, 0, 0, 0)


class Rig:
    def __init__(self, mappings, default_policy="nxdomain"):
        self.mappings = mappings
        self.default_policy = default_policy

    def handle(self, data):
        if len(data) < 12:
            return None, "malformed-query"
        qid, flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", data, 0)
        if flags & 0x8000:  # QR bit set = response, never served by a rig
            return None, "not-a-query"
        try:
            qname, off = parse_qname(data, 12)
            qtype, qclass = struct.unpack_from(">HH", data, off)
        except ValueError as exc:
            return None, str(exc)
        note = f"{qname} type={qclass}:{qtype}"
        if qtype in (41,):  # OPT / EDNS0 additional — not a question
            return None, note + " (OPT ignored)"
        if qtype != 1 or qclass != 1:  # only IN A is served
            return build_nxdomain(qid), note + " -> NXDOMAIN (type not served)"
        ip = self.mappings.get(qname.lower())
        if ip:
            return build_response(qid, qname, qtype, ip), note + f" -> {ip}"
        return build_nxdomain(qid), note + " -> NXDOMAIN (default policy)"


def serve(rig, bind, port, once=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind, port))
    print(f"dnsrig listening on udp/{bind}:{port} — mappings: {rig.mappings} default: {rig.default_policy}")
    while True:
        data, addr = s.recvfrom(4096)
        reply, note = rig.handle(data)
        print(f"query from {addr[0]}: {note}")
        if reply:
            s.sendto(reply, addr)
        if once:
            break


def self_test():
    # FR-04: loopback self-query assert — CI-safe, no sandbox, no admin
    rig = Rig({"rig.test": "127.0.0.1"})
    import threading
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv_port = srv.getsockname()[1]

    stop = threading.Event()

    def pump():
        srv.settimeout(0.25)
        while not stop.is_set():
            try:
                data, addr = srv.recvfrom(4096)
            except socket.timeout:
                continue
            reply, _ = rig.handle(data)
            if reply:
                srv.sendto(reply, addr)

    t = threading.Thread(target=pump, daemon=True)
    t.start()

    def raw_query(payload):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(payload, ("127.0.0.1", srv_port))
        resp, _ = s.recvfrom(4096)
        s.close()
        return resp

    def query(name):
        qid = 0x1234
        q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
        q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q
        resp = raw_query(q)
        return struct.unpack_from(">H", resp, 0)[0] == qid, struct.unpack_from(">H", resp, 2)[0] & 0x000F, resp

    try:
        ok1, rcode1, _ = query("rig.test")
        mapped_ok = ok1 and rcode1 == 0
        print(("PASS" if mapped_ok else "FAIL") + f": mapped name answered (rcode={rcode1})")

        ok2, rcode2, _ = query("unknown.test")
        nxdomain_ok = ok2 and rcode2 == 3
        print(("PASS" if nxdomain_ok else "FAIL") + f": unknown name NXDOMAIN (rcode={rcode2})")

        # OPT-tolerance: same mapped query but with an EDNS0 OPT record appended
        qid = 0x4321
        q = b"\x03rig\x04test\x00" + struct.pack(">HH", 1, 1)
        q += b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)  # OPT
        q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1) + q
        resp = raw_query(q)
        opt_ok = struct.unpack_from(">H", resp, 0)[0] == qid and struct.unpack_from(">H", resp, 2)[0] & 0x000F == 0
        print(("PASS" if opt_ok else "FAIL") + ": EDNS0/OPT tolerated")
    finally:
        stop.set()
        t.join(timeout=1)
        srv.close()

    ok = mapped_ok and nxdomain_ok and opt_ok
    print("dnsrig self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="fail-closed DNS test rig")
    ap.add_argument("--config", help="ini: [rig] bind/port, [mappings] name=ip")
    ap.add_argument("--self-test", action="store_true", help="loopback assert (CI-safe)")
    args = ap.parse_args()

    if args.self_test:
        sys.exit(self_test())

    if not args.config:
        ap.error("--config or --self-test required")
    cp = configparser.ConfigParser()
    read = cp.read(args.config, encoding="utf-8")
    if not read:
        print(f"FAIL: config not found: {args.config}")
        sys.exit(1)
    bind = cp.get("rig", "bind", fallback="127.0.0.1")
    port = cp.getint("rig", "port", fallback=53)
    mappings = {k.lower(): v for k, v in cp.items("mappings")} if cp.has_section("mappings") else {}
    serve(Rig(mappings), bind, port)


if __name__ == "__main__":
    main()
