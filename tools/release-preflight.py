#!/usr/bin/env python
# release-preflight — gated release verification for the simplewall fork
# (docs/specs/tooling/design.md r2, FR-01/FR-02; DEC-01 stdlib-only;
#  DEC-07 no private material needed by any profile of this tool).
#
# Attribution / lineage (NFR-01, DEC-06): the PE walk, SWC1 container
# decode and CNG conventions were hand-proven in the 2026-11-07 hardening
# sessions (see docs/specs/routine-hardening/design.md r4 follow-up and
# tools/cng-signature-bench.py — the bench remains the separate owner-side
# RSK-04 gate; this tool does NOT call it). The Authenticode authority is
# Windows itself via PowerShell Get-AuthenticodeSignature (disclosed
# OS-provided binary per SEC-01; ConvertTo-Json for stable parsing).
# Concept sources for the DNS/feed sibling tools: Crypt0s/FakeDns and
# hupe1980/fakedns (both MIT, cited in their own headers).
#
# Usage:
#   python tools/release-preflight.py bin/64/simplewall.exe            # full
#   python tools/release-preflight.py bin/64/simplewall.exe --ci       # CI profile
#   python tools/release-preflight.py <exe> --json                      # machine output
#
# Exit 0 only when every SELECTED check passes. Missing/unparseable
# inputs fail closed (FR-02/SEC-02) — never a silent skip.
import argparse
import base64
import ctypes
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

DEFAULT_THUMBPRINT = "DC91477AF1415F6D7C3B181B1EB2EC45FF907ED0"

# Known-bad artifacts that must never reappear in any shipped binary
# (docs/specs/routine-hardening/design.md r2: the transcription-corrupted
# public key from commit db1ef855).
CORRUPTED_KEY_Y = bytes.fromhex("faf3cfcb0e44874271c3e42dcffb2f42924ca61a8315d84ef2ec0723e02c6f05")

RESULTS = []


def record(name, ok, evidence, skip=False):
    status = "SKIP" if skip else ("PASS" if ok else "FAIL")
    RESULTS.append({"name": name, "status": status, "evidence": evidence})
    print(f"{status}: {name} — {evidence}")
    return ok or skip


def read_pe(path):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    if d[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("not a PE image")
    coff = pe + 4
    nsec, = struct.unpack_from("<H", d, coff + 2)
    optsz, = struct.unpack_from("<H", d, coff + 16)
    opt = coff + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    if magic != 0x20B:
        raise ValueError("not PE32+ (x64)")
    dd = opt + 112
    imp_rva = struct.unpack_from("<I", d, dd + 8)[0]
    rsrc_rva = struct.unpack_from("<I", d, dd + 16)[0]
    dllchar = struct.unpack_from("<H", d, opt + 70)[0]
    sec = opt + optsz

    def rva2off(rva):
        for i in range(nsec):
            o = sec + i * 40
            vsz, va, rsz, ro = struct.unpack_from("<IIII", d, o + 8)
            if va <= rva < va + max(vsz, rsz):
                return ro + (rva - va)
        return None

    return d, rva2off, imp_rva, rsrc_rva, dllchar


def import_dlls(d, rva2off, imp_rva):
    dlls = []
    off = rva2off(imp_rva)
    if off is None:
        raise ValueError("import directory RVA unresolvable")
    while True:
        _, _, _, name_rva, _ = struct.unpack_from("<IIIII", d, off)
        if name_rva == 0:
            break
        no = rva2off(name_rva)
        dlls.append(d[no:d.index(b"\x00", no)].decode())
        off += 20
    return dlls


def rcdata_entries(d, rva2off, rsrc_rva):
    out = {}
    if not rsrc_rva:
        return out

    def walk(off, level, path):
        named, ids = struct.unpack_from("<HH", d, off + 12)
        for i in range(named + ids):
            e = off + 16 + i * 8
            nid, offfield = struct.unpack_from("<II", d, e)
            if level < 2 and (offfield & 0x80000000):
                walk(rva2off(rsrc_rva + (offfield & 0x7FFFFFFF)), level + 1, path + [nid])
            else:
                de = rva2off(rsrc_rva + offfield)
                data_rva, data_sz = struct.unpack_from("<II", d, de)
                out[tuple(path + [nid])] = (data_rva, data_sz)

    walk(rva2off(rsrc_rva), 0, [])
    return out


def lznt1_decompress(body):
    ntdll = ctypes.WinDLL("ntdll.dll")
    ntdll.RtlGetCompressionWorkSpaceSize.restype = ctypes.c_ulong
    ntdll.RtlGetCompressionWorkSpaceSize.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    ntdll.RtlDecompressBuffer.restype = ctypes.c_ulong
    ntdll.RtlDecompressBuffer.argtypes = [ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    for fmt in (2, 3):  # COMPRESSION_FORMAT_LZNT1, then XPRESS — mirrors src/db.c
        ws = ctypes.c_ulong(0)
        frag = ctypes.c_ulong(0)
        if ntdll.RtlGetCompressionWorkSpaceSize(ctypes.c_ushort(fmt), ctypes.byref(ws), ctypes.byref(frag)) != 0:
            continue
        buf = ctypes.create_string_buffer(ws.value + 16)
        out = ctypes.create_string_buffer(len(body) * 16 + 65536)
        final = ctypes.c_ulong(0)
        if ntdll.RtlDecompressBuffer(ctypes.c_ushort(fmt), out, len(out), ctypes.c_char_p(body), len(body), ctypes.byref(final), buf) == 0:
            return out.raw[:final.value], fmt
    raise ValueError("SWC1 body decompressed by neither LZNT1 nor XPRESS")


def load_ground_truth(gt_dir):
    if not os.path.isdir(gt_dir):
        raise ValueError(f"ground-truth directory missing: {gt_dir}")
    gt = {}
    for name in ("imports.json", "blocklist.json", "pe-flags.json"):
        p = os.path.join(gt_dir, name)
        if not os.path.isfile(p):
            raise ValueError(f"ground-truth file missing: {p}")
        obj = json.load(open(p, encoding="utf-8"))
        if "provenance" not in obj:
            raise ValueError(f"ground-truth file lacks provenance header: {p}")
        gt[name] = obj
    keysha_p = os.path.join(gt_dir, "key-json-sha256.txt")
    if not os.path.isfile(keysha_p):
        raise ValueError(f"ground-truth file missing: {keysha_p}")
    gt["key_sha"] = open(keysha_p, encoding="utf-8").read().strip()
    return gt


def parse_update_key_h(path):
    text = open(path, encoding="utf-8").read()
    m = re.search(r"UPDATE_PUBLIC_KEY\[64\]\s*=\s*\{([^}]+)\}", text)
    if not m:
        raise ValueError("UPDATE_PUBLIC_KEY not found in update_key.h")
    return bytes.fromhex(re.sub(r"0x|[\s,]", "", m.group(1)))


def parse_app_version(path):
    text = open(path, encoding="utf-8").read()
    m = re.search(r'#define\s+APP_VERSION\s+L"([^"]+)"', text)
    if not m:
        raise ValueError("APP_VERSION not found in app.h")
    return m.group(1)


def version_resource_string(d, rva2off, rsrc_rva):
    for path, (rva, sz) in rcdata_entries(d, rva2off, rsrc_rva).items():
        if path and path[0] == 16:  # RT_VERSION
            off = rva2off(rva)
            blob = d[off:off + sz]
            text = blob.decode("utf-16-le", errors="ignore")
            m = re.search(r"ProductVersion\x00(?!\x00)((?:(?!\x00).){1,40})\x00", text)
            if m:
                return m.group(1)
    raise ValueError("no RT_VERSION resource with ProductVersion")


def check_authenticode(exe, thumbprint):
    # full profile only; authority = Windows (disclosed OS binary, SEC-01)
    # -EncodedCommand: bulletproof quoting (plain -Command breaks when the
    # argument is re-parsed by PowerShell as a script path)
    ps = (
        "Get-AuthenticodeSignature -FilePath '%s' | "
        "Select-Object Status, StatusMessage, "
        "@{n='Thumbprint';e={$_.SignerCertificate.Thumbprint}}, "
        "@{n='NotAfter';e={$_.SignerCertificate.NotAfter}} | ConvertTo-Json"
        % exe.replace("'", "''")
    )
    encoded = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    try:
        raw = subprocess.run(
            ["powershell", "-NoProfile", "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=60,
        ).stdout
        obj = json.loads(raw)
    except Exception as exc:
        return False, f"Authenticode query failed: {exc}"
    status = obj.get("Status")
    tp = obj.get("Thumbprint") or ""
    # ConvertTo-Json serializes the SignatureStatus enum as a NUMBER
    # (Valid=0) in some PowerShell versions, as the NAME in others
    if status not in ("Valid", 0, "0"):
        return False, f"signature Status={status} ({obj.get('StatusMessage')})"
    if tp.upper() != thumbprint.upper():
        return False, f"thumbprint {tp} != expected {thumbprint}"
    extra = ""
    na = obj.get("NotAfter")
    if na:
        extra = f" | NotAfter {na}"
        if "T-" not in str(na):
            try:
                import datetime
                dt = datetime.datetime.fromisoformat(str(na).replace("Z", "+00:00"))
                days = (dt - datetime.datetime.now(datetime.timezone.utc)).days
                if days < 30:
                    print(f"WARN: Authenticode cert expires in {days} days (owner renewal decision)")
            except Exception:
                pass
    return True, f"Valid, thumbprint match{extra}"


def main():
    ap = argparse.ArgumentParser(description="fork release preflight gate")
    ap.add_argument("exe")
    ap.add_argument("--ci", action="store_true", help="CI profile: skip release-authoritative checks (a, b2)")
    ap.add_argument("--json", action="store_true", help="machine-readable output on stdout")
    ap.add_argument("--thumbprint", default=DEFAULT_THUMBPRINT)
    ap.add_argument("--app-h", default=None, help="path to src/app.h (default: <tools>/../src/app.h)")
    ap.add_argument("--ground-truth-dir", default=None, help="default: <tools>/preflight-ground-truth")
    args = ap.parse_args()

    tool_dir = os.path.dirname(os.path.abspath(__file__))
    gt_dir = args.ground_truth_dir or os.path.join(tool_dir, "preflight-ground-truth")
    app_h = args.app_h or os.path.join(tool_dir, "..", "src", "app.h")

    exe = os.path.abspath(args.exe)
    if not os.path.isfile(exe):
        print(f"FAIL: exe not found: {exe}")
        return 1

    # FR-02: ground truth must load before anything else — fail closed
    try:
        gt = load_ground_truth(gt_dir)
        record("ground-truth-load", True, gt_dir)
    except (ValueError, json.JSONDecodeError) as exc:
        record("ground-truth-load", False, str(exc))
        return 1

    try:
        tree_key = parse_update_key_h(os.path.join(tool_dir, "..", "src", "update_key.h"))
        app_version = parse_app_version(app_h)
        d, rva2off, imp_rva, rsrc_rva, dllchar = read_pe(exe)
    except (ValueError, OSError) as exc:
        record("pe/app-h parse", False, str(exc))
        return 1

    ok_all = True

    # (a) Authenticode — full profile only (runner builds are unsigned;
    # DEC-05/DEC-07: the release engineer is the authority for (a)/(b2))
    if args.ci:
        ok_all &= record("(a) authenticode", False, "release profile — runner builds are unsigned", skip=True)
    else:
        ok, ev = check_authenticode(exe, args.thumbprint)
        ok_all &= record("(a) authenticode", ok, ev)

    # (b1) embedded feed key vs in-tree update_key.h (CI-safe)
    idx = d.find(tree_key)
    ok = idx >= 0
    ev = f"embedded key found at 0x{idx:x}" if ok else "embedded key NOT present"
    if ok and d.find(CORRUPTED_KEY_Y) >= 0:
        ok = False
        ev = "CORRUPTED historical key bytes present (db1ef855 regression)"
    ok_all &= record("(b1) embedded key == in-tree update_key.h", ok, ev)

    # (b2) in-tree key vs off-repo JSON ground truth (owner-side only)
    if args.ci:
        ok_all &= record("(b2) key vs off-repo JSON", False, "release profile — JSON never leaves owner machine", skip=True)
    else:
        json_path = r"D:\CV\Github\.keys\simplewall-signing.json"
        if not os.path.isfile(json_path):
            ok_all &= record("(b2) key vs off-repo JSON", False, f"JSON missing: {json_path}")
        else:
            blob = open(json_path, "rb").read()
            sha = hashlib.sha256(blob).hexdigest()
            if sha != gt["key_sha"]:
                ok_all &= record("(b2) key vs off-repo JSON", False,
                                 f"JSON SHA256 {sha} != pinned {gt['key_sha']} — change-controlled trust anchor violated (RSK-04)")
            else:
                import base64
                obj = json.loads(blob)
                json_key = base64.b64decode(obj["x"]) + base64.b64decode(obj["y"])
                ok_all &= record("(b2) key vs off-repo JSON", json_key == tree_key,
                                 "pinned SHA256 OK + bytes match" if json_key == tree_key else "JSON key bytes != in-tree key")

    # (c) import parity
    try:
        dlls = sorted(import_dlls(d, rva2off, imp_rva))
        expected = sorted(gt["imports.json"]["dlls"])
        extra = sorted(set(dlls) - set(expected))
        missing = sorted(set(expected) - set(dlls))
        ok = not extra and not missing
        ev = f"{len(dlls)} DLLs"
        if extra:
            ev += f" | EXTRA: {extra} (upstream merge? update imports.json with the cited diff — RSK-01)"
        if missing:
            ev += f" | MISSING: {missing} (upstream merge? — RSK-01)"
        ok_all &= record("(c) import parity", ok, ev)
    except ValueError as exc:
        ok_all &= record("(c) import parity", False, str(exc))

    # (d) version resource vs src/app.h
    try:
        pv = version_resource_string(d, rva2off, rsrc_rva)
        ok_all &= record("(d) version resource", pv == app_version,
                         f"ProductVersion {pv} vs APP_VERSION {app_version}")
    except ValueError as exc:
        ok_all &= record("(d) version resource", False, str(exc))

    # (e) SWC1 container: fourcc + flag + stored-SHA256(plaintext) + decode
    #     (LZNT1 then XPRESS, mirroring src/db.c) + blocklist parity
    try:
        entries = rcdata_entries(d, rva2off, rsrc_rva)
        rc = next((v for path, v in entries.items() if path and path[0] == 10 and path[1] == 1), None)
        if rc is None:
            raise ValueError("RCDATA id=1 (IDR_PROFILE_INTERNAL) not found")
        rva, sz = rc
        off = rva2off(rva)
        blob = d[off:off + sz]
        if blob[:3] != b"SWC":
            raise ValueError("SWC fourcc not present")
        flag = blob[3]
        stored = blob[4:36]
        body = blob[36:]
        plain, fmt = lznt1_decompress(body)
        sha_ok = hashlib.sha256(plain).digest() == stored
        import xml.etree.ElementTree as ET
        root = ET.fromstring(plain.decode("utf-8", errors="strict"))
        bl = root.find(".//rules_blocklist")
        count = len(bl.findall("item")) if bl is not None else -1
        expected_count = gt["blocklist.json"]["count"]
        ok = sha_ok and count == expected_count and flag == 0x31
        ev = f"flag=0x{flag:02x} fmt={'LZNT1' if fmt == 2 else 'XPRESS'} plaintext {len(plain)}B sha256 {'OK' if sha_ok else 'MISMATCH'} blocklist {count}/{expected_count} (RSK-01 if drift)"
        ok_all &= record("(e) SWC1 container + blocklist parity", ok, ev)
    except (ValueError, ET.ParseError) as exc:
        ok_all &= record("(e) SWC1 container + blocklist parity", False, str(exc))

    # (f) PE security flags parity
    flags_spec = gt["pe-flags.json"]
    ok = dllchar == flags_spec["value"]
    ev = f"DllCharacteristics 0x{dllchar:04x} vs parity 0x{flags_spec['value']:04x} ({', '.join(flags_spec['flags'])})"
    ok_all &= record("(f) PE security flags parity", ok, ev)

    if args.json:
        print(json.dumps({"exe": exe, "ci_profile": args.ci, "ok": bool(ok_all), "checks": RESULTS}, indent=2))

    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
