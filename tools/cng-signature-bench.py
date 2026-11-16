#!/usr/bin/env python
# RSK-04 CNG-path gate (round 2, r4 review): proves the EXACT byte-order
# conventions _r_update_verifysignature relies on, against the real CNG:
#   1. BCRYPT_ECCPUBLIC_BLOB accepts the verbatim big-endian X||Y from
#      src/update_key.h (magic ECS1 + cbKey=32) -> import STATUS_SUCCESS
#   2. BCryptVerifySignature accepts the P1363 big-endian r||s that
#      tools/update-signer.ps1 emits, AS-IS (no half-reversal)
#   3. little-endian halves are REFUSED (import 0xC000000D / verify 0xC000A000)
#   4. a tampered signature is rejected
# Usage: python tools/cng-signature-bench.py [key.json] [feed] [feed.sig]
# Exit 0 = all gates pass. Any other exit = conventions broken; do NOT ship.
import base64
import ctypes
import hashlib
import json
import sys

KEY_PATH = r"D:\CV\Github\.keys\simplewall-signing.json"
FEED_PATH = "VERSION"
SIG_PATH = "VERSION.sig"

BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345  # ECS1

bcrypt = ctypes.WinDLL("bcrypt.dll")
bcrypt.BCryptOpenAlgorithmProvider.restype = ctypes.c_ulong
bcrypt.BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
bcrypt.BCryptImportKeyPair.restype = ctypes.c_ulong
bcrypt.BCryptImportKeyPair.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong]
bcrypt.BCryptVerifySignature.restype = ctypes.c_ulong
bcrypt.BCryptVerifySignature.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong]


def main():
    key_path = sys.argv[1] if len(sys.argv) > 1 else KEY_PATH
    feed_path = sys.argv[2] if len(sys.argv) > 2 else FEED_PATH
    sig_path = sys.argv[3] if len(sys.argv) > 3 else SIG_PATH

    j = json.load(open(key_path))
    x_be = base64.b64decode(j["x"])
    y_be = base64.b64decode(j["y"])

    # gate 0: the in-tree key must match the off-repo ground truth
    keyh = open("src/update_key.h").read()
    import re
    m = re.search(r"UPDATE_PUBLIC_KEY\[64\]\s*=\s*\{([^}]+)\}", keyh)
    tree_key = bytes.fromhex(re.sub(r"0x|[\s,]", "", m.group(1)))
    if tree_key != x_be + y_be:
        print("FAIL: src/update_key.h does not match the key JSON ground truth")
        return 1

    blob_be = BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_bytes(4, "little") + (32).to_bytes(4, "little") + x_be + y_be
    blob_le = BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_bytes(4, "little") + (32).to_bytes(4, "little") + x_be[::-1] + y_be[::-1]

    halg = ctypes.c_void_p()
    if bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(halg), "ECDSA_P256", None, 0) != 0:
        print("FAIL: BCryptOpenAlgorithmProvider")
        return 1
    hkey = ctypes.c_void_p()
    if bcrypt.BCryptImportKeyPair(halg, None, "ECCPUBLICBLOB", ctypes.byref(hkey), blob_be, len(blob_be), 0) != 0:
        print("FAIL: verbatim big-endian key blob rejected by CNG")
        return 1

    feed = open(feed_path, "rb").read()
    sig = open(sig_path, "rb").read()
    if len(sig) != 64:
        print("FAIL: signature is %d bytes, expected 64 (raw r||s)" % len(sig))
        return 1
    digest = hashlib.sha256(feed).digest()
    d = ctypes.create_string_buffer(digest, 32)

    sig_be = ctypes.create_string_buffer(sig, 64)
    sig_le = ctypes.create_string_buffer(sig[:32][::-1] + sig[32:][::-1], 64)
    sig_bad = ctypes.create_string_buffer(bytes([sig[0] ^ 1]) + sig[1:], 64)

    checks = [
        ("verbatim BE key blob imports", True),
        ("BE-halves (P1363) signature verifies", bcrypt.BCryptVerifySignature(hkey, None, d, 32, sig_be, 64, 0) == 0),
        ("LE-halves signature REFUSED", bcrypt.BCryptVerifySignature(hkey, None, d, 32, sig_le, 64, 0) != 0),
        ("tampered signature REFUSED", bcrypt.BCryptVerifySignature(hkey, None, d, 32, sig_bad, 64, 0) != 0),
    ]
    failed = False
    for label, ok in checks:
        print(("PASS" if ok else "FAIL") + ": " + label)
        failed = failed or not ok

    bcrypt.BCryptDestroyKey(hkey)
    bcrypt.BCryptCloseAlgorithmProvider(halg, 0)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
