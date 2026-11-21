# Byte-exact simulation of the composite packstate round-trip (writer vs
# verifier) to find the remaining packs failure. Python -I, stdlib only.
import struct

FNV_INIT = 2166136261
FNV_PRIME = 16777619

def fnv1a32(data):
    h = FNV_INIT
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    return h

def wchars(s):
    # UTF-16LE bytes of a python string
    return s.encode('utf-16-le')

MAGIC = "COMPOSITE_PACKSTATE_V1"

# --- WRITER (fixed semantics: appendstringbuilder_ex takes BYTES) ---
buf = bytearray()
buf += wchars(MAGIC)            # (RTL_NUMBER_OF-1)*2 bytes
buf += wchars("\r\n")           # 2*2 bytes
guid_strs = []
for i in range(3):
    g = "{%08X-2A2B-3C3D-4E4F-505152535455}" % (i + 1)
    guid_strs.append(g)
# pack line: format L"pack=%s|%s|%08x\r\n" -> the rules_hash value unknown
# (selftest passes 3 filters; rules_hash = whatever) - use a placeholder
pack_line = "pack=telemetry-refresh|1.2.3|%08x\r\n" % 0xAABBCCDD
buf += wchars(pack_line)
for g in guid_strs:
    buf += wchars("filter=telemetry-refresh|%s\r\n" % g)

prefix = bytes(buf)             # everything before the trailer line
stored = fnv1a32(prefix)
buf += wchars("state_hash=%08x\r\n" % stored)
store = bytes(buf)

print("store size (bytes):", len(store), "| odd:", len(store) % 2)

# --- READER + VERIFIER (stateverify algorithm) ---
text = store.decode('utf-16-le')
assert text.startswith(MAGIC)

# scan lines for the LAST state_hash= line-start
trailer_off_chars = None
pos = 0
n = len(text)
while pos < n and text[pos] != '\x00':
    nl = text.find('\n', pos)
    if nl == -1:
        line_len_chars = n - pos
        next_pos = -1
    else:
        line_len_chars = nl - pos
        next_pos = nl + 1
    # strip \r
    ll = line_len_chars
    if ll and text[pos + ll - 1] == '\r':
        ll -= 1
    line = text[pos : pos + ll]
    if line.startswith("state_hash="):
        trailer_off_chars = pos
    if next_pos == -1:
        break
    pos = next_pos

assert trailer_off_chars is not None, "trailer not found"
prefix_bytes_len = trailer_off_chars * 2
hash_actual = fnv1a32(store[:prefix_bytes_len])
stored_val = int(text[trailer_off_chars:].split('\r\n')[0][len("state_hash="):], 16)
print("stored : %08x" % stored_val)
print("actual : %08x" % hash_actual)
print("MATCH" if stored_val == hash_actual else "MISMATCH")

# --- PARSE sanity: pack line + 3 filter lines ---
lines = [l for l in text.split("\r\n") if l]
print("lines:", lines)
