# x64 minidump analyzer: exception record, faulting thread context, stack
# walk with module+offset mapping. Pure python, no deps.
import struct, io, sys, json

DUMP = r"D:\CV\Github\verifier-artifacts-44807821539\x\dumps\simplewall.exe.5472.dmp"

data = open(DUMP, "rb").read()
magic, version, nstreams, dir_rva, cks, tds, flags = struct.unpack_from("<IIIIIIQ", data, 0)
assert magic == 0x504D444D, hex(magic)
print("streams:", nstreams)

def peek_module_name(rva):
    # try the documented MINIDUMP_R_STRING: Length; RVA buffer
    try:
        nlen, nbuf = struct.unpack_from("<II", data, rva)
        s = data[nbuf : nbuf + nlen].decode("utf-16-le", "replace").rstrip("\x00")
        if s and any(ord(c) > 32 for c in s):
            return s
    except Exception:
        pass
    # fallback: the string may sit directly at rva+8 with length at rva
    return None

streams = {}
for i in range(nstreams):
    t, sz, rva = struct.unpack_from("<III", data, dir_rva + i * 12)
    streams.setdefault(t, []).append((sz, rva))

# modules
modules = []
if 4 in streams:
    sz, rva = streams[4][0]
    n = struct.unpack_from("<I", data, rva)[0]
    print("module count:", n)
    off = rva + 4
    for i in range(n):
        base, isize, ck, tds2, name_rva = struct.unpack_from("<QIIII", data, off)
        name = peek_module_name(name_rva) or ("mod_%d@0x%X size=0x%X" % (i, base, isize))
        modules.append((base, isize, name))
        off += 108

print("== MODULES ==")
for base, isize, name in modules:
    print("  0x%016X +0x%-7X %s" % (base, isize, name[:70]))

def mod_of(addr):
    for base, isize, name in modules:
        if base <= addr < base + isize:
            return (name, addr - base)
    return None

# exception
if 6 in streams:
    sz, rva = streams[6][0]
    tid, align, code, eflags, rec, eaddr, nparams, unused = struct.unpack_from("<IIIIQQII", data, rva)
    info = struct.unpack_from("<15Q", data, rva + 40)
    ctx_sz, ctx_rva = struct.unpack_from("<II", data, rva + 160)
    print("== EXCEPTION ==")
    print("thread id:", tid)
    print("code: 0x%08X  address: 0x%016X (%s)" % (code, eaddr, mod_of(eaddr)))
    print("params:", nparams, [hex(x) for x in info[:min(nparams, 6)]])
    ctx = data[ctx_rva : ctx_rva + ctx_sz]
    rip = struct.unpack_from("<Q", ctx, 0xF8)[0]
    rsp = struct.unpack_from("<Q", ctx, 0x98)[0]
    rbp = struct.unpack_from("<Q", ctx, 0xA0)[0]
    print("faulting thread: RIP=0x%X (%s) RSP=0x%X RBP=0x%X" % (rip, mod_of(rip), rsp, rbp))
    exc_tid = tid

# thread contexts: dump Rip for every thread (all stacks overview)
threads = {}
if 3 in streams:
    sz, rva = streams[3][0]
    n = struct.unpack_from("<I", data, rva)[0]
    off = rva + 4
    for i in range(n):
        tid, sc, pc, pr, teb, stack_start, ssz, srva, csz, crva = struct.unpack_from("<IIIIQQIIII", data, off)
        threads[tid] = (stack_start, ssz, srva, csz, crva)
        off += 48

print("== ALL THREAD RIPs ==")
rows = []
for tid, (ss, sz2, srva, csz, crva) in sorted(threads.items()):
    ctx = data[crva : crva + csz]
    rip = struct.unpack_from("<Q", ctx, 0xF8)[0]
    m = mod_of(rip)
    rows.append((tid, rip, m))
    tag = ""
    if 6 in streams and tid == exc_tid:
        tag = "  <== FAULTING"
    print("tid %5d RIP=0x%016X %s%s" % (tid, rip, ("%s+0x%X" % m) if m else "?", tag))

# stack walk of the faulting thread: scan stack for return addresses
if 6 in streams and exc_tid in threads:
    ss, sz2, srva, csz, crva = threads[exc_tid]
    ctx = data[crva : crva + csz]
    rsp = struct.unpack_from("<Q", ctx, 0x98)[0]
    stack = data[srva : srva + sz2]
    print("== FAULTING THREAD STACK SCAN (module hits, rsp base 0x%X) ==" % rsp)
    base = ss
    start = max(0, rsp - base) if rsp >= base else 0
    hits = []
    for i in range(start, sz2 - 8, 8):
        v = struct.unpack_from("<Q", stack, i)[0]
        m = mod_of(v)
        if m:
            hits.append((rsp + (i - start), v, m))
    for a, v, m in hits[:60]:
        print("  [rsp+0x%05X] 0x%016X  %s+0x%X" % (a - rsp, v, m[0], m[1]))
