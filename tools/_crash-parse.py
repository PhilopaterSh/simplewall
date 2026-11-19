# fresh crash dump parser (correct MINIDUMP_EXCEPTION_STREAM layout)
import struct
import sys

path = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\Philo\Desktop\simplewall_crash\simplewall-1794962163.dmp'
d = open(path, 'rb').read()
_, _, nstreams, dir_rva = struct.unpack_from('<IIII', d, 0)
streams = {}
for i in range(nstreams):
    t, sz, rva = struct.unpack_from('<III', d, dir_rva + i * 12)
    streams.setdefault(t, []).append((sz, rva))

# exception stream (type 6): tid@0 pad@4 code@8 flags@12 record@16 address@24 nparams@32 pad@36 params[8]@40, context{size@160 rva@164}
sz, rva = streams[6][0]
tid = struct.unpack_from('<I', d, rva + 0)[0]
code = struct.unpack_from('<I', d, rva + 8)[0]
address = struct.unpack_from('<Q', d, rva + 24)[0]
nparams = struct.unpack_from('<I', d, rva + 32)[0]
ctx_size, ctx_rva = struct.unpack_from('<II', d, rva + 160)
print(f'EXCEPTION tid={tid} code=0x{code:08X} address=0x{address:X} nparams={nparams} context@0x{ctx_rva:X} ({ctx_size}B)')
params = struct.unpack_from('<8Q', d, rva + 40)
for i in range(min(nparams, 4)):
    print(f'  param[{i}] = 0x{params[i]:X}')

# module list (type 4)
sz, rva = streams[4][0]
nmod = struct.unpack_from('<I', d, rva)[0]
mods = []
off = rva + 4
for i in range(nmod):
    base, size, checksum, timestamp, name_rva = struct.unpack_from('<QIIII', d, off)
    wlen = struct.unpack_from('<I', d, name_rva)[0]
    name = d[name_rva + 4:name_rva + 4 + wlen * 2].decode('utf-16-le', errors='replace')
    mods.append((name, base, size, timestamp))
    off += 108

exe = next((m for m in mods if 'simplewall' in m[0].lower()), None)
if exe:
    print(f'simplewall: base=0x{exe[1]:X} size=0x{exe[2]:X} ts=0x{exe[3]:X}')
if exe and exe[1] <= address < exe[1] + exe[2]:
    print(f'>>> CRASH RVA in simplewall.exe: 0x{address - exe[1]:X}')
for name, base, size, ts in mods:
    if base <= address < base + size:
        print(f'>>> crash module: {name} offset=0x{address - base:X}')

# context record: x64 CONTEXT — Rip at offset 0xF8
RIP = struct.unpack_from('<Q', d, ctx_rva + 0xF8)[0]
RSP = struct.unpack_from('<Q', d, ctx_rva + 0x98)[0]
print(f'CONTEXT Rip=0x{RIP:X} Rsp=0x{RSP:X}')
if exe and exe[1] <= RIP < exe[1] + exe[2]:
    print(f'>>> Rip RVA in simplewall.exe: 0x{RIP - exe[1]:X}')

# raw stack scan for simplewall return addresses (frame approximation)
sz, thrva = streams[3][0]
nthr = struct.unpack_from('<I', d, thrva)[0]
o = thrva + 4
stack_found = None
for i in range(nthr):
    tid_t, suspend, prio, _1, teb, stack_start, stack_end = struct.unpack_from('<IIIIIQQ', d, o)[:7]
    # MINIDUMP_THREAD: ThreadId(4) SuspendCount(4) PriorityClass(4) Priority(4) Teb(8) Stack{Start(8) End(8) Size(4) Rva(4)} ThreadContext{Size(4) Rva(4)}
    st_size, st_rva = struct.unpack_from('<II', d, o + 32)
    if tid_t == tid:
        stack_found = (st_rva, st_size)
    o += 48
if stack_found:
    st_rva, st_size = stack_found
    print(f'stack: rva=0x{st_rva:X} size={st_size}')
    count = 0
    for off in range(0, st_size - 8, 8):
        v = struct.unpack_from('<Q', d, st_rva + off)[0]
        if exe and exe[1] <= v < exe[1] + exe[2]:
            print(f'  stack+{off}: simplewall+0x{v - exe[1]:X}')
            count += 1
            if count > 12:
                break
