import struct
from argparse import ArgumentParser
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

parser = ArgumentParser()
parser.add_argument("filename")
args = parser.parse_args()

def code_sentinelle(jitter):
    jitter.running = False
    jitter.pc = 0
    return True

def emulate_func(jitter, score):
    jitter.cpu.AX = 0x96f
    jitter.cpu.BX = score 
    jitter.push_uint16_t(0x1337)
    jitter.add_breakpoint(0x1337, code_sentinelle)
    jitter.run(0x17e)
    return jitter.vm.get_mem(jitter.cpu.AX, 16)

def emulate_rand(jitter, min, max):
    jitter.cpu.AX = min 
    jitter.cpu.BX = max 
    jitter.push_uint16_t(0x1337)
    jitter.add_breakpoint(0x1337, code_sentinelle)
    jitter.run(0x9a)
    return jitter.cpu.CX

with open(args.filename, 'rb') as f:
    pe_dos = f.read()

seg0_start_offset = 0x80
seg0_end_offset = 0xfae
seg0_data = pe_dos[seg0_start_offset:seg0_end_offset]

loc_db = LocationDB()

jitter = Machine("x86_16").jitter(loc_db, "gcc")
jitter.stack_base = 0x4000
jitter.stack_size = 0x1000
jitter.init_stack()
jitter.vm.add_memory_page(0, PAGE_READ | PAGE_WRITE, seg0_data)

seed = 0xc0a
jitter.vm.set_mem(0x98, struct.pack("<H", seed))

num2sc = { 0: "H", 1: "P", 2: "K", 3: "M" }

seq = []
for i in range(128):
    score = 0
    num = emulate_rand(jitter, 0, 3)
    sc = num2sc[num]
    seq.append(sc)
    jitter.vm.set_mem(0x97f+i, sc.encode('utf-8')) 
    for sc in seq:
        score += ord(sc)
    output = emulate_func(jitter, score)
    jitter.vm.set_mem(0x96f, output)

patch_offset = 0x8e85
data = bytearray(pe_dos)
for i, b in enumerate(output):
    data[patch_offset+i] = b

with open("FlareSay_patched.exe", "wb") as f:
    f.write(data)
