from tqdm import tqdm
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

with open(args.filename, 'rb') as f:
    data = f.read()

start_addr = 0x600
func_addr = 0x1296

loc_db = LocationDB()

jitter = Machine("x86_16").jitter(loc_db, "gcc")
jitter.stack_base = 0xD000
jitter.stack_size = 0x1000
jitter.init_stack()
jitter.vm.add_memory_page(start_addr, PAGE_READ | PAGE_WRITE, data)

for n in tqdm(range(0, 0x10000)):
    key_addr = 0x2A4C
    key = [6, 1, 0xD, 2, 0xE, 6, 0xE, 1, 4, 0xA, 7, 5]
    key.append(n & 0xF)
    key.append((n >> 4) & 0xF)
    key.append((n >> 8) & 0xF)
    key.append((n >> 12) & 0xF)
    jitter.vm.set_mem(key_addr, bytes(key))

    jitter.push_uint16_t(0x1337)
    jitter.add_breakpoint(0x1337, code_sentinelle)
    jitter.run(func_addr)

    if jitter.cpu.AX == 0:
        key_s = ""
        for c in key:
            key_s += f"{c:X}"
        print(f"Found key: {key_s}")
        break
    
    jitter.vm.set_mem(start_addr, data)
