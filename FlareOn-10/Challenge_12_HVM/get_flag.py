from base64 import b64encode
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.os_dep.win_api_x86_32 import winobjs

FIRST_INPUT = b"FLARE2023FLARE2023FLARE2023FLARE2023\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
ENC_FLAG = bytes.fromhex("1976372F3D1D263F7B0639581223256B2A073C381868161C30093423085B212436616A266A0F445D06")

def code_sentinelle(jitter):
    jitter.running = False
    jitter.pc = 0
    return True

def custom_salsa20_block(jitter, state_in):
    state_in_addr = winobjs.heap.alloc(jitter, 64)
    jitter.vm.set_mem(state_in_addr, state_in)

    state_out_addr = winobjs.heap.alloc(jitter, 64)
    jitter.vm.set_mem(state_out_addr, b"\x00"*64)

    salsa20_func_start_addr = 0
    salsa20_func_end_addr = 0x303
    jitter.cpu.RDI = state_out_addr
    jitter.cpu.RSI = state_in_addr

    jitter.add_breakpoint(salsa20_func_end_addr, code_sentinelle)
    jitter.run(salsa20_func_start_addr)

    return jitter.vm.get_mem(state_out_addr, 64)

def custom_salsa20_encrypt(jitter, data, state):
    xor_func_start_addr = 0x330
    xor_func_end_addr = 0x397

    data_addr = winobjs.heap.alloc(jitter, len(data))
    jitter.vm.set_mem(data_addr, data)

    state_addr = winobjs.heap.alloc(jitter, len(state))
    jitter.vm.set_mem(state_addr, state)

    for i in range(0, len(data) // 8, 2):
        jitter.cpu.RDI = data_addr + ((i+1)*8)
        jitter.cpu.RSI = data_addr + ((i)*8)
        jitter.cpu.RDX = state_addr
        jitter.add_breakpoint(xor_func_end_addr, code_sentinelle)
        jitter.run(xor_func_start_addr)

    return jitter.vm.get_mem(data_addr, 48)


with open("bytecode.bin", "rb") as f:
    data = f.read()

loc_db = LocationDB()

jitter = Machine("x86_64").jitter(loc_db, "gcc")
jitter.init_stack()
#jitter.set_trace_log()
jitter.vm.add_memory_page(0, PAGE_READ | PAGE_WRITE, data)

state_in = 16*FIRST_INPUT[:4]
state_out = custom_salsa20_block(jitter, state_in)

first_input_enc = custom_salsa20_encrypt(jitter, FIRST_INPUT, state_out)

final_key = b64encode(bytes(first_input_enc))
print(final_key)
flag = []
for i, c in enumerate(ENC_FLAG):
    flag.append(c ^ final_key[i])

print(bytes(flag).decode() + "@flare-on.com")
