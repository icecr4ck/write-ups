from miasm.analysis.sandbox import Sandbox_Linux_x86_64
from miasm.analysis.dse import DSEEngine
from miasm.expression.expression import *

def xxx___printf_chk(jitter):
    ret_ad, args = jitter.func_args_systemv(["flag", "format", "arg"])
    print(jitter.get_c_str(args.format))
    return jitter.func_ret_systemv(ret_ad, 1)

def xxx_fgets(jitter):
    ret_ad, args = jitter.func_args_systemv(["dest", "size", "stream"])
    s = input()
    jitter.vm.set_mem(args.dest, s.encode())
    return jitter.func_ret_systemv(ret_ad, len(s))

def xxx_strcspn(jitter):
    ret_ad, args = jitter.func_args_systemv(["s", "rejected"])
    s = jitter.get_c_str(args.s)
    jitter.vm.set_mem(args.s, s.strip().encode())
    return jitter.func_ret_systemv(ret_ad, len(s))

def xxx___memcpy_chk(jitter):
    ret_ad, args = jitter.func_args_systemv(["dest", "src", "len", "destlen"])
    src = jitter.vm.get_mem(args.src, args.len)
    jitter.vm.set_mem(args.dest, src)

    global dse
    dse.attach(jitter)

    return jitter.func_ret_systemv(ret_ad, args.dest)

def xxx_puts_symb(dse):
    raise RuntimeError("Exit")

def symbolize_vm(dse):
    global vm_registers_symb, already_disass

    # update the DSE state (including the memory) from the concrete state
    dse.update_state_from_concrete(mem=True)

    # symbolize the memory corresponding to the VM registers (16 registers of 32 bits at 0x203040)
    for i in range(16):
        vm_registers_symb[ExprMem(ExprInt(0x203040 + i*4, 64), 32)] = ExprId("VM_R{}".format(i), 32)

    # symbolize the VM registers that correpond to real registers
    vm_registers_symb[dse.ir_arch.arch.regs.R9] = ExprId("VM_FLAGS", 64)
    vm_registers_symb[dse.ir_arch.arch.regs.RSI] = ExprId("VM_PC", 64)

    # update the DSE state with the VM registers symbols
    dse.update_state(vm_registers_symb)

    # get the VM state (PC, instruction bytes and opcode)
    vm_pc = int(dse.jitter.cpu.RSI)
    vm_instr = int(dse.jitter.cpu.RCX)
    vm_opcode = int(dse.jitter.cpu.RAX)

    # if the VM instruction was not already disassembled, we print the state and add a breakpoint at NEXT_ADDR
    if not vm_pc in already_disass or (vm_pc in already_disass and vm_instr != already_disass[vm_pc]):
        print("\n{:x}:".format(vm_pc), end=" ")

        already_disass[vm_pc] = vm_instr

        # VM opcode 0xFF exits the VM 
        if vm_opcode == 0xFF:
            print("EXIT")

        # VM opcode 30 executes aesenc instruction but this instruction is not implemented in miasm
        if vm_opcode == 30:
            arg0 = vm_registers_symb[ExprMem(ExprInt(0x203040+(((vm_instr >> 16) & 0xF)*4), 64), 32)]
            arg1 = vm_registers_symb[ExprMem(ExprInt(0x203040+(((vm_instr >> 12) & 0xF)*4), 64), 32)]
            dest = vm_registers_symb[ExprMem(ExprInt(0x203040+(((vm_instr >> 20) & 0xF)*4), 64), 32)]
            print("@128[{} + 0x203080] = AESENC(@128[{} + 0x203080], @128[{} + 0x203080])".format(dest, arg0, arg1))

        dse.add_instrumentation(NEXT_ADDR, disass_vm_instruction)

    # as we do not want miasm to raise an exception when aesenc is jitted, we jump after the instruction and update the DSE state accordingly
    if vm_instr >> 24 == 30:
        dse.jitter.pc = 0x232d
        dse.jitter.cpu.RIP = 0x232d
        dse.update_state({
            dse.ir_arch.arch.regs.RIP: ExprInt(0x232d, 64),
            dse.ir_arch.arch.regs.RAX: ExprInt(vm_pc+4, 64) # update pc
        })

    return True

def disass_vm_instruction(dse):
    global vm_registers_symb

    vm_instr = ""

    # get memory modifications
    for dst, src in dse.symb.modified(ids=False):
        # do not print vm registers unchanged
        if dst in vm_registers_symb and src == vm_registers_symb[dst]:
            continue
        vm_instr += "{} = {}\n".format(dst.replace_expr(vm_registers_symb), dse.eval_expr(src))

    # get register modifications
    for dst, src in dse.symb.modified(mems=False):
        # dst = ExprMem(VM_REG)
        if src in vm_registers_symb:
            vm_instr += "{} = {}\n".format(dst, dse.eval_expr(src))
        # VM_REG != VM_REG_ID
        elif dst in vm_registers_symb and src != vm_registers_symb[dst] and vm_registers_symb[dst] != ExprId("VM_PC", 64):
            vm_instr += "{} = {}\n".format(vm_registers_symb[dst], dse.eval_expr(src))

    # if no modifications then print ZF and VM_PC changes
    if not vm_instr:
        for dst, src in dse.symb.modified(mems=False):
            if dst == dse.ir_arch.arch.regs.zf:
                vm_instr += "ZF = {}\n".format(dse.eval_expr(src))
            elif dst in vm_registers_symb and vm_registers_symb[dst] == ExprId("VM_PC", 64):
                vm_instr += "VM_PC = {}\n".format(dse.eval_expr(src))

    print(vm_instr.strip())

    # remove callback
    del dse.instrumentation[NEXT_ADDR]

    return True


parser = Sandbox_Linux_x86_64.parser("Disassembler for keykoolol challenge")
parser.add_argument("filename", help="Challenge filename")
options = parser.parse_args()

sb = Sandbox_Linux_x86_64(options.filename, options, globals())

dse = DSEEngine(sb.machine)
dse.add_lib_handler(sb.libs, globals())

DISPATCHER_ADDR = 0xa5D
NEXT_ADDR = 0xa77

vm_registers_symb = {}
already_disass = {}

dse.add_instrumentation(DISPATCHER_ADDR, symbolize_vm)

sb.run()
