import ida_ua
import ida_auto
import ida_bytes
import ida_funcs
import ida_allins
import ida_kernwin

def get_jump_location(ea):
    insn = ida_ua.insn_t()
    length = ida_ua.decode_insn(insn, ea)
    if insn.itype != ida_allins.NN_jmp:
        return None, None
    return insn.ops[0].addr, length
    
def redo_analysis(ea):
    ida_funcs.del_func(ea)
    ida_bytes.del_items(ea)
    ida_auto.auto_recreate_insn(ea)

def deobfuscate(cur_ea):
    todo = set()

    first_jmp_dst, _ = get_jump_location(cur_ea)
    if not first_jmp_dst:
        print(f"Error: instruction at {hex(cur_ea)} is not a jmp, try again")
        return
        
    todo.add(first_jmp_dst)
    func = ida_funcs.get_func(cur_ea)
    while todo:
        ea = todo.pop()
        
        if ida_funcs.func_contains(func, ea):
            print(f"Found jump back to function at {hex(ea)}")
            continue
        
        redo_analysis(ea)
        
        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, ea)
        if insn.itype == ida_allins.NN_retn:
            print(f"Found ret at {hex(ea)}")
            ida_funcs.append_func_tail(func, ea, ea + length)
            continue
        
        # conditional jump values are all between NN_ja and NN_jz
        elif insn.itype >= ida_allins.NN_ja and insn.itype <= ida_allins.NN_jz:
            print(f"Found conditional jump at {hex(ea)}")
            todo.add(insn.ops[0].addr)
            
        start_tail_addr = ea
        ea += length
        
        func_jmp = ida_funcs.get_func(ea)
        if func_jmp:
            ida_funcs.remove_func_tail(func_jmp, ea)
            
        redo_analysis(ea)
        
        jmp_dst, length = get_jump_location(ea)
        if not jmp_dst:
            print(f"Instruction at {hex(end_tail_addr)} is not a jmp, unknwon pattern")
            return
        
        ida_funcs.append_func_tail(func, start_tail_addr, ea + length)
        print(f"Created tail chunk at {hex(start_tail_addr)}")
        
        todo.add(jmp_dst)


class Deobfuscator(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        deobfuscate(ctx.cur_ea)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_DISASM else ida_kernwin.AST_DISABLE_FOR_WIDGET


act_name = "deobfuscator"
action = ida_kernwin.action_desc_t(act_name, "Deobfuscate", Deobfuscator(), "Ctrl+Shift+D")
if ida_kernwin.register_action(action):
    print("Deobfuscator registered")
    
    class Hooks(ida_kernwin.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup):
            if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
                ida_kernwin.attach_action_to_popup(widget, popup, act_name, None)

    hooks = Hooks()
    hooks.hook()
    
else:
    if ida_kernwin.unregister_action(act_name):
        print("Deobfuscator unregistered")

    if hooks is not None:
        hooks.unhook()
        hooks = None


