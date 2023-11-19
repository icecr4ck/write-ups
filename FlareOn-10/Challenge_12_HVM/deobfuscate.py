import ida_ua
import ida_ida
import ida_bytes
import ida_idaapi
import ida_kernwin
from Crypto.Cipher import ARC4

PATTERN = '49 B8 ?? ?? ?? ?? ?? ?? ?? ?? 41 B9 ?? ?? ?? ?? E4 03'

def decrypt_function(ea):
    insn = ida_ua.insn_t()
    length = ida_ua.decode_insn(insn, ea)
    rc4_key_int = insn.ops[1].value
    rc4_key = rc4_key_int.to_bytes(8, byteorder="little")
    
    ea += length
    
    length = ida_ua.decode_insn(insn, ea)
    data_size = insn.ops[1].value
    
    ea += length + 2
    
    data = ida_bytes.get_bytes(ea, data_size)
    dec_data = ARC4.new(rc4_key).decrypt(data)
    ida_bytes.patch_bytes(ea, dec_data)

start_ea = ida_ida.inf_get_min_ea()
end_ea = ida_ida.inf_get_max_ea()

while True:
    pat = ida_bytes.compiled_binpat_vec_t()
    ida_bytes.parse_binpat_str(pat, start_ea, PATTERN, 16)
    match_ea = ida_bytes.bin_search(start_ea, end_ea, pat, ida_bytes.BIN_SEARCH_FORWARD)
    if match_ea == ida_idaapi.BADADDR:
        break
    decrypt_function(match_ea)
    print(f"Decrypted function at {hex(match_ea)}")
    start_ea = match_ea + 1
