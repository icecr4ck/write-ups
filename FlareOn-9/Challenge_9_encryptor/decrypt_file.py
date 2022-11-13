import re
from Crypto.Cipher import ChaCha20
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.locationdb import LocationDB
from miasm.analysis.sandbox import Sandbox_Win_x86_64


def convert_to_raw(bn):
    res = b""
    for i in range(int(len(bn)/8), 0, -1):
        res += bn[(i-1)*8:i*8][::-1]
    return res


loc_db = LocationDB()

parser = Sandbox_Win_x86_64.parser()
parser.add_argument("executable")
parser.add_argument("encrypted_file")
args = parser.parse_args()

with open(args.encrypted_file, "rb") as f:
    data = f.read()

m = re.search(rb"[a-f0-9]+\n", data)
start, _ = m.span()

hardcoded_modulus, enc_file_modulus, enc_code, enc_key, _ = data[start:].split(b'\n')

sb = Sandbox_Win_x86_64(loc_db, args.executable, args, globals())

modulus_addr = 0x20001000
modulus = convert_to_raw(bytes.fromhex(enc_file_modulus.decode())) + b"\x00"*8
sb.jitter.vm.add_memory_page(modulus_addr, PAGE_READ | PAGE_WRITE, modulus)

base_addr = 0x20002000
base = convert_to_raw(bytes.fromhex(enc_key.decode())) + b"\x00"*8
sb.jitter.vm.add_memory_page(base_addr, PAGE_READ | PAGE_WRITE, base)

exponent_addr = 0x20003000
exponent = bytes.fromhex("01000100") + b"\x00"*132
sb.jitter.vm.add_memory_page(exponent_addr, PAGE_READ | PAGE_WRITE, exponent)

remainder_addr = 0x20004000
remainder = b"\x00"*136
sb.jitter.vm.add_memory_page(remainder_addr, PAGE_READ | PAGE_WRITE, remainder)

modular_exp_addr = 0x4016CC

sb.call(modular_exp_addr, remainder_addr, base_addr, exponent_addr, modulus_addr)

result = sb.jitter.vm.get_mem(remainder_addr, 128)

chacha20_key = result[:32]
chacha20_nonce = result[36:48]

cipher = ChaCha20.new(key=chacha20_key, nonce=chacha20_nonce)
print(cipher.decrypt(data[:start]).decode())
