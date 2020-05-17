import re
from pwn import *

context.log_level = 'debug'

r = remote('challenges2.challenge-anssi.fr', 3000)

def get_serial(username, key):
    with open('out.txt','w+') as fout:
        with open('err.txt','w+') as ferr:
            out = subprocess.call(["./keygen", username, str(key)], stdout=fout, stderr=ferr)
            fout.seek(0)
            serial = fout.read()
    return serial.strip()

while True:
    line = r.readline()
    match = re.findall(r'Give me two valid serials for username: (.*)$', line.decode())
    if match:
        username = match[0]
        print("[+] Username: {}".format(username))
        r.sendline(get_serial(username, 0))
        r.sendline(get_serial(username, 1))
    else:
        r.interactive()
