import socket
import struct
from dnslib import *


class MT19937:
    def __init__(self, seed):
        self.w = 32
        self.n = 624
        self.m = 397
        self.r = 31
        self.a = 0x9908B0DF
        self.u = 11
        self.d = 0xFFFFFFFF
        self.s = 7
        self.b = 0x9D2C5680
        self.t = 15
        self.c = 0xEFC60000
        self.l = 18
        self.f = 1812433253
        
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = -~self.lower_mask

        self.index = self.n + 1
        self.state = [0] * self.n

        self.state[0] = seed
        for i in range(1, self.n):
            self.state[i] = (self.f * (self.state[i-1] ^ (self.state[i-1] >> (self.w-2))) + i) & 0xffffffff


    def extract_number(self):
        if self.index >= self.n:
            self.twist()
            self.index = 0

        y = self.state[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        self.index += 1
        return y & 0xffffffff


    def twist(self):
        for i in range(0, self.n):
            x = (self.state[i] & self.upper_mask) + (self.state[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ self.a
            self.state[i] = self.state[(i + self.m) % self.n] ^ xA


    def rand(self, mn, mx):
        return mn + (self.extract_number() % (mx - mn))


chars_counter = "amsjl6zci20dbt35guhw7n1fqvx4k8y9rpoe"
chars_domain = "abcdefghijklmnopqrstuvwxyz0123456789"


def decode_num(data):
    res = 0
    for i in range(len(data)):
        res += (len(chars_counter) ** i) * chars_counter.index(data[::-1][i])
    return res 


def scramble_chars_domain(ctr):
    res = ""
    charset = list(chars_domain)
    mt = MT19937(ctr)
    for i in range(len(chars_domain)):
        num = mt.rand(0, len(charset))
        res += charset[num]
        charset.remove(charset[num])

    return res


def decode_data(data, domain):
    return "".join([chars_domain[domain.index(c)] for c in data])


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('192.168.56.103', 53))

tasks = ['2', '10', '8', '19', '11', '1', '15', '13', '22', '16', '5', '12', '21', '3', '18', '17', '20', '14', '9', '7', '4']

task_data = b""
task_offset = 0
agent_id = "1"

while True:
    data, addr = s.recvfrom(1024)
    
    request = DNSRecord.parse(data)

    qname = request.q.qname
    domain = str(qname)

    if not domain.endswith("flare-on.com."):
        continue

    if domain == "flare-on.com.":
        print("======================== flare-on.com ========================")

        answer = A("107.180.40.55")

        reply = DNSRecord(DNSHeader(id=request.header.id), q=request.q)
        reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=127, rdata=answer))

        s.sendto(reply.pack(), addr)
        continue

    elif domain == "webmail.flare-on.com.":
        print("======================== webmail.flare-on.com ========================")
        
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=3), q=request.q)

        s.sendto(reply.pack(), addr)
        continue


    sub_domain = domain.split('.')[0]

    print(f"Sub-domain: {sub_domain}")

    enc_counter = sub_domain[-3:]
    counter = decode_num(enc_counter)
    print(f"\tDecoded counter: {counter}")

    domain = scramble_chars_domain(counter)

    enc_payload = sub_domain[:-3]
    dec_payload = decode_data(enc_payload, domain)
   
    dec_first = decode_num(dec_payload[0])

    if dec_first == int(agent_id):
        print("\tRequest type: 4 (GET_TASK_SIZE)")
        
        task_offset = 0
        task_data = b"\x2b" + tasks.pop(0).encode()
        task_size = len(task_data)
        
        answer_data = b"\x80"
        answer_data += struct.pack("I", task_size)[::-1][1:]

    elif dec_first == 0:
        print("\tRequest type: 0 (INIT)")

        data = dec_payload[1:]
        print(f"\tPayload: {data}")

        answer_data = b"\x03\x13\x37" + agent_id.encode()

    elif dec_first == 2:
        print("\tRequest type: 2 (GET_TASK_DATA)")
        
        data = dec_payload[1:]

        agent_id = decode_num(data[0])
        print(f"\tFrom agent: {agent_id}")
       
        answer_data = task_data

    elif dec_first == 1:
        print("\tRequest type: 1 (GET_TASK_RESULT)")

        data = dec_payload[1:]
        print(f"\tResult: {data}")

        answer_data = b"1234" 

    elif dec_first == 3:
        print("\tRequest type: 1 (GET_TASK_DATA)")

        answer_data = task_data

    if len(answer_data) != 4:
        answer_data += b"\x80"*(4-len(answer_data))

    answer_ip = '.'.join(map(str, list(answer_data)))
    print(f"\tAnswer: {answer_ip}")
    answer = A(answer_ip)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=127, rdata=answer))

    s.sendto(reply.pack(), addr)
