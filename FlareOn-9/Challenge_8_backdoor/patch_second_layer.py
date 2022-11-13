import lief
from Crypto.Cipher import ARC4

TARGET = "FlareOn.Backdoor_patched.exe"

XOR_KEY = 0xa298a6bd
RC4_KEY = bytes.fromhex("1278abdf")

D = {
    88: 0,
    214: 0,
    215: 0,
    95: 0,
    65024: 0,
    59: 3,
    46: 2,
    60: 3,
    47: 2,
    65: 3,
    52: 2,
    61: 3,
    48: 2,
    66: 3,
    53: 2,
    62: 3,
    49: 2,
    67: 3,
    54: 2,
    63: 3,
    50: 2,
    68: 3,
    55: 2,
    64: 3,
    51: 2,
    140: 1,
    56: 3,
    43: 2,
    1: 0,
    57: 3,
    44: 2,
    58: 3,
    45: 2,
    40: 1,
    41: 1,
    111: 1,
    116: 1,
    65025: 0,
    65026: 0,
    65027: 0,
    195: 0,
    65028: 0,
    65029: 0,
    65046: 1,
    211: 0,
    103: 0,
    104: 0,
    105: 0,
    106: 0,
    212: 0,
    138: 0,
    179: 0,
    130: 0,
    181: 0,
    131: 0,
    183: 0,
    132: 0,
    185: 0,
    133: 0,
    213: 0,
    139: 0,
    180: 0,
    134: 0,
    182: 0,
    135: 0,
    184: 0,
    136: 0,
    186: 0,
    137: 0,
    118: 0,
    107: 0,
    108: 0,
    224: 0,
    210: 0,
    209: 0,
    109: 0,
    110: 0,
    65047: 0,
    112: 1,
    91: 0,
    92: 0,
    37: 0,
    65041: 0,
    220: 0,
    65048: 0,
    65045: 1,
    117: 1,
    39: 1,
    65033: 5,
    2: 0,
    3: 0,
    4: 0,
    5: 0,
    14: 4,
    65034: 5,
    15: 4,
    32: 6,
    22: 0,
    23: 0,
    24: 0,
    25: 0,
    26: 0,
    27: 0,
    28: 0,
    29: 0,
    30: 0,
    21: 0,
    31: 4,
    33: 7,
    34: 6,
    35: 7,
    163: 1,
    151: 0,
    144: 0,
    146: 0,
    148: 0,
    150: 0,
    152: 0,
    153: 0,
    154: 0,
    145: 0,
    147: 0,
    149: 0,
    143: 1,
    123: 1,
    124: 1,
    65030: 1,
    77: 0,
    70: 0,
    72: 0,
    74: 0,
    76: 0,
    78: 0,
    79: 0,
    80: 0,
    71: 0,
    73: 0,
    75: 0,
    142: 0,
    65036: 5,
    6: 0,
    7: 0,
    8: 0,
    9: 0,
    17: 4,
    65037: 5,
    18: 4,
    20: 0,
    113: 1,
    126: 1,
    127: 1,
    114: 1,
    208: 1,
    65031: 1,
    221: 3,
    222: 2,
    65039: 0,
    198: 1,
    90: 0,
    216: 0,
    217: 0,
    101: 0,
    141: 1,
    115: 1,
    65049: 4,
    0: 0,
    102: 0,
    96: 0,
    38: 0,
    254: 0,
    253: 0,
    252: 0,
    251: 0,
    250: 0,
    249: 0,
    248: 0,
    255: 0,
    65054: 0,
    65053: 0,
    194: 1,
    93: 0,
    94: 0,
    42: 0,
    65050: 0,
    98: 0,
    99: 0,
    100: 0,
    65052: 1,
    65035: 5,
    16: 4,
    164: 1,
    155: 0,
    156: 0,
    157: 0,
    158: 0,
    159: 0,
    160: 0,
    161: 0,
    162: 0,
    125: 1,
    223: 0,
    82: 0,
    83: 0,
    84: 0,
    85: 0,
    86: 0,
    87: 0,
    81: 0,
    65038: 5,
    10: 0,
    11: 0,
    12: 0,
    13: 0,
    19: 4,
    129: 1,
    128: 1,
    89: 0,
    218: 0,
    219: 0,
    69: 8,
    65044: 0,
    122: 0,
    65042: 4,
    121: 1,
    165: 1,
    65043: 0,
    97: 0
}

sections = {
    "ffc58f78": [0xaf18],
    "7c5ccd91": [0x93e8],
    "b3650258": [0xb6dc],
    "305a002f": [0x96dc],
    "4a0fb136": [0x9970],
    "0686a47b": [0xb1d4],
    "2fad6d86": [0xb520],
    "7cddb7c1": [0xb8e8],
    "a4691056": [0xb834],
    "cc80b00c": [0x9fac],
    "becb82d3": [0x985c],
    "3460378b": [0xa90c],
    "0651f80b": [0xa660],
    "edd1976b": [0xa714],
    "e712183a": [0x1987c, 0x198e4],
    "710b11bc": [0x199b0],
    "326aa956": [0x9808],
    "8d3a199f": [0x19714],
    "77c01ab2": [0xb4a4],
    "719ee568": [0xb3dc],
    "c61192c7": [0xb150],
    "7135726c": [0x98b0],
    "1b8e2238": [0x197dc],
    "794ac846": [0x9a34],
    "9181748d": [0xa82c],
    "4951e547": [0x19ad8],
    "538fcc69": [0x9794],
    "b1c8119c": [0x908a],
    "f965be73": [0xa5c4],
    "74fbaf68": [0xb314],
    "f9a758d3": [0xaaac],
    "69991a3e": [0x1994c],
    "80761762": [0x19a4c],
    "30b905e5": [0xa048],
    "4f0f2ca3": [0xa24c],
    "e530c010": [0xa9b8],
    "4ea4cf8d": [0xbd28],
    "977deaed": [0xb0a0, 0xb0f8],
    "11d539d6": [0xa0ec],
    "8de5507b": [0xa19c],
    "89b957e3": [0x91a0],
    "689d7525": [0x92ec],
    "30752c49": [0x9378],
    "5ca8a517": [0x9450],
    "96c576e4": [0x950c],
    "94957fff": [0x9a9c],
    "0e5cf5d9": [0x9b58],
    "27086010": [0x9be4],
    "ee6d9a21": [0x9d90],
    "c4493ff5": [0x9e8c],
    "85b3a7dd": [0xa300],
    "520c2390": [0xa490],
    "846fcbb2": [0x909e],
    "f8a2493f": [0xab4c],
    "1aa22d63": [0xacf0],
    "892fac73": [0xad58],
    "db08afea": [0xb9d0],
    "81e1a476": [0xbab0],
    "ede0bad0": [0xbb34],
    "699fdcf2": [0xbba0],
    "33d51cd2": [0xbc78],
    "310d4de0": [0xbfe8],
}

with open(TARGET, "rb") as f:
    data = bytearray(f.read())

b = lief.parse(TARGET)

for name, offsets in sections.items():
    # get encrypted IL bytecode from section corresponding to SHA256 hash
    enc_bc = b.get_section(name).content.tobytes()

    # decrypt IL bytecode with RC4
    dec_bc = bytearray(ARC4.new(RC4_KEY).decrypt(enc_bc))

    # decrypt metadata tokens with XOR
    i = 0
    while i < len(dec_bc):
        num = dec_bc[i]
        if num == 254:
            num = 65024 + dec_bc[i+1]
            i += 1

        i += 1
        ot = D[num]
        if ot == 1:
            # extract encrypted metadata token
            enc_md = dec_bc[i] + (dec_bc[i+1] << 8) + (dec_bc[i+2] << 16) + (dec_bc[i+3] << 24)

            # decrypt it
            dec_md = enc_md ^ XOR_KEY

            # patch token in bytecode
            dec_bc[i] = dec_md & 0xFF
            dec_bc[i+1] = (dec_md >> 8) & 0xFF
            dec_bc[i+2] = (dec_md >> 16) & 0xFF
            dec_bc[i+3] = (dec_md >> 24) & 0xFF

            i += 4

        elif ot == 2 or ot == 4:
            i += 1

        elif ot == 3 or ot == 6:
            i += 4

        elif ot == 5:
            i += 2

        elif ot == 7:
            i += 8

        elif ot == 8:
            jmp_offset = dec_bc[i] + (dec_bc[i+1] << 8) + (dec_bc[i+2] << 16) + (dec_bc[i+3] << 24)
            i += 4 + (jmp_offset * 4)

    # patch methods body with cleaned IL bytecode
    for offset in offsets:
        for i in range(len(dec_bc)):
            data[offset+i] = dec_bc[i]

with open(TARGET, "wb") as f:
    f.write(data)
