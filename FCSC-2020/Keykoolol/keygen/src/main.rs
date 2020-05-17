use std::env;
use std::arch::x86_64::*;

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

fn multiply(x: u8, y: u8) -> u8 {
    ((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))
}

fn aesni_inv_encrypt(enc_array: &[u8], key_array: &[u8]) -> [u8; 16] {
    let mut dec_array: [u8; 16] = [0; 16];

    // add round key
    for i in 0..16 {
        dec_array[i] = enc_array[i] ^ key_array[i];
    }

    // inv mix columns
    for i in 0..4 {
        let a = dec_array[0+i*4];
        let b = dec_array[1+i*4];
        let c = dec_array[2+i*4];
        let d = dec_array[3+i*4];

        dec_array[0+i*4] = (multiply(a, 0xe) ^ multiply(b, 0xb) ^ multiply(c, 0xd) ^ multiply(d, 0x9)) as u8;
        dec_array[1+i*4] = (multiply(b, 0xe) ^ multiply(c, 0xb) ^ multiply(d, 0xd) ^ multiply(a, 0x9)) as u8;
        dec_array[2+i*4] = (multiply(c, 0xe) ^ multiply(d, 0xb) ^ multiply(a, 0xd) ^ multiply(b, 0x9)) as u8;
        dec_array[3+i*4] = (multiply(d, 0xe) ^ multiply(a, 0xb) ^ multiply(b, 0xd) ^ multiply(c, 0x9)) as u8;
    }

    // inv sub bytes
    for i in 0..16 {
        dec_array[i] = INV_SBOX[usize::from(dec_array[i])] as u8;
    }

    // inv shift rows
    let tmp = dec_array[13];
    dec_array[13] = dec_array[9];
    dec_array[9] = dec_array[5];
    dec_array[5] = dec_array[1];
    dec_array[1] = tmp;

    let tmp = dec_array[2];
    dec_array[2] = dec_array[10];
    dec_array[10] = tmp;
    let tmp = dec_array[6];
    dec_array[6] = dec_array[14];
    dec_array[14] = tmp;

    let tmp = dec_array[3];
    dec_array[3] = dec_array[7];
    dec_array[7] = dec_array[11];
    dec_array[11] = dec_array[15];
    dec_array[15] = tmp;

    return dec_array;
}

fn aesni_encrypt(dec_array: &[u8], key_array: &[u8]) -> __m128i {
    let key: __m128i;
    let dec: __m128i;

    unsafe {
        key = _mm_loadu_si128(key_array as *const _ as *const __m128i);
        dec = _mm_loadu_si128(dec_array as *const _ as *const __m128i);
        _mm_aesenc_si128(dec, key)
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let username = &args[1];
    let key: u8 = args[2].parse().unwrap();

    let mut username_enc: [u8; 16] = [0; 16];

    for (i, &c) in username.as_bytes().iter().enumerate() {
        for j in 0..16 {
            username_enc[(i + j) % 0x10] ^= ((((usize::from(c) + j) * 0xD) ^ 0x25) % 0xFF) as u8;
        }
    }

    let mut serial: [u8; 128] =  [0; 128];
    serial[..16].copy_from_slice(&username_enc);

    for i in 0..80 {
        serial[i + 16] = ((usize::from(serial[i]) * 3) ^ 0xFF) as u8; 
    }

    let aes_key: [u8; 32] = [key; 32];

    serial[96..128].copy_from_slice(&aes_key);

    let serial_encrypted = serial.clone();

    let mut buf1: [u8; 16];
    let mut buf2: [u8; 16];
    let mut buf3: [u8; 16];
    let mut buf4: [u8; 16];
    let mut buf5: [u8; 16];
    let mut buf6: [u8; 16];

    for _n in 0..32 {
        buf1 = aesni_inv_encrypt(&serial[16..32], &serial[96..112]);
        buf2 = aesni_inv_encrypt(&serial[32..48], &serial[96..112]);
        buf4 = aesni_inv_encrypt(&serial[64..80], &serial[96..112]);
        buf3 = aesni_inv_encrypt(&serial[48..64], &buf4);
        buf5 = aesni_inv_encrypt(&serial[80..96], &serial[112..128]);
        buf6 = aesni_inv_encrypt(&serial[0..16], &buf1);

        serial[0..16].copy_from_slice(&buf1);
        serial[16..32].copy_from_slice(&buf2);
        serial[32..48].copy_from_slice(&buf3);
        serial[48..64].copy_from_slice(&buf4);
        serial[64..80].copy_from_slice(&buf5);
        serial[80..96].copy_from_slice(&buf6);
    }

    println!("{}", hex::encode(&serial[..]));
    
    for _n in 0..32 {
        unsafe {
            buf1 = std::mem::transmute::<__m128i, [u8; 16]>(aesni_encrypt(&serial[80..96], &serial[0..16]));
            buf6 = std::mem::transmute::<__m128i, [u8; 16]>(aesni_encrypt(&serial[64..80], &serial[112..128]));
            buf5 = std::mem::transmute::<__m128i, [u8; 16]>(aesni_encrypt(&serial[48..64], &serial[96..112]));
            buf4 = std::mem::transmute::<__m128i, [u8; 16]>(aesni_encrypt(&serial[32..48], &serial[48..64]));
            buf3 = std::mem::transmute::<__m128i, [u8; 16]>(aesni_encrypt(&serial[16..32], &serial[96..112]));
            buf2 = std::mem::transmute::<__m128i, [u8; 16]>(aesni_encrypt(&serial[0..16], &serial[96..112]));
        }

        serial[0..16].copy_from_slice(&buf1);
        serial[16..32].copy_from_slice(&buf2);
        serial[32..48].copy_from_slice(&buf3);
        serial[48..64].copy_from_slice(&buf4);
        serial[64..80].copy_from_slice(&buf5);
        serial[80..96].copy_from_slice(&buf6);
    }

    assert_eq!(hex::encode(&serial[..]), hex::encode(&serial_encrypted[..]));
}
