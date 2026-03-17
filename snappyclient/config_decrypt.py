from __future__ import annotations
import snappy
import struct
from typing import List
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import base58
import py7zr
import io
import py7zr.io
import os
import sys



def generatekey_nonce(content):
    hashobject = hashlib.sha256(content)
    key  = hashobject.digest()
    counter = key[0] +1
    nonce = content
    while counter !=0:
        hashobject = hashlib.sha1(nonce)
        nonce = hashobject.digest()
        counter = counter - 1
    nonce = nonce[0:0xc]
    return key, nonce
    

def extract_7z_memory(archive_bytes: bytes, password_bytes: bytes, target_name: bytes) -> bytes:
    archive_stream = io.BytesIO(archive_bytes)
    pwd = password_bytes.decode('utf-8') 
    target_name = target_name.decode('utf-8')

    with py7zr.SevenZipFile(archive_stream, mode='r', password=pwd) as z:
        limit = 128 * 1024 * 1024
        factory = py7zr.io.BytesIOFactory(limit=limit)
        z.extract(targets=[target_name], factory=factory)
        fobj = factory.products.get(target_name)
        if fobj is None:
            raise RuntimeError(f"no file object for {target_name}")

        try:
            file_len = fobj.size()
        except Exception:
                fobj.seek(0, os.SEEK_END)
                file_len = fobj.tell()
                fobj.seek(0, os.SEEK_SET)


        buf = fobj.read(file_len)
        return buf

def ChaCha20Poly1305encrypt(key, nonce, plaincontent):
    aad = b''
    aead = ChaCha20Poly1305(key)
    ct_and_tag = aead.encrypt(nonce, plaincontent, aad)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    return ct_and_tag, ciphertext, tag

def ChaCha20Poly1305decrypt(key, nonce, enccontent, tag):
    aad = b''
    data = enccontent + tag
    aead = ChaCha20Poly1305(key)
    try:
        plaincontent = aead.decrypt(nonce, data, aad)
    except Exception:
        print("decryption failed")
        return 1
    return plaincontent
    
def rol32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def f1(x, y, z): return x ^ y ^ z
def f2(x, y, z): return ((y ^ z) & x) ^ z
def f3(x, y, z): return (x | (~y & 0xFFFFFFFF)) ^ z
def f4(x, y, z): return ((x ^ y) & z) ^ y
def f5(x, y, z): return x ^ (y | (~z & 0xFFFFFFFF))

RL = [
 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
]
RR = [
 5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
]
SL = [
 11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
]
SR = [
 8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
]

KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
FL = [f1, f2, f3, f4, f5]
FR = [f5, f4, f3, f2, f1]

def ripemd160_modified(data: bytes) -> bytes:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    bitlen = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    d = data + b"\x80"
    while (len(d) % 64) != 56:
        d += b"\x00"
    d += struct.pack("<Q", bitlen)

    for off in range(0, len(d), 64):
        X = list(struct.unpack("<16I", d[off:off+64]))

        L: List[int] = [h[0], h[1], h[2], h[3], h[4]]
        R: List[int] = [h[0], h[1], h[2], h[3], h[4]]

        for i in range(80):
            if i == 32:
                A_i, B_i, C_i, D_i, E_i = 2, 3, 4, 0, 1
                A = L[A_i]
                B = L[B_i]
                C = L[C_i]
                Dv = L[D_i]
                E = L[E_i]
                A = (A + f2(B, C, Dv) + X[0] + 0x6ED9EBA1) & 0xFFFFFFFF
                A = (rol32(A, 7) + E) & 0xFFFFFFFF
                C = rol32(C, 10)
                L[A_i] = A
                L[C_i] = C

            r = i // 16
            a,b,c,dd,e = L
            t = (a + FL[r](b,c,dd) + X[RL[i]] + KL[r]) & 0xFFFFFFFF
            t = (rol32(t, SL[i]) + e) & 0xFFFFFFFF
            L = [e, t, b, rol32(c,10), dd]

            rr = i // 16
            a,b,c,dd,e = R
            t = (a + FR[rr](b,c,dd) + X[RR[i]] + KR[rr]) & 0xFFFFFFFF
            t = (rol32(t, SR[i]) + e) & 0xFFFFFFFF
            R = [e, t, b, rol32(c,10), dd]

        a1,b1,c1,d1,e1 = L
        A2,B2,C2,D2,E2 = R
        t = (h[1] + c1 + D2) & 0xFFFFFFFF
        h[1] = (h[2] + d1 + E2) & 0xFFFFFFFF
        h[2] = (h[3] + e1 + A2) & 0xFFFFFFFF
        h[3] = (h[4] + a1 + B2) & 0xFFFFFFFF
        h[4] = (h[0] + b1 + C2) & 0xFFFFFFFF
        h[0] = t

    return struct.pack("<5I", *h)




def decrypt_config(filename: str)->None:
    with open(filename, 'rb') as f:
        compressed_data = f.read()  
    try:
        uncompressed_data = snappy.uncompress(compressed_data)
    except:
        print("decompression failed")
        exit()
    enc_data_size = struct.unpack('<H',uncompressed_data[0:2])[0]
    context_size =  struct.unpack('<H',uncompressed_data[2:4])[0]
    enc_content_outputtag = uncompressed_data[4:enc_data_size+4]
    enc_content = uncompressed_data[4:enc_data_size+4-16]
    output_tag = uncompressed_data[enc_data_size+4-16:enc_data_size+4]
    context_content = uncompressed_data[enc_data_size+4:enc_data_size+4+context_size]
    keya, noncea = generatekey_nonce(context_content)
    noncea = noncea[0:0xc]
    context_content_compressed = snappy.compress(context_content)
    ct_and_tag, ciphertext, tag = ChaCha20Poly1305encrypt(keya, noncea, context_content_compressed)
    ct_and_tagb58 = base58.b58encode(ct_and_tag)
    ct_and_tagb58_ripemdmodb58 = base58.b58encode(ripemd160_modified(ct_and_tagb58))
    tag_ripemdmodb58 = base58.b58encode(ripemd160_modified(tag))
    hashobjectkeyb = hashlib.sha256(ct_and_tagb58_ripemdmodb58)
    keyb = hashobjectkeyb.digest()
    hashobjectnonceb = hashlib.sha256(tag_ripemdmodb58)
    nonceb = hashobjectnonceb.digest()
    nonceb = nonceb[0:0xc]
    key_seedcompressed = ChaCha20Poly1305decrypt(keyb, nonceb, enc_content, output_tag)
    key_seed = snappy.uncompress(key_seedcompressed)
    keyc, noncec = generatekey_nonce(key_seed)
    enc_content2 = key_seed[:-16]
    tag2 = key_seed[-16:]
    k7z_sig = b'\x37\x7A\xBC\xAF\x27\x1C\x00\x04'
    k7z_data = k7z_sig + context_content[8:]
    key_seedripedmdmod_b58 = base58.b58encode(ripemd160_modified(key_seed))
    key_seedripedmdmod_b58_keyseed=key_seedripedmdmod_b58+key_seed
    archive_path_ip = base58.b58encode(ripemd160_modified(key_seedripedmdmod_b58_keyseed))
    keyd_nonced = extract_7z_memory(k7z_data, key_seed, archive_path_ip)
    keyd = keyd_nonced[:0x20]
    nonced =  keyd_nonced[0x20:]
    enc_tag = base58.b58decode(key_seed)
    encd = enc_tag[:0x20]
    tagd = enc_tag[0x20:]
    ip = ChaCha20Poly1305decrypt(keyd, nonced, encd, tagd)
    ip = snappy.uncompress(ip)
    print(ip)
    iphashobject =hashlib.sha1(ip)
    iphash = iphashobject.digest().hex().encode("utf-8")
    ipmod = base58.b58encode(ripemd160_modified(ip))
    ipmod_keyseed = ipmod+key_seed
    archive_path_port = base58.b58encode(ripemd160_modified(ipmod_keyseed))
    port_string = extract_7z_memory(k7z_data, key_seed, archive_path_port)
    print(port_string)

def main():
    file_path = sys.argv[1]
    decrypt_config(file_path)
    

if __name__ == "__main__":
    main()






