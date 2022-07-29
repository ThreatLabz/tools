import os, binascii
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from Crypto.Cipher import DES3

def tounicode(s):
    out = b""
    try: s = binascii.unhexlify(s.replace(b" ", b""))
    except: pass
    for e in s:
        if e >= 0x80: out += b"\xFD\xFF"
        else: out += (e.to_bytes(1, 'little') + b"\x00")
    return out

def decrypt_blackbyte_v1(fake_png_file, enc_data):
    seed = fake_png_file[0x0:0x10]
    tdes_iv = fake_png_file[0x410:0x418]
    tdes_key = fake_png_file[0x410:0x428]
    des3_cipher = DES3.new(tdes_key, DES3.MODE_CBC, tdes_iv)
    passwd = binascii.hexlify(des3_cipher.decrypt(seed))
    passwd = tounicode(passwd)
    salt = tounicode(b"BLACKBYTE_IS_COOL")
    hmac = pbkdf2_hmac("sha1", passwd, salt, 1000, 32)
    aes_key = hmac[0:16]
    return AES.new(key=aes_key, mode=AES.MODE_CBC, iv=aes_key).decrypt(enc_data)

