import sys
from Crypto.Cipher import AES

def decrypt_partyticket(filename):
    data = open(filename,"rb").read()

    key = b"6FBBD7P95OE8UT5QRTTEBIWAR88S74DO"
    cipher = AES.new(key, AES.MODE_GCM, data[:12])
    tag = data[-32-256-16:-32-256]
    dec = cipher.decrypt_and_verify(data[12:-32-256-16], tag)
    return dec

