import sys
import struct
import binascii
from dataclasses import dataclass
from typing import List, Optional
from Crypto.Cipher import ChaCha20  

K0 = 0xCEDD9AB7
K1 = 0x7FCBB9E9
HEADER_LEN = 0x3C

def is_header_valid(header_bytes: bytes, k0: int = K0, k1: int = K1) -> bool:
    if len(header_bytes) != HEADER_LEN:
        return False

    data = struct.unpack("<15I", header_bytes)
    MAGIC1, MAGIC2, MAGIC3, crc_value_stored = data[0], data[1], data[2], data[14]

    condition_1 = ((MAGIC2 ^ k0) & 0xFFFFFFFF) == ((~MAGIC1) & 0xFFFFFFFF)
    if not condition_1:
        return False

    condition_2 = ((k1 ^ MAGIC3) & 0xFFFFFFFF) == MAGIC2
    if not condition_2:
        return False

    crc_value = binascii.crc32(header_bytes[:0x38])
    return crc_value_stored == crc_value

@dataclass
class Match:
    offset: int
    key: bytes   
    nonce: bytes 
    header: bytes

def find_matches(data: bytes) -> List[Match]:
    matches: List[Match] = []
    n = len(data)
    for off in range(0, n - HEADER_LEN + 1):
        chunk = data[off:off + HEADER_LEN]
        if is_header_valid(chunk):
            key = chunk[0x0C:0x0C + 0x20]
            nonce = chunk[0x2C:0x2C + 0x0C]
            matches.append(Match(offset=off, key=key, nonce=nonce, header=chunk))
    return matches

def chacha20_decrypt(ciphertext: bytes, key32: bytes, nonce12: bytes) -> bytes:
    cipher = ChaCha20.new(key=key32, nonce=nonce12)
    cipher.seek(64)
    return cipher.decrypt(ciphertext)

def extract_and_decrypt(data: bytes) -> None:
    matches = find_matches(data)
    if not matches:
        print("No matching headers found.")
        return None

    matches.sort(key=lambda m: m.offset)

    print(f"Found {len(matches)} headers.")
    for counter, m in enumerate(matches):
        start = m.offset + HEADER_LEN
        end = matches[counter + 1].offset if counter + 1 < len(matches) else len(data)

        if end < start:
            print(f"Invalid Stream")
            continue

        ciphertext = data[start:end]
        if not ciphertext:
            print("Empty ciphertext")
            continue

        try:
            plaintext = chacha20_decrypt(ciphertext, m.key, m.nonce)
        except Exception as e:
            print("Decryption failed")
            continue

        print(f"Decrypted Data : {plaintext}")

def main():
    in_path = sys.argv[1]
    with open(in_path, "rb") as f:
        data = f.read()

    extract_and_decrypt(data)

if __name__ == "__main__":
    main()
