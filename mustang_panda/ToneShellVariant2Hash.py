def do_hash(rgbGuid: bytes) -> int:
    hash: int = 0
    for j in range(0, 0x10, 4):
        byte_j = rgbGuid[j]
        byte_j1 = rgbGuid[j + 1]
        byte_j2 = rgbGuid[j + 2]
        byte_j3 = rgbGuid[j + 3]

        term1 = 0x3C4E2E1 * byte_j1
        term2 = 0x200F1 * byte_j2
        term3 = byte_j3 + term1 + term2
        term4 = 0x521B95D1 * byte_j
        term5 = 0x779A09C1 * hash
        next_hash_unmasked = term4 + term3 + term5
        hash = next_hash_unmasked & 0xFFFFFFFF
    return hash