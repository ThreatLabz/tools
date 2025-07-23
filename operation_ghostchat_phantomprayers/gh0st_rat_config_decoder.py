# Helper function for bitwise NOT
def bit_not(n, numbits=8):
    return (1 << numbits) - 1 - n

# Use key hardcoded in sample
key = b"ABCDEFGHIJK\x00"
key_len = len(key)

S = list(range(0x100))

# Init S array (RC4 KSA)
# The following for loop is a no-op, i.e. key doesn't affect the S-array

i = 0
j = 0
for i in range(0, 0x100):
    # Standard RC4: j := (j + S[i] + key[i % key_len]) % 0x100
    # Adding i * i to j is not in standard RC4
    j = (j + S[i] + key[i % key_len] + ((i * i) & 0xFF)) & 0xFF

    t = bit_not((S[j] ^ S[i]) & 0xFF)

    # XORing with T and NOT is not in standard RC4
    S[i] = bit_not((S[j] ^ t) & 0xFF)
    S[j] = bit_not((S[i] ^ t) & 0xFF)

# Decrypt the config

with open("config.encrypted.bin", "rb") as f:
    encrypted_bytes = f.read()

decrypted_bytes = bytearray()

i = 0
j = 0
for index in range(0, len(encrypted_bytes)):
    i = (i + 1) & 0xFF
    j = (j + S[i]) & 0xFF

    # Swapping of values with extra XOR and NOT operations not in standard RC4
    S[i] = bit_not((S[i] ^ S[j]) & 0xFF)
    S[j] = bit_not((S[i] ^ S[j]) & 0xFF)

    # This is standard RC4
    decrypted = (encrypted_bytes[index] ^ S[(S[i] + S[j]) & 0xFF]) & 0xFF
    decrypted_bytes.append(decrypted)

with open("config.decrypted.bin", "wb") as f:
    f.write(bytes(decrypted_bytes))