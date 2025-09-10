import zlib
def decrypt_data(data: bytearray) -> bytes:
    key =bytearray(b'\x8A\x91\x36\x10\xE9\x05\xC3\xDD\x1F\x65\x78\x11\xEA\x3B\x19\x33\x47\x1B\x23\x0F\x88\xE1\xC1\x55\x61\x60\x99\xA0\x3A\xB0\xAB\xC0')
    for i in range(len(data)):
        mod = i % 4
        pos = i % 0x20
        
        if mod == 0:
            data[i] = (data[i] ^ key[pos]) & 0xFF 
        elif mod == 1:
            data[i] = (data[i] - (key[pos] >> 1))  & 0xFF 
        elif mod == 2:
            data[i] = (data[i] + (key[pos] * 4 ))  & 0xFF 
        elif mod == 3:
            data[i] = (data[i] - (key[pos] * 4))  & 0xFF

    uncdata = zlib.decompress(data)
    return uncdata
