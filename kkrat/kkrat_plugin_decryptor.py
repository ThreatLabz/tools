def decrypt_plugin(data: bytearray) -> bytearray:
    key =bytearray(b'\x20\x31\xA7\x1C\x39\x95\x63\xAd\xAF\x15\x72\xE1\x0a\xBb\x39\x53\x87\xEb\x13\x22\x08\xA0\x01\xC5\xE1\x40\x49\x6D\x7a\x3E\x0b\x26')
    for i in range(len(data)):
        mod = i % 3
        pos = i % 0x20
        if mod == 0:
            data[i] = (data[i] - (key[pos] >> 2)) & 0xFF
        elif mod == 1:
            data[i] = (data[i] - (key[pos] << 1)) & 0xFF
        elif mod == 2:
            data[i] = (data[i] ^ ((key[pos] << 2) + i + (key[pos] % i))) & 0xFF
        elif mod == 3:
            data[i] = (data[i] + (key[pos] << 1)) & 0xFF

    return data
