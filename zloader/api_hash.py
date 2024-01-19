def calculate_checksum(func_name, xor_constant):
    checksum = 0
    for element in func_name.upper():
        checksum = 16*checksum - (0 - (ord(element)+1))
        if checksum & 0xf0000000 != 0:
            checksum = ((((checksum & 0xf0000000) >> 24) ^ checksum) & 0xfffffff)
    return checksum ^ xor_constant

