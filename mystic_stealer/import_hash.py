import sys

def hash_import_name(function_name, constant_val):
    i = 0
    for val in function_name:
        i = ord(val) ^ ((constant_val * i) & 0xffffffff)
    return i


print(hex(hash_import_name(sys.argv[1], sys.argv[2])))
