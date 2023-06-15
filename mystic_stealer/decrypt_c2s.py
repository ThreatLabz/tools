def decrypt(block, key):
    sum = 0xC6EF3720
    delta = 0x61C88647
    
    key0, key1, key2, key3 = struct.unpack("<4L", key)

    block_size = 8  
    num_blocks = len(block) // block_size
    blocks = struct.unpack("<2L" * num_blocks, block)

    v0 = blocks[0]
    v1 = blocks[1]
    
    for i in range(32):
        v1 = v1 - ((v0 + sum) ^ (key2 + (v0 << 4)) ^ (key3 + (v0 >> 5)))
        v1 = uint32(v1)
        # print("v1:", hex(v1))
        v7 = uint32(v1 + sum)
        sum = uint32(sum + delta)
        v8 = v7 ^ uint32(key0 + (v1 << 4)) ^ uint32(key1 + (v1 >> 5));
        v0 =  uint32(v0 - v8);
        
    
    return struct.pack("<2L", v0, v1)

