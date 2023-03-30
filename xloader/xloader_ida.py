# Author: Zscaler ThreatLabz
# Blog reference: https://www.zscaler.com/blogs/security-research/technical-analysis-xloaders-code-obfuscation-version-43
# Description: This is an IDA Python script to deobfuscate Xloader's code and data for version 4.3
# Follow us on Twitter: @ThreatLabz

import struct
from ida_defines import *
from custom_buffer_decryption_algorithm import custom_buffer_decryption_algorithm_1
from custom_rc4 import custom_rc4
from custom_sha1 import custom_sha1

#####################################################################################################
# UTIL:

seg_0 = list(IDAAPI_Segments())[0]
full_content = IDAAPI_GetManyBytes(IDAAPI_SegStart(seg_0), IDAAPI_SegEnd(seg_0)-IDAAPI_SegStart(seg_0))

def patch_decrypted_data(dec, start, makecode = False):
    print(f"Patching decrypted data {hex(start)}")
    end = start + len(dec)
    #start = IDAAPI_get_fileregion_ea(start)
    #end = IDAAPI_get_fileregion_ea(start + len(dec))
    print(f"Patching decrypted data {hex(start)} -> {hex(end)}")
    for i in range(0, len(dec)):
        IDAAPI_patch_byte(start + i, dec[i])
    if makecode:
        p = start
        while p < end:
            IDAAPI_MakeCode(p)
            sz = IDAAPI_ItemSize(p)
            if not sz: sz = 1
            p += sz
        IDAAPI_MakeFunction(start, end)

def xor(data: bytes, key: bytes) -> bytes:
    r = []
    for i, b in enumerate(data):
        r.append(b ^ key[i % len(key)])
    return bytes(r)

#####################################################################################################
# PUSHEBP DATA BLOCKS:

def get_pushebp_block_size(get_func):
    size_found = None
    for ref in IDAAPI_XrefsTo(get_func, 0):
        prev = ref.frm
        for i in range(0, 20):
            prev = IDAAPI_PrevHead(prev)
            ins = IDAAPI_GetMnem(prev)
            if ins == "push":
                v0 = IDAAPI_GetOperandValue(prev, 0)
                if size_found is None:
                    size_found = v0
                elif size_found != v0:
                    print(f"[-] ERROR: inconsistencies trying to find the size of the pushebp block {hex(get_func)}")
                    return None
                break
    return size_found

def read_pushebp_blocks():
    blocks = dict()
    pushebp_block_tag = b"\xe8\x00\x00\x00\x00\x58\xc3\x55\x8b\xec"
    pushebp_block_tag_len = len(pushebp_block_tag)
    for segea in IDAAPI_Segments():
        for head in IDAAPI_Heads(IDAAPI_SegStart(segea), IDAAPI_SegEnd(segea)):
            if IDAAPI_GetManyBytes(head, pushebp_block_tag_len) == pushebp_block_tag:
                sz = get_pushebp_block_size(head)
                if sz:
                    content = IDAAPI_GetManyBytes(head + pushebp_block_tag_len, 0x100000)
                    decrypted = custom_buffer_decryption_algorithm_1(content, sz)
                    blocks[head + pushebp_block_tag_len] = {'content' : content,
                                                            'decrypted' : decrypted,
                                                            'size' : sz}
    return blocks

#####################################################################################################
# NOPUSHEBP ENCRYPTED FUNCTIONS:

def decrypt_function_nopushebp(func_start, func_end, call_addr, enc_addr):
    '''
        Decryptors of the PUSHEBP functions usually looks like this:
            .text:1041FAE3 68 F4 68 C8 20                                push    20C868F4h
            ...
            .text:1041FAF4 E8 1A AB FF FF                                call    OBFUS_Do_Init_Memory_3F_if_0xFAB122D4_return_0_else_xor_a1_54edd2c
            ...
            .text:1041FAFE C7 45 E0 08 58 EC 0F                          mov     [ebp+init_key], 0FEC5808h
            .text:1041FB05 C7 45 E4 F3 A4 48 7B                          mov     [ebp+var_1C], 7B48A4F3h
            .text:1041FB0C C7 45 E8 4D B6 84 27                          mov     [ebp+var_18], 2784B64Dh
            .text:1041FB13 C7 45 EC DA 58 66 DF                          mov     [ebp+var_14], 0DF6658DAh
            .text:1041FB1A C7 45 F0 16 2F 08 32                          mov     [ebp+var_10], 32082F16h
            ...
            .text:1041FB45 68 C6 8A EF 01                                push    1EF8AC6h
            .text:1041FB4A 52                                            push    edx
            .text:1041FB4B E8 03 AB FF FF                                call    OBFUS_xor_array_5_dwords

            .text:1041FB5E 68 41 CE A7 06                                push    6A7CE41h
            ...
            .text:1041FB66 E8 A8 AA FF FF                                call    OBFUS_Do_Init_Memory_3F_if_0xFAB122D4_return_0_else_xor_a1_54edd2c
            ...
            .text:1041FB7A E8 14 AA FF FF                                call    OBFUS_DecryptCriticalCodeType2_noPUSHEBPhdr_set_90909090ec8b55_return_end
            ...
            .text:1041FB89 E8 D5 67 FF FF                                call    CORE_EncryptedCodeNoPushEBP_XX
        Sometimes instead of calling OBFUS_Do_Init_Memory_3F_if_0xFAB122D4_return_0_else_xor_a1_54edd2c to xor the start and end tags of the encrypted code,
        it directly add a xor instruction
    '''
    global full_content
    seeds = list()
    key = None
    head = call_addr
    while head > func_start:
        if key and 5 == len(seeds):
            break
        head = IDAAPI_PrevHead(head)
        ins = IDAAPI_GetMnem(head)
        op0 = IDAAPI_GetOpType(head, 0)
        v0 = IDAAPI_GetOperandValue(head, 0)
        if ins == "push" and op0 == 5 and v0 > 0xfffff:
            seeds.insert(0, v0)
        elif ins == "mov" and op0 == 4:
            prev = IDAAPI_PrevHead(head)
            prev_prev = IDAAPI_PrevHead(prev)
            prev_prev_prev = IDAAPI_PrevHead(prev_prev)
            prev_prev_prev_prev = IDAAPI_PrevHead(prev_prev_prev)
            if IDAAPI_GetMnem(prev) == "mov" and IDAAPI_GetMnem(prev_prev) == "mov" and \
                IDAAPI_GetMnem(prev_prev_prev) == "mov" and IDAAPI_GetMnem(prev_prev_prev_prev) == "mov" and \
                IDAAPI_GetOpType(prev, 0) == 4 and IDAAPI_GetOpType(prev_prev, 0) == 4 and \
                IDAAPI_GetOpType(prev_prev_prev, 0) == 4 and IDAAPI_GetOpType(prev_prev_prev_prev, 0) == 4:
                v0 = IDAAPI_GetOperandValue(prev_prev_prev_prev, 1)
                v1 = IDAAPI_GetOperandValue(prev_prev_prev, 1)
                v2 = IDAAPI_GetOperandValue(prev_prev, 1)
                v3 = IDAAPI_GetOperandValue(prev, 1)
                v4 = IDAAPI_GetOperandValue(head, 1)
                if v0 > 0xfffff and v1 > 0xfffff and v2 > 0xfffff and \
                   v3 > 0xfffff and v4 > 0xfffff:
                    key = struct.pack("L", v0) + struct.pack("L", v1) + \
                      struct.pack("L", v2) + struct.pack("L", v3) + struct.pack("L", v4)
        elif ins == "call" and op0 == 7:
            s = IDAAPI_GetManyBytes(v0, 40)
            if s and b"\x3f\x00\x00\x00" in s:
                for i in range(0, 200):
                    v0 = IDAAPI_NextHead(v0)
                    if IDAAPI_GetOpType(v0, 1) == 5:
                        imm = IDAAPI_GetOperandValue(v0, 1)
                        if imm > 0xfffff:
                            seeds.insert(0, imm)
                            break
    if 5 == len(seeds) and key:
        print("call nopushebp func found:", hex(call_addr))
        print(list(map(hex, seeds)))
        if key: print(key.hex())
        print("-")
        tags = list()
        for k in [0, 1]:
            for j in range(0, len(seeds)):
                for i in range(1, len(seeds)):
                    if seeds[i] ^ seeds[j] and struct.pack("L", seeds[i] ^ seeds[j]) in full_content:
                        tags.append(seeds[i] ^ seeds[j])
                        seeds.pop(i)
                        seeds.pop(j)
                        break
        if len(tags) == 2:
            key = xor(key, struct.pack("L", seeds[0]))
            print(list(map(hex, tags)))
            print(seeds[0])
            print(key.hex())
            if full_content.index(struct.pack("L", tags[0])) >  full_content.index(struct.pack("L", tags[1])):
                tag1 = struct.pack("L", tags[1])
                tag2 = struct.pack("L", tags[0])
            else:
                tag1 = struct.pack("L", tags[0])
                tag2 = struct.pack("L", tags[1])
            print(tag1.hex(), tag2.hex(), key.hex())
            print("--------")
            return {
                "tag1" : tag1,
                "tag2" : tag2,
                "key": key}

def get_encrypted_functions_nopushebp():
    dec_func_info_list = list()
    for ea in IDAAPI_Segments():
        for funcea in IDAAPI_Functions(IDAAPI_SegStart(ea), IDAAPI_SegEnd(ea)):
            func = IDAAPI_get_func(funcea)
            try: func_start_ea = func.startEA
            except: func_start_ea = func.start_ea
            try: func_end_ea = func.endEA
            except: func_end_ea = func.end_ea
            for head in IDAAPI_Heads(func_start_ea, func_end_ea):
                ins = IDAAPI_GetMnem(head)
                op0 = IDAAPI_GetOpType(head, 0)
                if ins == "call" and op0 == 7:
                    v0 = IDAAPI_GetOperandValue(head, 0)
                    s = IDAAPI_GetManyBytes(v0, 3)
                    if s != b"\x55\x8b\xec" and s != b"\x58\x50\xc3" and s != b"\xe8\x00\x00":
                        dec_func_info = decrypt_function_nopushebp(func_start_ea, func_end_ea, head, v0)
                        if dec_func_info:
                            dec_func_info_list.append(dec_func_info)
    return dec_func_info_list

def guess_key_encrypted_functions_nopushebp(pushebp_blks, key2, enc):
    more_zeros_key = None
    more_zeros_n = 0
    for blk in pushebp_blks:
        pushebp_blk_sha_key = custom_sha1(blk)
        dec = custom_rc4(enc, pushebp_blk_sha_key)
        dec = custom_rc4(dec, key2)
        zeros = dec.count(b"\x00")
        if zeros > more_zeros_n:
            more_zeros_n = zeros
            more_zeros_key = pushebp_blk_sha_key
    return more_zeros_key

def decrypt_encrypted_functions_nopushebp(pushebp_blks):
    dec_func_info_list = get_encrypted_functions_nopushebp()
    for dec_func in dec_func_info_list:
        print(dec_func)
        for seg in IDAAPI_Segments():
            seg_content = IDAAPI_GetManyBytes(IDAAPI_SegStart(seg), IDAAPI_SegEnd(seg)-IDAAPI_SegStart(seg))
            if dec_func["tag1"] in seg_content and dec_func["tag2"] in seg_content:
                enc = seg_content.split(dec_func["tag1"])[1].split(dec_func["tag2"])[0]
                pushebp_blk_sha_key = guess_key_encrypted_functions_nopushebp(pushebp_blks, dec_func["key"], enc)
                dec = custom_rc4(enc, pushebp_blk_sha_key)
                dec = b"\x55\x8B\xEC" + custom_rc4(dec, dec_func["key"]) + b"\x90\x90\x90\x90"
                tag_start_i = seg_content.index(dec_func["tag1"])
                patch_i = IDAAPI_SegStart(seg) + tag_start_i + 4 - 3
                patch_decrypted_data(dec, patch_i, makecode = True)

#####################################################################################################
# PUSHEBP ENCRYPTED FUNCTIONS:

def analyze_initkey_subfunc_encrypted_functions_pushebp(funcaddr):
    key = None
    xor_key = None
    func = IDAAPI_get_func(funcaddr)
    if not func: return
    try: func_start_ea = func.startEA
    except: func_start_ea = func.start_ea
    try: func_end_ea = func.endEA
    except: func_end_ea = func.end_ea
    for head in IDAAPI_Heads(func_start_ea, func_end_ea):
        if IDAAPI_GetMnem(head) == "mov" and IDAAPI_GetOpType(head, 0) == 4:
            next = IDAAPI_NextHead(head)
            next_next = IDAAPI_NextHead(next)
            next_next_next = IDAAPI_NextHead(next_next)
            next_next_next_next = IDAAPI_NextHead(next_next_next)
            if IDAAPI_GetMnem(next) == "mov" and IDAAPI_GetMnem(next_next) == "mov" and \
                IDAAPI_GetMnem(next_next_next) == "mov" and IDAAPI_GetMnem(next_next_next_next) == "mov" and \
                IDAAPI_GetOpType(next, 0) == 4 and IDAAPI_GetOpType(next_next, 0) == 4 and \
                IDAAPI_GetOpType(next_next_next, 0) == 4 and IDAAPI_GetOpType(next_next_next_next, 0) == 4:
                v4 = IDAAPI_GetOperandValue(next_next_next_next, 1)
                v3 = IDAAPI_GetOperandValue(next_next_next, 1)
                v2 = IDAAPI_GetOperandValue(next_next, 1)
                v1 = IDAAPI_GetOperandValue(next, 1)
                v0 = IDAAPI_GetOperandValue(head, 1)
                if v0 > 0xfffff and v1 > 0xfffff and v2 > 0xfffff and \
                   v3 > 0xfffff and v4 > 0xfffff:
                    key = struct.pack("L", v0) + struct.pack("L", v1) + \
                      struct.pack("L", v2) + struct.pack("L", v3) + struct.pack("L", v4)
        if IDAAPI_GetMnem(head) == "push" and IDAAPI_GetOpType(head, 0) == 5:
            v0 = IDAAPI_GetOperandValue(head, 0)
            if v0 > 0xfffff:
                xor_key = struct.pack("L", v0)
    if key and xor_key:
        return xor(key, xor_key)

def find_decryptor_and_keys_encrypted_functions_pushebp():
    for ea in IDAAPI_Segments():
        for funcea in IDAAPI_Functions(IDAAPI_SegStart(ea), IDAAPI_SegEnd(ea)):
            n_90909090 = 0
            key_xor = list()
            init_key = list()
            func = IDAAPI_get_func(funcea)
            try: func_start_ea = func.startEA
            except: func_start_ea = func.start_ea
            try: func_end_ea = func.endEA
            except: func_end_ea = func.end_ea
            for head in IDAAPI_Heads(func_start_ea, func_end_ea):
                if (IDAAPI_GetOpType(head, 0) == 5 and \
                   IDAAPI_GetOperandValue(head, 0) == 0x90909090) or \
                   (IDAAPI_GetOpType(head, 1) == 5 and \
                   IDAAPI_GetOperandValue(head, 1) == 0x90909090):
                    n_90909090 += 1
                if IDAAPI_GetMnem(head) == "xor" and \
                   IDAAPI_GetOpType(head, 1) == 5:
                    v = IDAAPI_GetOperandValue(head, 1)
                    if v > 0xfffff:
                        key_xor.append(struct.pack("L", v))
            if n_90909090 == 2 and len(key_xor) == 1:
                for head in IDAAPI_Heads(func_start_ea, func_end_ea):
                    if IDAAPI_GetMnem(head) == "call" and \
                       IDAAPI_GetOpType(head, 0) == 7:
                        k = analyze_initkey_subfunc_encrypted_functions_pushebp(IDAAPI_GetOperandValue(head, 0))
                        if k:
                            init_key.append(k)
                if len(init_key) == 1:
                    return func_start_ea, key_xor[0], init_key[0]

def decrypt_encrypted_functions_pushebp():
    decryptor_90909090, key_xor_90909090, init_key_90909090 = find_decryptor_and_keys_encrypted_functions_pushebp()
    print(f"90909090 decryptor found: {hex(decryptor_90909090)} {key_xor_90909090.hex()} {init_key_90909090.hex()}")
    for ref in IDAAPI_XrefsTo(decryptor_90909090, 0):
        # .text:104130F3 68 E2 57 54 19                                push    195457E2h
        # .text:104130F8 56                                            push    esi
        # .text:104130F9 C7 45 F0 4D 48 5B 4F                          mov     [ebp+var_10], 4F5B484Dh
        # .text:10413100 C7 45 F4 04 33 00 00                          mov     [ebp+var_C], 3304h
        # .text:10413107 C7 45 F8 38 42 52 61                          mov     [ebp+var_8], 61524238h
        # .text:1041310E C7 45 FC 0C 32 00 00                          mov     [ebp+var_4], 320Ch
        # .text:10413115 E8 89 FE FF FF                                call    DecryptCriticalCodeType1_Set_909090909090
        call_addr = ref.frm
        print(f"call to 90909090 decryptor found: {hex(call_addr)}")
        movs = IDAAPI_GetManyBytes(call_addr - 28, 28)
        if movs[0] == 0xc7 and movs[7] == 0xc7 and \
           movs [14] == 0xc7 and movs[21] == 0xc7:
            encfunc_tag1 = movs[3:7] + movs[10:12]
            encfunc_tag2 = movs[17:21] + movs[24:26]
            encfunc_id = None
            prev = call_addr
            while True:
                prev = IDAAPI_PrevHead(prev)
                if IDAAPI_GetMnem(prev) == "push" and IDAAPI_GetOpType(prev, 0) == 5:
                    v0 = IDAAPI_GetOperandValue(prev, 0)
                    if v0 > 0xfffff:
                        encfunc_id = struct.pack("L", v0)
                        break
            print(f"tags: {encfunc_tag1.hex()} {encfunc_tag2.hex()} id: {encfunc_id.hex()}")
            cur_init_key_90909090 = xor(init_key_90909090, key_xor_90909090)
            cur_init_key_90909090 = xor(cur_init_key_90909090, encfunc_id)
            cur_encfunc_tag1 = custom_rc4(encfunc_tag1, cur_init_key_90909090)
            cur_encfunc_tag2 = custom_rc4(encfunc_tag2, cur_init_key_90909090)
            for seg in IDAAPI_Segments():
                seg_content = IDAAPI_GetManyBytes(IDAAPI_SegStart(seg), IDAAPI_SegEnd(seg)-IDAAPI_SegStart(seg))
                if cur_encfunc_tag1 in seg_content and cur_encfunc_tag2 in seg_content:
                    tag_start_i = seg_content.index(cur_encfunc_tag1)
                    patch_i = IDAAPI_SegStart(seg) + tag_start_i
                    print(f"tags found, decrypting functions: {hex(patch_i)}")
                    enc = seg_content.split(cur_encfunc_tag1)[1].split(cur_encfunc_tag2)[0]
                    dec = b"\x90\x90\x90\x90\x90\x90" + custom_rc4(enc, cur_init_key_90909090) + b"\x90\x90\x90\x90\x90\x90"
                    
                    patch_decrypted_data(dec, patch_i, makecode = True)
        print("--------")

#####################################################################################################
# MAIN:

def dowork():
    blks = list()
    for addr, blk in read_pushebp_blocks().items():
        print(hex(addr))
        print(hex(blk['size']))
        print(hex(len(blk['decrypted'])))
        blks.append(blk['decrypted'])
    decrypt_encrypted_functions_pushebp()
    decrypt_encrypted_functions_nopushebp(blks)
dowork()
#####################################################################################################
