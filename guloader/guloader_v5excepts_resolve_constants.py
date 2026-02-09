from ida_defines import *

def resolve_obfuscated_constants_target_ea(ea, b_c0000005_jmp=False):
    IDAAPI_MakeCode(ea)
    if IDAAPI_GetDisasm(ea).startswith('mov ') and IDAAPI_GetOpType(ea, 0) == 1:
        # every time this value is found, we assume it could be a mov opcode
        # we need to confirm we have found a constant deobfuscator block
        # we need to find xor, sub or add instructions close to the candidate
        # mov instruction (we should find at least three of these instructions 
        # using the same register as the candidate mov instruction in the next 
        # 12 instructions after the candidate mov)
        nextea = ea
        hot_counter = 0
        chained_ops = ''
        mov_reg = IDAAPI_GetOperandValue(ea, 0)
        final_value = IDAAPI_GetOperandValue(ea, 1)
        for i in range(0, 12):
            nextea = nextea + IDAAPI_ItemSize(nextea)
            IDAAPI_MakeCode(nextea)
            dism = IDAAPI_GetDisasm(nextea)
            if (dism.startswith('xor ') or dism.startswith('sub ') or \
                dism.startswith('add ') or dism.startswith('mov ')) and \
               IDAAPI_GetOpType(nextea, 0) == 1 and \
               IDAAPI_GetOperandValue(nextea, 0) == mov_reg:
                hot_counter += 1
                modifier = IDAAPI_GetOperandValue(nextea, 1)
                if dism.startswith('xor '):
                    final_value ^= modifier
                    chained_ops += f'xor {hex(modifier)} '
                if dism.startswith('sub '):
                    final_value = (final_value - modifier)&0xffffffff
                    chained_ops += f'sub {hex(modifier)} '
                if dism.startswith('add '):
                    final_value = (final_value + modifier)&0xffffffff
                    chained_ops += f'add {hex(modifier)} '
                if dism.startswith('mov '):
                    # if we have found a new mov to the same register, a new constant
                    # is being build on the register, we have to break
                    break
            # if we know that the constant is used to perform a exception c0000005 jump
            # (a constant under 0x10000 is calculated), after the calculation of the constant
            # we must see a instruction mov [calculation_reg], reg. If the user specifies
            # with the argument b_c0000005_jmp that we are dealing with this type of 
            # constant, then we have to break here
            if b_c0000005_jmp:
                if dism.startswith('mov ') and \
                    IDAAPI_GetOpType(nextea, 0) == 3 and \
                    IDAAPI_GetOpType(nextea, 1) == 1 and \
                    IDAAPI_GetOperandValue(nextea, 0) == mov_reg:
                    break
        if hot_counter >= 2:
            # found!
            print('found obfuscated constant!', hex(ea), hex(final_value))
            IDAAPI_MakeComm(ea, f'obfuscated constant {hex(final_value)} {chained_ops}')

def resolve_obfuscated_constants():
    # example 1:
    # seg000:0061F32F BB B9 A0 77 E1                                mov     ebx, 0E177A0B9h
    # seg000:0061F334 84 D2                                         test    dl, dl
    # seg000:0061F336 81 F3 84 CB 58 B6                             xor     ebx, 0B658CB84h
    # seg000:0061F33C 66 85 CB                                      test    bx, cx
    # seg000:0061F33F 81 F3 49 96 2E 0C                             xor     ebx, 0C2E9649h
    # seg000:0061F345 85 CB                                         test    ebx, ecx
    # seg000:0061F347 81 EB 73 FD 01 5B                             sub     ebx, 5B01FD73h
    # seg000:0061F34D 3D B1 FA 0E 5C                                cmp     eax, 5C0EFAB1h
    # seg000:0061F352 53                                            push    ebx
    # example 2:
    # .data:00441DFB B9 32 96 D5 61                                mov     ecx, 61D59632h
    # .data:00441E00 66 85 DB                                      test    bx, bx
    # .data:00441E03 38 FD                                         cmp     ch, bh
    # .data:00441E05 81 F1 C4 46 80 02                             xor     ecx, 28046C4h
    # .data:00441E0B 81 F1 09 84 62 5D                             xor     ecx, 5D628409h
    # .data:00441E11 84 D2                                         test    dl, dl
    # .data:00441E13 81 E9 D6 54 37 3E                             sub     ecx, 3E3754D6h
    # .data:00441E19 38 D3                                         cmp     bl, dl
    # .data:00441E1B 8A 52 01                                      mov     dl, [edx+1]
    # .data:00441E1E 38 C1                                         cmp     cl, al
    # .data:00441E20 30 CA                                         xor     dl, cl
    # .data:00441E22 38 D8                                         cmp     al, bl

    # search B8 -> BF opcodes: mov eax, value -> mov edi, value
    for ea in IDAAPI_Segments():
        for ea in range(IDAAPI_SegStart(ea), IDAAPI_SegEnd(ea)):
            b = IDAAPI_GetManyBytes(ea, 1)
            if b and (0xb8 <= b[0] <= 0xbf):
                resolve_obfuscated_constants_target_ea(ea)