import yara
from ida_defines import *

def patterns_C0000005():
    return [
        # 0xC0000005
        # seg000:00616D75 B8 BD 53 05 3B                    mov     eax, 3B0553BDh
        # seg000:00616D7A 35 F3 BB E0 6E                    xor     eax, 6EE0BBF3h
        # seg000:00616D7F 35 BA 57 44 D1                    xor     eax, 0D14457BAh
        # seg000:00616D84 35 7B 71 D7 97                    xor     eax, 97D7717Bh
        # seg000:00616D89 35 EB CF 76 13                    xor     eax, 1376CFEBh
        # seg000:00616D8E 89 38                             mov     [eax], edi
        { 'pattern':'B8 [4] (35|2D|05) [4] (35|2D|05) [4] (35|2D|05) [4] (35|2D|05) [4] 89', 'disp_exception':25, 'patching_offset':25, 'type':'type_MOV_C0000005', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},

        # 0xC0000005
        # seg000:00616B82 B8 73 FF 7C 1F                    mov     eax, 1F7CFF73h
        # seg000:00616B87 35 3F 8D 33 AB                    xor     eax, 0AB338D3Fh
        # seg000:00616B8C 35 68 33 E5 9F                    xor     eax, 9FE53368h
        # seg000:00616B91 05 3C 09 56 D4                    add     eax, 0D456093Ch
        # seg000:00616B96 89 30                             mov     [eax], esi <- exception EIP
        { 'pattern':'B8 [4] (35|2D|05) [4] (35|2D|05) [4] (35|2D|05) [4] 89', 'disp_exception':20, 'patching_offset':20, 'type':'type_MOV_C0000005', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},

        # 0xC0000005
        # seg000:0061B6E5 B8 25 72 79 13                    mov     eax, 13797225h  ; obfuscated constant 0xc1fa xor 0x690093fc sub 0x7a791fdf
        # seg000:0061B6EA 35 FC 93 00 69                    xor     eax, 690093FCh
        # seg000:0061B6EF 2D DF 1F 79 7A                    sub     eax, 7A791FDFh
        # seg000:0061B6F4 89 10                             mov     [eax], edx
        { 'pattern':'B8 [4] (35|2D|05) [4] (35|2D|05) [4] 89', 'disp_exception':15, 'patching_offset':15, 'type':'type_MOV_C0000005', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},

        # 0xC0000005
        # careful! this pattern must be first than next one, else next one will detect this code too and will apply incorrect disp_exception
        # seg000:00616B09 BB CA 1D DC BA                                mov     ebx, 0BADC1DCAh
        # seg000:00616B0E 81 F3 3F 06 69 2C                             xor     ebx, 2C69063Fh
        # seg000:00616B14 81 EB 4F 83 5F B9                             sub     ebx, 0B95F834Fh
        # seg000:00616B1A 81 F3 9C 41 66 B4                             xor     ebx, 0B466419Ch
        # seg000:00616B20 81 F3 44 A9 33 69                             xor     ebx, 6933A944h
        # seg000:00616B26 89 33                                         mov     [ebx], esi <- exception EIP
        { 'pattern':'?? [4] 81 [5] 81 [5] 81 [5] 81 [5] 89', 'disp_exception':29, 'patching_offset':29, 'type':'type_MOV_C0000005', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},

        # 0xC0000005
        # careful! this pattern must be first than next one, else next one will detect this code too and will apply incorrect disp_exception
        # seg000:00613C32 BA 07 FF 8D 19                                mov     edx, 198DFF07h
        # seg000:00613C37 81 F2 14 16 59 B4                             xor     edx, 0B4591614h
        # seg000:00613C3D 81 F2 5C 11 3C 77                             xor     edx, 773C115Ch
        # seg000:00613C43 81 F2 A8 EE E8 DA                             xor     edx, 0DAE8EEA8h
        # seg000:00613C49 89 02                                         mov     [edx], eax <- exception EIP
        { 'pattern':'?? [4] 81 [5] 81 [5] 81 [5] 89', 'disp_exception':23, 'patching_offset':23, 'type':'type_MOV_C0000005', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},

        # 0xC0000005
        # careful! this pattern is too short, maybe we should add additional post_jump_checks
        # seg000:00616C8F BF 48 51 87 2D                    mov     edi, 2D875148h
        # seg000:00616C94 81 F7 C7 01 C7 B7                 xor     edi, 0B7C701C7h
        # seg000:00616C9A 81 F7 78 5C 40 9A                 xor     edi, 9A405C78h
        # seg000:00616CA0 89 3F                             mov     [edi], edi
        { 'pattern':'?? [4] 81 [5] 81 [5] 89', 'disp_exception':17, 'patching_offset':17, 'type':'type_MOV_C0000005', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},
    ]

def patterns_80000004():
    return [
        # 0x80000004
        #.data:004035D3 9C                                            pushf
        #.data:004035D4 89 E7                                         mov     edi, esp
        #.data:004035D6 01 1F                                         add     [edi], ebx
        #.data:004035D8 9D                                            popf                    ; trick (type_PUSHF) target: 4035e6 (off: b)
        #.data:004035D9 84 C0                                         test    al, al
        #.data:004035DB 75 08                                         jnz     short near ptr unk_4035E5 <- exception EIP

        # 0x80000004
        # seg000:0060F4F5 9C                                            pushf
       # seg000:0060F4F6 89 E2                                         mov     edx, esp
        # seg000:0060F4F8 09 0A                                         or      [edx], ecx
        # seg000:0060F4FA 9D                                            popf
        # seg000:0060F4FB 66 85 D8                                      test    ax, bx -> sometimes instructions with 66 after popf
        # seg000:0060F4FE 78 0C                                         js      short loc_60F50C <- exception EIP
        { 'pattern':'9C 89 [3] 9D', 'disp_exception':6, 'patching_offset':0, 'type':'type_POPF_80000004', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},
    ]

def patterns_C0000096():
    return [
        # 0xC0000096
        # seg000:0062F2CA 5A                                pop     edx
        # seg000:0062F2CB 81 C7 18 E6 1A 24                 add     edi, 241AE618h
        # seg000:0062F2D1 66 0F C7 37                       vmclear qword ptr [edi]
        # seg000:0062F2D5 00                                db    0
        # seg000:0062F2D6 00                                db    0
        { 'pattern':'66 0F [2-8] 00 00 00 00 00 00', 'disp_exception':0, 'patching_offset':0, 'type':'type_C0000096_0F', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},

        # seg000:0061A507  F3 0F C7 36                        vmxon   qword ptr [esi]
        # seg000:0061A507                     sub_61A391      endp
        # seg000:0061A50B  00                                 db    0
        # seg000:0061A50C  00                                 db    0
        # seg000:0061A50D  00                                 db    0
        { 'pattern':'(F0|F1|F2|F3|F4|F5|F6|F7) 0F [2-8] 00 00 00 00 00 00', 'disp_exception':0, 'patching_offset':0, 'type':'type_C0000096_0F', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},

        # 0xC0000096
        # seg000:0062D05B 0F 01 1A                          lidt    fword ptr [edx]
        # seg000:0062D05E 3B 00                             cmp     eax, [eax]
        # seg000:0062D060 00                                db    0
        # seg000:0062D061 00                                db    0
        # seg000:0062D062 00                                db    0
        # seg000:0062D063 00                                db    0
        { 'pattern':'0F [2-8] 00 00 00 00 00 00', 'disp_exception':0, 'patching_offset':0, 'type':'type_C0000096_0F', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},

        # seg000:0061A87D  F4                                 hlt
        # seg000:0061A87E  72 A7                              jb      short loc_61A827
        # seg000:0061A880  14 00                              adc     al, 0
        # seg000:0061A882  00                                 db    0
        # seg000:0061A883  00                                 db    0
        # seg000:0061A884  00                                 db    0
        { 'pattern':'F4 [2-8] 00 00 00 00 00 00', 'disp_exception':0, 'patching_offset':0, 'type':'type_C0000096_0F', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},
    ]

def patterns_80000003():
    return [
        # seg000:0060830E B8 E2 FA 5C 1F                                mov     eax, 1F5CFAE2h
        # seg000:00608313 35 68 CB DD 5A                                xor     eax, 5ADDCB68h
        # seg000:00608318 35 6A AD E6 7E                                xor     eax, 7EE6AD6Ah
        # seg000:0060831D CC                                            int     3
        { 'pattern':'CC', 'disp_exception':0, 'patching_offset':0, 'type':'type_CC_80000003', 'patch':True, 'post_jump_checks': {'n_disasm_ins' : 7, 'limit_jump_size_min' : 0x10, 'limit_jump_size_max' : 0x40}},
    ]

def patterns_80000003_only_comment():
    return [
        # seg000:0060830E B8 E2 FA 5C 1F                                mov     eax, 1F5CFAE2h
        # seg000:00608313 35 68 CB DD 5A                                xor     eax, 5ADDCB68h
        # seg000:00608318 35 6A AD E6 7E                                xor     eax, 7EE6AD6Ah
        # seg000:0060831D CC                                            int     3
        { 'pattern':'CC', 'disp_exception':0, 'patching_offset':0, 'type':'type_CC_80000003', 'patch':False, 'post_jump_checks': {'n_disasm_ins' : 7, 'limit_jump_size_min' : 0x10, 'limit_jump_size_max' : 0x40}},
    ]

def prechecks_C0000005(ea_match, pattern, data):
    # TODO: optional check invalid mem code address < 0x10000
    return pattern

def prechecks_80000004(ea_match, pattern, data):
    pattern_checks = pattern.copy()
    # flag step is set by popf instruction and 0x80000004 except happends after executing the
    # next instruction, so we need to move a instruction after the match + disp
    #print('pattern_checks 80000004', hex(ea_match), IDAAPI_ItemSize(ea_match + pattern_checks['disp_exception']))
    for i in range(0, 0x10):
        IDAAPI_DelItems(ea_match + pattern_checks['disp_exception'] + i)
    IDAAPI_MakeCode(ea_match + pattern_checks['disp_exception'])
    pattern_checks['disp_exception'] += IDAAPI_ItemSize(ea_match + pattern_checks['disp_exception'])
    #print('pattern_checks 80000004', hex(ea_match), hex(ea_match + pattern_checks['disp_exception'] + enc_jmp_disp_exception), hex(b[e[0] + pattern_checks['disp_exception'] + enc_jmp_disp_exception]))
    # pattern_checks 80000004 0x62df03 1
    # pattern_checks 80000004 0x62df03 6479661 0x5e
    return pattern_checks

def prechecks_C0000096(ea_match, pattern, data):
    return pattern

def prechecks_80000003(ea_match, pattern, data):
    # TODO: additional checks for int 3
    if not IDAAPI_GetDisasm(ea_match).startswith('int     3'):
        return None
    else:
        return pattern

def findall_pattern(data, pattern):
    rule = yara.compile(source=f'rule pattern {{ strings: $pattern = {{{pattern}}} condition: $pattern }}')
    if matches := rule.match(data=data):
        for match in matches:
            for string in match.strings:
                yield string[0]