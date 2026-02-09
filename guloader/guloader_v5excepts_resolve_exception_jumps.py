from guloader_v5excepts_patterns import *
from guloader_v5excepts_util import *
from ida_defines import *

def find_parameters_exception_jumps(bin, base):
    # From sample: 7fccb9545a51bb6d40e9c78bf9bc51dc2d2a78a27b81bf1c077eaf405cbba6e9
    # seg000:00648F6E E8 7F 00 00 00                    call    ANTI_CheckDrRegs_ecx_xorkey_0x85
    # seg000:00648F73 38 C8                             cmp     al, cl
    # seg000:00648F75 BA 22 5E DB 16                    mov     edx, 16DB5E22h
    # seg000:00648F7A 66 81 FE 70 A2                    cmp     si, 0A270h
    # seg000:00648F7F 81 EA 53 D6 A1 10                 sub     edx, 10A1D653h
    # seg000:00648F85 81 F2 7F 70 BB B7                 xor     edx, 0B7BB707Fh
    # seg000:00648F8B 38 E5                             cmp     ch, ah
    # seg000:00648F8D 81 F9 47 DF B1 1B                 cmp     ecx, 1BB1DF47h
    # seg000:00648F93 81 F2 08 F7 82 B1                 xor     edx, 0B182F708h
    # seg000:00648F99 85 DA                             test    edx, ebx
    # seg000:00648F9B 01 D0                             add     eax, edx
    # seg000:00648F9D 85 CB                             test    ebx, ecx
    # seg000:00648F9F 8B 10                             mov     edx, [eax]
    # seg000:00648FA1 66 39 C8                          cmp     ax, cx
    # seg000:00648FA4 83 C2 23                          add     edx, 23h ; '#'
    # seg000:00648FA7 38 C8                             cmp     al, cl
    # seg000:00648FA9 E8 6C FE FF FF                    call    pointed_by_eax_plusequal_pointed_by_edx_xor_ecx

    # ANTI_CheckDrRegs_ecx_xorkey_0x85:
    # seg000:00648FF2 8B 40 04                          mov     eax, [eax+4]
    # ...
    # seg000:0064903A 83 C2 04                          add     edx, 4
    # ...
    # seg000:00649048 83 3C 10 00                       cmp     dword ptr [eax+edx], 0
    # seg000:0064904C 75 80                             jnz     short eax_equal_zero_and_retn4
    # ...
    # seg000:0064905E B9 CB 5E 8B E3                    mov     ecx, 0E38B5ECBh ; xor key jumps = 0x85
    # seg000:00649063 81 F1 AC 2E 36 1B                 xor     ecx, 1B362EACh
    # seg000:00649069 81 F1 28 CB 02 5C                 xor     ecx, 5C02CB28h
    # seg000:0064906F F8                                clc
    # seg000:00649070 81 C1 36 45 40 5B                 add     ecx, 5B404536h
    # seg000:00649076 84 E5                             test    ch, ah
    # seg000:00649078 C3                                retn

    # pointed_by_eax_plusequal_pointed_by_edx_xor_ecx:
    # seg000:00648E1A 38 FC                             cmp     ah, bh
    # seg000:00648E1C 66 3D 55 67                       cmp     ax, 6755h
    # seg000:00648E20 66 85 C3                          test    bx, ax
    # seg000:00648E23 0F B6 12                          movzx   edx, byte ptr [edx]
    # seg000:00648E26 66 39 CA                          cmp     dx, cx
    # seg000:00648E29 81 FF 55 1F A2 58                 cmp     edi, 58A21F55h
    # seg000:00648E2F 31 CA                             xor     edx, ecx
    # seg000:00648E31 38 C2                             cmp     dl, al
    # seg000:00648E33 01 10                             add     [eax], edx
    # seg000:00648E35 84 E7                             test    bh, ah
    # seg000:00648E37 C3                                retn

    return {
        'xor_key_exception' : 0x85,     # Values from sample 7fccb9545a51bb6d40e9c78bf9bc51dc2d2a78a27b81bf1c077eaf405cbba6e9
        'enc_jmp_disp_exception' : 0x23 # These values should be extracted from the exception handler of the analyzed sample
    }                                   # and set in the script

def jmp_patch(trick, ea_match, ea_patch, ea_jump, b_patch, b_make_comments, jmp_disp):
    for del_ea in range(ea_patch, ea_jump):
        if b_patch:
            IDAAPI_patch_byte(del_ea, 0x90)
        else:
            pass #IDAAPI_DelItems(del_ea, 1)
    if b_patch:
        # patch the first bytes with jmp +2, before 90 90 90.. to find easily the block
        IDAAPI_patch_byte(ea_patch, 0xeb)
        IDAAPI_patch_byte(ea_patch + 1, 0x00)
    if b_patch:
        IDAAPI_MakeCode(ea_patch)
        IDAAPI_MakeCode(ea_jump) # make code where the trick is jumping too
    if b_make_comments:
        IDAAPI_MakeComm(ea_match, "trick (%s) target: %x (off: %x)" % (trick, ea_jump, jmp_disp))

def resolve_exception_jumps_match_found(seg_data, ea_seg, off_match, pattern, prechecks, xor_key_exception = None, enc_jmp_disp_exception = None, b_make_comments = True):

    # find the exception handler jump deobfuscator offset and xor key if not given
    if not xor_key_exception or not enc_jmp_disp_exception:
        exception_jumps_params = find_parameters_exception_jumps(seg_data, ea_seg)
        xor_key_exception = exception_jumps_params['xor_key_exception']
        enc_jmp_disp_exception = exception_jumps_params['enc_jmp_disp_exception']

    # calculate ea of the matching pattern
    ea_match = ea_seg + off_match

    # make code where the pattern was found, at least
    for i in range(0, 0x60):
        IDAAPI_DelItems(ea_match + i)
    ea_temp = ea_match
    for i in range(0, 15):
        IDAAPI_MakeCode(ea_temp)
        ea_temp = ea_temp + IDAAPI_ItemSize(ea_temp)

    # perform specific prechecks for the specific exception
    if pattern_checks := prechecks(ea_match, pattern, seg_data):

        ea_except = ea_match + pattern_checks['disp_exception']
        ea_patch = ea_match + pattern_checks['patching_offset']

        if off_match + pattern_checks['disp_exception'] + enc_jmp_disp_exception < len(seg_data):

            jmp_disp = seg_data[off_match + pattern_checks['disp_exception'] + enc_jmp_disp_exception] ^ xor_key_exception
            ea_jump = 0xffffffff&(ea_except + jmp_disp)

            post_checks = True
            if 'post_jump_checks' in pattern_checks:
                if 'n_disasm_ins' in pattern_checks['post_jump_checks']:
                    if not is_disasm_code(ea_jump, pattern_checks['post_jump_checks']['n_disasm_ins']):
                        post_checks = False
                if 'limit_jump_size_max' in pattern_checks['post_jump_checks']:
                    if jmp_disp > pattern_checks['post_jump_checks']['limit_jump_size_max']:
                        post_checks = False
                if 'limit_jump_size_min' in pattern_checks['post_jump_checks']:
                    if jmp_disp < pattern_checks['post_jump_checks']['limit_jump_size_min']:
                        post_checks = False
            if post_checks:
                print("PATCHING success!! %x %x trick (%s) target: %x (off: %x)" % (ea_match, ea_except, pattern_checks['type'], ea_jump, jmp_disp))
                jmp_patch(pattern_checks['type'], ea_match, ea_patch, ea_jump, pattern_checks['patch'], b_make_comments, jmp_disp)
            else:
                pass #print("POSTCHECK failed!! %x %x trick (%s) target: %x (off: %x)" % (ea_match, ea_except, pattern_checks['type'], ea_jump, jmp_disp))

def resolve_exception_jumps_common(patterns, prechecks, xor_key_exception = None, enc_jmp_disp_exception = None, b_make_comments = True):
    for ea_seg in IDAAPI_Segments():
        if seg_data := IDAAPI_GetManyBytes(ea_seg, IDAAPI_SegEnd(ea_seg) - IDAAPI_SegStart(ea_seg)):
            for pattern in patterns:
                for e in findall_pattern(seg_data, pattern['pattern']):
                    resolve_exception_jumps_match_found(seg_data, ea_seg, e, pattern, prechecks, xor_key_exception, enc_jmp_disp_exception, b_make_comments)
                    # reload seg data after last patch
                    seg_data = IDAAPI_GetManyBytes(ea_seg, IDAAPI_SegEnd(ea_seg) - IDAAPI_SegStart(ea_seg))