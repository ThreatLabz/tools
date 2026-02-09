from guloader_v5excepts_resolve_exception_jumps import resolve_exception_jumps_match_found
import struct

from ida_defines import *


patterns_match = [
    { 'pattern':b'\xcc', 'disp_exception':0, 'patching_offset':0, 'type':'type_CC_80000003', 'patch':True, 'post_jump_checks': {'limit_jump_size_max' : 0x40}},
]

patterns_stop = [
    { 'pattern':b'\xc3'},
]

def null_prechecks(ea_match, pattern, data):
    return pattern

def check_patterns(check_30_bytes):
    for pattern in patterns_match:
        if check_30_bytes.startswith(pattern['pattern']):
            return 1, pattern
    for pattern in patterns_stop:
        if check_30_bytes.startswith(pattern['pattern']):
            return 2, None
    return 0, None

def manage_nops_block(ea_seg, seg_end, seg_data, ea_nops, xor_key_exception, enc_jmp_disp_exception, b_make_comments):
    print('NOPS block found:', hex(ea_nops))
    # follow instructions until finding a match or stop condition
    while ea_nops < seg_end:
        IDAAPI_MakeCode(ea_nops)
        # check match/stop conditions
        res_code, pattern = check_patterns(IDAAPI_GetManyBytes(ea_nops, 30))
        # is stop?
        if res_code == 2:
            break
        # is match?
        if res_code == 1:
            # if match found, call the common exception jumps deobfuscator (the same that is used in the search-specific-pattern-and-patch method in the other py module)
            print('SMART exception jumps match found', hex(ea_nops))
            resolve_exception_jumps_match_found(seg_data, ea_seg, ea_nops - ea_seg, pattern, null_prechecks, xor_key_exception, enc_jmp_disp_exception, b_make_comments)
            # re-read segment to get the patched bytes updated
            seg_data = IDAAPI_GetManyBytes(ea_seg, seg_end - ea_seg)
            break
        # follow calls in case there are int3 where the call is pointing
        if IDAAPI_GetDisasm(ea_nops).startswith('call ') and \
           IDAAPI_GetOpType(ea_nops, 0) == 7:
            call_addr = IDAAPI_GetOperandValue(ea_nops, 0)
            # only calls to the same segment
            if ea_seg <= call_addr < seg_end:
                res_code, pattern = check_patterns(IDAAPI_GetManyBytes(call_addr, 30))
                # is match?
                if res_code == 1:
                    # if match found, call the common exception jumps deobfuscator (the same that is used in the search-specific-pattern-and-patch method in the other py module)
                    print('SMART exception jumps match found (follow call)', hex(call_addr))
                    resolve_exception_jumps_match_found(seg_data, ea_seg, call_addr - ea_seg, pattern, null_prechecks, xor_key_exception, enc_jmp_disp_exception, b_make_comments)
                    # re-read segment to get the patched bytes updated
                    seg_data = IDAAPI_GetManyBytes(ea_seg, seg_end - ea_seg)
        if not (item_sz := IDAAPI_ItemSize(ea_nops)):
            # error?
            break
        ea_nops = ea_nops + item_sz
    return seg_data

def resolve_exception_jumps_smart(xor_key_exception = None, enc_jmp_disp_exception = None, b_make_comments = True):
    for ea_seg in IDAAPI_Segments():
        seg_end = IDAAPI_SegEnd(ea_seg)
        if seg_data := IDAAPI_GetManyBytes(ea_seg, seg_end - ea_seg):
            i = 0
            # search for patched code to start to analyze from there
            while (i := seg_data.find(b'\xeb\x00\x90\x90\x90', i + 1)) != -1:
                ea_nops = ea_seg + i
                seg_data = manage_nops_block(ea_seg, seg_end, seg_data, ea_nops, xor_key_exception, enc_jmp_disp_exception, b_make_comments)