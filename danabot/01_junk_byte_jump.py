# find and patch jump junk byte anti-analysis

import idaapi
import idc


def get_pattern_len(pattern):
    return len(pattern.replace(" ", "")) // 2
    
    
def nop_range(start_ea, end_ea):
    idc.del_items(start_ea, idaapi.DELIT_NOTRUNC, (end_ea - start_ea))
    ea = start_ea
    while ea < end_ea:
        idc.patch_byte(ea, 0x90)
        ea += 1
        
    idc.create_insn(start_ea)
    

patterns = [
    # .text:0074F5BD B8 00 00 00 00                                mov     eax, 0
    # .text:0074F5C2 83 F8 01                                      cmp     eax, 1
    # .text:0074F5C5 7C 01                                         jl      short near ptr unk_74F5C8
    # .text:0074F5C7 6C                                            db  6Ch
    # .text:0074F5C8 0F                            unk_74F5C8      db  0Fh
    "B8 ?? 00 00 00 83 F8 ?? ?? 01 ??",

    # .text:00D115E6 BB 01 00 00 00                                mov     ebx, 1
    # .text:00D115EB 83 FB 01                                      cmp     ebx, 1
    # .text:00D115EE 7E 01                                         jle     short near ptr unk_D115F1
    # .text:00D115F0 E4                                            db 0E4h
    # .text:00D115F1 0F                            unk_D115F1      db  0Fh
    "BB ?? 00 00 00 83 FB ?? ?? 01 ??",
]


num_patches = 0
for pattern in patterns:
    ea = idc.get_inf_attr(idc.INF_MIN_EA)
    while True:
        ea = ida_search.find_binary(ea, idc.BADADDR, pattern, 16, idc.SEARCH_DOWN)
        if ea == idc.BADADDR:
            break
            
        end_ea = ea + get_pattern_len(pattern)
        print(f"patching jump junk byte: 0x{ea:x} - 0x{end_ea:x}")
        nop_range(ea, end_ea)
        num_patches += 1
    
print(f"{num_patches} patches")
