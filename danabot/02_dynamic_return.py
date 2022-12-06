# find and patch dynamic return anti-analysis

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


# .text:00751505 E8 00 00 00 00                                call    $+5
# .text:0075150A 58                                            pop     eax
# .text:0075150B 83 C0 09                                      add     eax, 9
# .text:0075150E 50                                            push    eax
# .text:0075150F C2 00 00                                      retn    0
# .text:00751512 D6                                            db 0D6h
pattern = "E8 00 00 00 00 58 83 C0 09 50 C2 00 00 ??"

num_patches = 0
ea = idc.get_inf_attr(idc.INF_MIN_EA)
while True:
    ea = ida_search.find_binary(ea, idc.BADADDR, pattern, 16, idc.SEARCH_DOWN)
    if ea == idc.BADADDR:
        break
        
    end_ea = ea + get_pattern_len(pattern)
    print(f"patching dynamic ret: 0x{ea:x} - 0x{end_ea:x}")
    nop_range(ea, end_ea)
    num_patches += 1
    
print(f"{num_patches} patches")
