# remove uppercase stack string letters

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
    

# .text:0043452F 2C 1A                                         sub     al, 1Ah
# .text:00434531 73 04                                         jnb     short loc_434537
pattern = "2C 1A ?? ??"

num_patches = 0
ea = idc.get_inf_attr(idc.INF_MIN_EA)
while True:
    ea = ida_search.find_binary(ea, idc.BADADDR, pattern, 16, idc.SEARCH_DOWN)
    if ea == idc.BADADDR:
        break

    end_ea = ea + get_pattern_len(pattern)
    print(f"patching uppercase jump: 0x{ea:x} - 0x{end_ea:x}")
    nop_range(ea, end_ea)
    num_patches += 1

print(f"{num_patches} patches")
