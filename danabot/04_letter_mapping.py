# map danabot's stack string letters

import ida_search
import idautils
import idc


def set_and_get_letter_mapping():
    min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    
    # .text:004335AD C6 05 E8 D9 76 00 71          mov     ds:byte_76D9E8, 71h ; 'q'
    # .text:004335B4 C6 05 E9 D9 76 00 77          mov     ds:byte_76D9E9, 77h ; 'w'
    ascii_pattern = "C6 05 ?? ?? ?? ?? 71"
    ascii_pattern_addr = ida_search.find_binary(min_ea, idc.BADADDR, ascii_pattern, 16, idc.SEARCH_DOWN)
    if ascii_pattern_addr == idc.BADADDR:
        print("couldn't find ascii_pattern_addr")
        return
    
    ascii_start = idc.get_operand_value(ascii_pattern_addr, 0)
    print(f"ascii_start: 0x{ascii_start:x}")
    
    # .text:00433663 66 C7 05 B4 D9 76 00 71 00    mov     ds:word_76D9B4, 71h ; 'q'
    # .text:0043366C 66 C7 05 B6 D9 76 00 77 00    mov     ds:word_76D9B6, 77h ; 'w'
    wide_pattern = "66 c7 05 ?? ?? ?? ?? 71 00"
    wide_pattern_addr = ida_search.find_binary(min_ea, idc.BADADDR, wide_pattern, 16, idc.SEARCH_DOWN)
    if wide_pattern_addr == idc.BADADDR:
        print("couldn't find wide_pattern_addr")
        return
    
    wide_start = idc.get_operand_value(wide_pattern_addr, 0)
    print(f"wide_start: 0x{wide_start:x}")
    
    letters = "qwertyuiopasdfghjklzxcvbnm"
    letter_mapping = {}
    for i, letter in enumerate(letters):
        ascii_addr = ascii_start + i 
        letter_mapping[ascii_addr] = letter
        idc.set_name(ascii_addr, f"g_{letter}")
    
        found = False
        for xref in idautils.XrefsTo(ascii_addr):
            if idautils.XrefTypeName(xref.type) == "Data_Offset":
                letter_mapping[xref.frm] = letter
                idc.set_name(xref.frm, f"gp_{letter}")
                found = True

        if not found:
            print(f"couldn't find pointer for 0x{ascii_addr:x}")
    
        wide_addr = wide_start + 2 * i 
        letter_mapping[wide_addr] = letter
        idc.set_name(wide_addr, f"g_w_{letter}")
    
        found = False
        for xref in idautils.XrefsTo(wide_addr):
            if idautils.XrefTypeName(xref.type) == "Data_Offset":
                letter_mapping[xref.frm] = letter
                idc.set_name(xref.frm, f"gp_w_{letter}")
                found = True
    
        if not found:
            print(f"couldn't find pointer for 0x{wide_addr:x}")
    
    return letter_mapping


letter_mapping = set_and_get_letter_mapping()
print("letter_mapping set")
