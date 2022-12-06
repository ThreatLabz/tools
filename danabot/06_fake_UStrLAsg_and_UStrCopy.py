# find and patch junk UStrLAsg and UStrCopy calls

import collections

import idaapi
import idautils
import idc


def nop_range(start_ea, end_ea):
    idc.del_items(start_ea, idaapi.DELIT_NOTRUNC, (end_ea - start_ea))
    ea = start_ea
    while ea < end_ea:
        idc.patch_byte(ea, 0x90)
        ea += 1
        
    idc.create_insn(start_ea)

   
def handle_junk_UStrLAsg(ea, junk_vars=[]):
    args =  []
    
    # .text:0074F626 8D 45 8C                      lea     eax, [ebp+var_74]
    # .text:0074F629 8B 55 8C                      mov     edx, [ebp+var_74]
    # .text:0074F62C E8 93 AB CB FF                call    @System@@UStrLAsg$qqrr20System@UnicodeStringx20System@UnicodeString ; System::__linkproc__ UStrLAsg(System::UnicodeString &,System::UnicodeString)
    prev1_ea = idc.prev_head(ea)
    if idc.print_insn_mnem(prev1_ea) != "mov":
        return
        
    # edx
    if idc.get_operand_value(prev1_ea, 0) != 0x2:
        return
        
    prev1_src = idc.get_operand_value(prev1_ea, 1)
    args.append(prev1_src)
    
    prev2_ea = idc.prev_head(prev1_ea)
    if idc.print_insn_mnem(prev2_ea) != "lea":
        return
        
    # eax
    if idc.get_operand_value(prev2_ea, 0) != 0x0:
        return
        
    prev2_src = idc.get_operand_value(prev2_ea, 1)
    args.append(prev2_src)
    
    if not junk_vars:
        return args
        
    if any([a in junk_vars for a in args]):
        start_ea = prev2_ea
        end_ea = idc.next_head(ea)
        print(f"patching junk UStrLAsg: 0x{start_ea:x} - 0x{end_ea:x}")
        nop_range(start_ea, end_ea)
        
        return True


def handle_junk_UStrCopy(ea, junk_vars=[]):
    args =  []
    
    # .text:0074F65D 8D 45 98                                      lea     eax, [ebp+var_68]
    # .text:0074F660 50                                            push    eax
    # .text:0074F661 B9 02 00 00 00                                mov     ecx, 2
    # .text:0074F666 BA 01 00 00 00                                mov     edx, 1
    # .text:0074F66B 8B 45 90                                      mov     eax, [ebp+var_70]
    # .text:0074F66E E8 95 B9 CB FF                                call    @System@@UStrCopy$qqrx20System@UnicodeStringii ; System::__linkproc__ UStrCopy(System::UnicodeString,int,int)
    prev1_ea = idc.prev_head(ea)
    if idc.print_insn_mnem(prev1_ea) != "mov":
        return
        
    # eax
    if idc.get_operand_value(prev1_ea, 0) != 0x0:
        return
        
    prev1_src = idc.get_operand_value(prev1_ea, 1)
    args.append(prev1_src)
    
    prev5_ea = prev1_ea
    for i in range(4):
        prev5_ea = idc.prev_head(prev5_ea)
        
    if idc.print_insn_mnem(prev5_ea) != "lea":
        return
        
    # eax
    if idc.get_operand_value(prev5_ea, 0) != 0x0:
        return
        
    prev5_src = idc.get_operand_value(prev5_ea, 1)
    args.append(prev5_src)
    
    if not junk_vars:
        return args
        
    if any([a in junk_vars for a in args]):
        start_ea = prev5_ea
        end_ea = idc.next_head(ea)
        print(f"patching junk UStrCopy: 0x{start_ea:x} - 0x{end_ea:x}")
        nop_range(start_ea, end_ea)
        
        return True


try:
    UStrLAsg_addr = [n[0] for n in idautils.Names() if "UStrLAsg" in n[1]][0]
except Exception as err:
    print(f"getting UStrLAsg_addr err: {err}")
    UStrLAsg_addr = None

try:
    UStrCopy_addr = [n[0] for n in idautils.Names() if "UStrCopy" in n[1]][0]
except Exception as err:
    print(f"getting UStrCopy_addr err: {err}")
    UStrCopy_addr = None

num_patches = 0
for func_ea in idautils.Functions():
    #print(f"checking function 0x{func_ea:x}")
    func = idaapi.get_func(func_ea)
    
    possible_vars = []
    flow_chart = idaapi.FlowChart(func)
    for block in flow_chart:
        #print(f"checking block 0x{block.start_ea:x} - 0x{block.end_ea:x}")

        ea = block.start_ea
        while ea < block.end_ea:
            if idc.print_insn_mnem(ea) == "call":
                if idc.get_operand_value(ea, 0) == UStrLAsg_addr:
                    if vars := handle_junk_UStrLAsg(ea):
                        possible_vars += vars
                
                elif idc.get_operand_value(ea, 0) == UStrCopy_addr:
                    if vars := handle_junk_UStrCopy(ea):
                        possible_vars += vars
                
            ea = idc.next_head(ea)
    
    junk_vars = []
    for var, count in collections.Counter(possible_vars).items():
        if count > 10:
            print(f"0x{var:x} is likely a junk var ({count})")
            junk_vars.append(var)

    flow_chart = idaapi.FlowChart(func)
    for block in flow_chart:
        ea = block.start_ea
        while ea < block.end_ea:
            if idc.print_insn_mnem(ea) == "call":
                if idc.get_operand_value(ea, 0) == UStrLAsg_addr:
                    if handle_junk_UStrLAsg(ea, junk_vars) == True:
                        num_patches += 1
                
                elif idc.get_operand_value(ea, 0) == UStrCopy_addr:
                    if handle_junk_UStrCopy(ea, junk_vars) == True:
                        num_patches += 1
                
            ea = idc.next_head(ea)
    
print(f"{num_patches} patches")
