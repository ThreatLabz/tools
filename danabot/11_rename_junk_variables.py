# rename potentially junk global variables containing junk_strings

import idautils
import idc


junk_strings = [b".exe", b".dll"]

num_renames = 0
for func_ea in idautils.Functions():
    #print(f"checking function 0x{func_ea:x}")
    func = idaapi.get_func(func_ea)
    
    flow_chart = idaapi.FlowChart(func)
    for block in flow_chart:
        #print(f"checking block 0x{block.start_ea:x} - 0x{block.end_ea:x}")

        ea = block.start_ea
        while ea < block.end_ea:
            if idc.print_insn_mnem(ea) in ["mov", "lea"]:                
                if idc.get_operand_type(ea, 1) in [idc.o_imm, idc.o_mem]:
                    src_op = idc.get_operand_value(ea, 1)
                
                    ascii = idc.get_strlit_contents(src_op, -1, STRTYPE_C)
                    if ascii and any([js in ascii for js in junk_strings]):
                        name = "junk_string"
                        print(f"0x{src_op:x} is likely a junk_string")
                        idc.set_name(src_op, name, idc.SN_NOCHECK|0x800)
                        num_renames += 1
                    
                    p_ascii = idc.get_strlit_contents(idc.get_wide_dword(src_op), -1, STRTYPE_C)
                    if p_ascii and any([js in p_ascii for js in junk_strings]):
                        name = "junk_string"
                        print(f"0x{src_op:x} is likely a junk_string")
                        idc.set_name(src_op, name, idc.SN_NOCHECK|0x800)
                        num_renames += 1
                                            
                    wide = idc.get_strlit_contents(src_op, -1, STRTYPE_C_16)
                    if wide and any([js in wide for js in junk_strings]):
                        name = "junk_string"
                        print(f"0x{src_op:x} is likely a junk_string")
                        idc.set_name(src_op, name, idc.SN_NOCHECK|0x800)
                        num_renames += 1
                    
                    p_wide = idc.get_strlit_contents(idc.get_wide_dword(src_op), -1, STRTYPE_C_16)
                    if p_wide and any([js in p_wide for js in junk_strings]):
                        name = "junk_string"
                        print(f"0x{src_op:x} is likely a junk_string")
                        idc.set_name(src_op, name, idc.SN_NOCHECK|0x800)
                        num_renames += 1
                    
            ea = idc.next_head(ea)
            
print(f"{num_renames} renames")
