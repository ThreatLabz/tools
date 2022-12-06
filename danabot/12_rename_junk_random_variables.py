# rename potentially junk global variables being assigned random values

import idaapi
import idautils
import idc


#  .text:004071F7  69 93 08 50 69 00 05 84 08 08 imul    edx, dword_695008[ebx], 8088405h
pattern = "69 93 ?? ?? ?? ?? 05 84 08 08"
min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
ea = ida_search.find_binary(min_ea, idc.BADADDR, pattern, 16, idc.SEARCH_DOWN)
Random_addr = idaapi.get_func(ea).start_ea
if not Random_addr:
    print("Couldn't find Random_addr")
    
num_renames = 0
for func_ea in idautils.Functions():
    #print(f"checking function 0x{func_ea:x}")
    func = idaapi.get_func(func_ea)
    
    flow_chart = idaapi.FlowChart(func)
    for block in flow_chart:
        #print(f"checking block 0x{block.start_ea:x} - 0x{block.end_ea:x}")

        ea = block.start_ea
        while ea < block.end_ea:
            if idc.print_insn_mnem(ea) == "call":
                if idc.get_operand_value(ea, 0) == Random_addr:
                    next_ea = idc.next_head(ea)
                    if idc.print_insn_mnem(next_ea) == "mov":
                        if idc.get_operand_type(next_ea, 0) in [idc.o_imm, idc.o_mem]:
                            dst_op = idc.get_operand_value(next_ea, 0)
                            name = "junk_random"
                            print(f"0x{ea:x} likely assigns a junk variable: 0x{dst_op:x}")
                            idc.set_name(dst_op, name, idc.SN_NOCHECK|0x800)
                            num_renames += 1
                        
            ea = idc.next_head(ea)
            
print(f"{num_renames} renames")
