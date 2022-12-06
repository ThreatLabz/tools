# delete and re-analyze code from scratch

import ida_funcs
import idautils
import idc


func_eas = [f for f in idautils.Functions()]

min_ea = idc.get_inf_attr(INF_MIN_EA)
max_ea = idc.get_inf_attr(INF_MAX_EA)
idc.del_items(min_ea, 0, (max_ea - min_ea))

for func_ea in func_eas:
    idc.create_insn(func_ea)
    ida_funcs.add_func(func_ea)
    
# .text:0041106C 55                            push    ebp
# .text:0041106D 8B EC                         mov     ebp, esp
pattern = "55 8B EC"

ea = idc.get_inf_attr(idc.INF_MIN_EA)
while True:
    ea = ida_search.find_binary(ea, idc.BADADDR, pattern, 16, idc.SEARCH_DOWN)
    if ea == idc.BADADDR:
        break
                
    idc.create_insn(ea)
    ida_funcs.add_func(ea)
    
    ea += 1

print("code reset")
print(f"double check {pattern} and manually fix up")
