# find and remove danabot's stack strings
#
# algorithm: for each basic block that contains a stack string:
#
# - save the stack string letters (the goal isn't to recover the exact string, just enough to get a sense of it)
# - nop from first stack string letter to the last StrCat function in the block

import json

import idaapi
import idautils
import idc


def nop_range(start_ea, end_ea):
    comment_mapping = {}
    ea = start_ea
    while ea < end_ea:
        comment_mapping[ea] = idc.generate_disasm_line(ea, 0)
        ea = idc.next_head(ea)

    idc.del_items(start_ea, idaapi.DELIT_NOTRUNC, (end_ea - start_ea))
    ea = start_ea
    while ea < end_ea:
        idc.patch_byte(ea, 0x90)
        ea += 1
        
    idc.create_insn(start_ea)

    for ea, comment in comment_mapping.items():
        idc.set_cmt(ea, comment, 0)
    
    
def get_stack_string_letters_from_block(block, letter_mapping):
    letters = ""
    
    ea = block.start_ea
    while ea < block.end_ea:
        # .text:0074F70F A1 5C 70 76 00                mov     eax, gp_n
        if idc.print_insn_mnem(ea) == "mov":
            if idc.get_operand_type(ea, 1) == idc.o_mem:
                src_op = idc.get_operand_value(ea, 1)
                if src_op in letter_mapping:
                    letters += letter_mapping[src_op]
                    
        ea = idc.next_head(ea)
        
    return letters
    

def get_last_StrCat_call_in_block(start_ea, StrCat_addrs):
    ea = block.end_ea
    while ea >= start_ea:
        ea = idc.prev_head(ea)
        if idc.print_insn_mnem(ea) == "call":
            if idc.get_operand_value(ea, 0) in StrCat_addrs:
                return ea
            

def patch_stack_string_letter_to_last_StrCat_call_in_block(block, letter_mapping, StrCat_addrs):
    stack_string_letter_start_ea = None
    ea = block.start_ea
    while ea < block.end_ea:
        if idc.print_insn_mnem(ea) == "mov":
            if idc.get_operand_type(ea, 1) == idc.o_mem:
                if idc.get_operand_value(ea, 1) in letter_mapping:
                    stack_string_letter_start_ea = ea
                    break
                    
        ea = idc.next_head(ea)
                    
    if not stack_string_letter_start_ea:
        return

    last_StrCat_call_in_block_ea = get_last_StrCat_call_in_block(stack_string_letter_start_ea, StrCat_addrs)
    if not last_StrCat_call_in_block_ea:
        return
    last_StrCat_call_in_block_ea = idc.next_head(last_StrCat_call_in_block_ea)
        
    print(f"patching stack string letter to last StrCat call: 0x{stack_string_letter_start_ea:x} - 0x{last_StrCat_call_in_block_ea:x}")
    nop_range(stack_string_letter_start_ea, last_StrCat_call_in_block_ea)
    
    return True
    
    
StrCat_addrs = []
try:
    LStrCatN_addr = [n[0] for n in idautils.Names() if "LStrCatN" in n[1]][0]
    print(f"LStrCatN_addr: 0x{LStrCatN_addr:x}")
    StrCat_addrs.append(LStrCatN_addr)
except Exception as err:
    print(f"getting LStrCatN_addr err: {err}")

try:
    PStrNCat_addr = [n[0] for n in idautils.Names() if "PStrNCat" in n[1]][0]
    print(f"PStrNCat_addr: 0x{PStrNCat_addr:x}")
    StrCat_addrs.append(PStrNCat_addr)
except Exception as err:
    print(f"getting PStrNCat_addr err: {err}")

try:
    UStrCatN_addr = [n[0] for n in idautils.Names() if "UStrCatN" in n[1]][0]
    print(f"UStrCatN_addr: 0x{UStrCatN_addr:x}")
    StrCat_addrs.append(UStrCatN_addr)
except Exception as err:
    print(f"getting UStrCatN_addr err: {err}")

# grr lumina
try:    
    serv_concatmultistrs_addr = [n[0] for n in idautils.Names() if "serv_concatmultistrs" in n[1]][0]
    print(f"serv_concatmultistrs_addr: 0x{serv_concatmultistrs_addr:x}")
    StrCat_addrs.append(serv_concatmultistrs_addr)
except Exception as err:
    print(f"getting serv_concatmultistrs_addr err: {err}")

comment_mapping = {}
num_patches = 0
for func_ea in idautils.Functions():
    #print(f"checking function 0x{func_ea:x}")
    func = idaapi.get_func(func_ea)
    
    flow_chart = idaapi.FlowChart(func)
    for block in flow_chart:
        #print(f"checking block 0x{block.start_ea:x} - 0x{block.end_ea:x}")
        
        stack_string_letters = get_stack_string_letters_from_block(block, letter_mapping)
        if not stack_string_letters:
            continue
            
        #print(f"stack_string_letters: {stack_string_letters}")
        comment_mapping[block.start_ea] = stack_string_letters
        
        if patch_stack_string_letter_to_last_StrCat_call_in_block(block, letter_mapping, StrCat_addrs) == True:
            num_patches += 1

print(f"{num_patches} patches")

fp = open("comment_mapping.json", "w")
fp.write(json.dumps(comment_mapping))
fp.close()
print("wrote comment_mapping.json")
