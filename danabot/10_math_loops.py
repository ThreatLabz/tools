# patch junk math loops

import idaapi
import ida_ua
import idautils
import idc


def block_ends_with_a_jump(block):
    JUMPS = [idaapi.NN_ja, idaapi.NN_jae, idaapi.NN_jb, idaapi.NN_jbe, idaapi.NN_jc, idaapi.NN_jcxz, idaapi.NN_je, idaapi.NN_jecxz, idaapi.NN_jg, idaapi.NN_jge, idaapi.NN_jl, idaapi.NN_jle, idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni, idaapi.NN_jmpshort, idaapi.NN_jna, idaapi.NN_jnae, idaapi.NN_jnb, idaapi.NN_jnbe, idaapi.NN_jnc, idaapi.NN_jne, idaapi.NN_jng, idaapi.NN_jnge, idaapi.NN_jnl, idaapi.NN_jnle, idaapi.NN_jno, idaapi.NN_jnp, idaapi.NN_jns, idaapi.NN_jnz, idaapi.NN_jo, idaapi.NN_jp, idaapi.NN_jpe, idaapi.NN_jpo, idaapi.NN_jrcxz, idaapi.NN_js, idaapi.NN_jz]

    last_insn_ea = idc.prev_head(block.end_ea)
    insn = ida_ua.insn_t()
    idaapi.decode_insn(insn, last_insn_ea)

    return insn.itype in JUMPS

def nop_range(start_ea, end_ea):
    idc.del_items(start_ea, idaapi.DELIT_NOTRUNC, (end_ea - start_ea))
    ea = start_ea
    while ea < end_ea:
        idc.patch_byte(ea, 0x90)
        ea += 1
    
    idc.create_insn(start_ea)

def patch_math_loop(block, allowed_mnems):
    ea = block.start_ea
    mnems = []
    while ea < block.end_ea:
        mnems.append(idc.print_insn_mnem(ea))
        ea = idc.next_head(ea)
        
    # only patch blocks that have been nopped before
    if mnems.count("nop") < 2:
        return False
        
    mnems = [m for m in mnems if m != "nop"]
    
    if not block_ends_with_a_jump(block):
        return False
            
    last_insn_ea = idc.prev_head(block.end_ea)   
    jump_dest = idc.get_operand_value(last_insn_ea, 0)
    if jump_dest != block.start_ea:
        return False
   
    # jump
    mnems.pop(-1)
    # cmp
    mnems.pop(-1)
    
    if all([m in allowed_mnems for m in mnems]):
        print(f"patching math loop: 0x{block.start_ea:x} - 0x{block.end_ea:x}: {mnems}")
        nop_range(block.start_ea, block.end_ea)
    
        return True
    return False
    

allowed_mnems = ["mov", "lea", "inc", "add", "sub", "imul", "xor", "shl", "not"] 

num_patches = 0
for func_ea in idautils.Functions():
    #print(f"checking function 0x{func_ea:x}")
    func = idaapi.get_func(func_ea)

    flow_chart = idaapi.FlowChart(func)
    for block in flow_chart:
        #print(f"checking block 0x{block.start_ea:x} - 0x{block.end_ea:x}")
        if patch_math_loop(block, allowed_mnems):
            num_patches += 1
            
print(f"{num_patches} patches")