from capstone import *
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
import re

k_eng = Ks(KS_ARCH_X86, KS_MODE_64)

def nop_blk(current_address: int, end_address: int) -> None:
    del_items(current_address, idaapi.DELIT_NOTRUNC, (end_address - current_address))
    ea = current_address
    while ea < end_address:
        patch_byte(ea, 0x90)
        ea += 1
    create_insn(current_address)

def patch_with_call(current_addr: int, target_addr: int) -> bytes:
    final_call_off = target_addr - (current_addr)
    opcodes, _ = k_eng.asm(f"call {final_call_off}")
    return bytes(opcodes)


def patch_with_jmp(current_addr: int, target_addr: int) -> bytes:
    final_jmp_off = target_addr - (current_addr)
    opcodes, _ = k_eng.asm(f"jmp {final_jmp_off}")
    return bytes(opcodes)

def deobf_block_with_a_CALL(address: int) -> None:
    copy_addr = address
    call_addr_off = 0
    call_addr = 0
    end_address = 0
    return_address_off = 0
    return_address = 0
    for counter in range(0x100):
        instr_mnem = print_insn_mnem(copy_addr)
        if instr_mnem.startswith("ret"):
            end_address = copy_addr
            break
        elif instr_mnem == "lea" and get_operand_type(copy_addr, 0) == o_reg and get_operand_type(copy_addr, 1) == o_mem and not return_address:
            return_address = get_operand_value(copy_addr, 1)
        elif instr_mnem == "sub" and get_operand_type(copy_addr, 0) == o_reg and get_operand_type(copy_addr, 1) == o_imm and not return_address_off:
            return_address_off = get_operand_value(copy_addr, 1)
        elif instr_mnem == "lea" and get_operand_type(copy_addr, 0) == o_reg and get_operand_type(copy_addr, 1) == o_mem and not call_addr:
            call_addr = get_operand_value(copy_addr, 1)
        elif instr_mnem == "sub" and get_operand_type(copy_addr, 0) == o_reg and get_operand_type(copy_addr, 1) == o_imm and not call_addr_off:
            call_addr_off = get_operand_value(copy_addr, 1)
        copy_addr = next_addr(copy_addr)
    if return_address_off and return_address and call_addr and call_addr_off and end_address:
        call_addr -= call_addr_off
        return_address -= return_address_off
        patching_call_bytes = patch_with_call(address, call_addr)
        patching_jmp_bytes = patch_with_jmp(address + 5, return_address)
        nop_blk(address, end_address)
        ida_bytes.patch_bytes(address, patching_call_bytes)
        ida_bytes.patch_bytes(address + 5, patching_jmp_bytes)
        create_insn(address)
        create_insn(address + 5)
    else:
        print(f"Failed to deflow at {address:02x}")


def deobf_block_without_a_CALL(address: int) -> None:
    copy_addr = address
    target_block_addr = 0
    next_block_off = 0
    end_address = 0
    for counter in range(0x100):
        instr_mnem = print_insn_mnem(copy_addr)
        if instr_mnem.startswith("ret"):
            # +1 is lame here. get the actual size instead via API
            end_address = copy_addr + 1
            break
        elif instr_mnem == "lea" and get_operand_type(copy_addr, 0) == o_reg and get_operand_type(copy_addr, 1) == o_mem and not target_block_addr:
            target_block_addr = get_operand_value(copy_addr, 1)
        elif instr_mnem == "sub" and get_operand_type(copy_addr, 0) == o_reg and get_operand_type(copy_addr, 1) == o_imm and target_block_addr:
            next_block_off = get_operand_value(copy_addr, 1)
        copy_addr = next_addr(copy_addr)
    if next_block_off and target_block_addr and end_address:
        next_blk_addr = target_block_addr - next_block_off
        patching_bytes = patch_with_jmp(address, next_blk_addr)
        nop_blk(address, end_address)
        ida_bytes.patch_bytes(address, patching_bytes)
        create_insn(address)
    else:
        print(f"Failed to find next block for {address:02x}")

def is_CALL_block(address: int) -> bool:
    copy_addr = address
    founds_leas = 0
    for counter in range(0x100):
        instr_mnem = print_insn_mnem(copy_addr)
        if instr_mnem.startswith("ret"):
            break
        elif instr_mnem == "lea":
            founds_leas += 1
        copy_addr = next_addr(copy_addr)
    return founds_leas == 2

with open("", "rb") as f:
	data = f.read()

imagebase = ida_nalt.get_imagebase()
raw_section_off = 0 # set target section raw offset.
section_va = 0 # set target section virtual address.
# should be push rax, push rax
for match in re.finditer(rb"\x50\x50", data):
    func_addr = match.start() - raw_section_off + section_va + imagebase
    instr = print_insn_mnem(func_addr)
    if instr == "push" and get_operand_type(func_addr, 0) == o_reg:
        if is_CALL_block(func_addr):
            deobf_block_with_a_CALL(func_addr)
        else:
            deobf_block_without_a_CALL(func_addr)
    