import yara
import capstone
from capstone.x86 import *
import pefile
import validators
import sys
import base64
from typing import Optional

def decrypt_string(data: str, add: int, xor: int) -> bytearray:
    data = base64.b64decode(data)
    dec_data = bytearray()
    for i in data:
        i = (i + add) & 0xFF
        i = (i ^ xor) & 0xFF
        dec_data.append(i)
    return dec_data
	
def get_virtual_address_from_offset(pe: pefile.PE, offset: int) -> Optional[int]:
    for section in pe.sections:
        if section.PointerToRawData <= offset < section.PointerToRawData + section.SizeOfRawData:
            return pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + (offset - section.PointerToRawData)
    return None


def get_key(md: capstone.Cs, content: bytes, pe: pefile.PE, matches: list) -> Optional[tuple[int, int]]:
    for m in matches:
        for s in m.strings:
            if s.identifier == "$key":
                for i in s.instances:
                    instructions = md.disasm(content[i.offset:i.offset+500], get_virtual_address_from_offset(pe, i.offset))
                    for ins in instructions:
                        if ins.mnemonic == "add":
                            add = ins.operands[1].imm

                        if ins.mnemonic == "xor":
                            xor = ins.operands[1].imm
                            return add, xor
    return None

def get_group_and_version(md: capstone.Cs, content: bytes, pe: pefile.PE, matches: list, file: object) -> Optional[tuple[str, str]]:
    match_counter = 0
    group = None
    version = None
    for m in matches:
        for s in m.strings:
            if s.identifier == "$groupandVersion":
                for i in s.instances:
                    instructions = md.disasm(content[i.offset:i.offset+500], get_virtual_address_from_offset(pe, i.offset))
                    for ins in instructions:
                        if ins.mnemonic == "push" and ins.operands[0].type == X86_OP_IMM:
                            push_address = ins.operands[0].imm
                            push_offset = pe.get_offset_from_rva(push_address - pe.OPTIONAL_HEADER.ImageBase)

                            file.seek(push_offset)
                            enc_end = push_offset
                            size = 0
                            current_data = file.read(1)
                            while current_data != b'\x00':
                                enc_end = enc_end + 1
                                size = size + 1
                                file.seek(enc_end)
                                current_data = file.read(1)
                            file.seek(push_offset)
                            enc_content = file.read(size)
                            add, xor = get_key(md, content, pe, matches)
                            dec_string = decrypt_string(enc_content, add, xor)
                            match_counter += 1
                            if match_counter == 1:
                                group = dec_string

                            if match_counter == 2:
                                version = dec_string
                                return group.decode("utf-8"), version.decode("utf-8")
    return None

def get_network_key_table(md: capstone.Cs, content: bytes, pe: pefile.PE, matches: list, file: object) -> Optional[bytes]:
    for m in matches:
        for s in m.strings:
            if s.identifier == "$nwkeyTable":
                for i in s.instances:
                    instructions = md.disasm(content[i.offset:i.offset+500], get_virtual_address_from_offset(pe, i.offset))
                    for ins in instructions:
                        if ins.mnemonic == "mov" and ins.operands[1].type == X86_OP_MEM:
                            push_address = ins.operands[1].mem.disp
                            push_offset = pe.get_offset_from_rva(push_address - pe.OPTIONAL_HEADER.ImageBase)
                            file.seek(push_offset)
                            key_table = file.read(0x20)
                            return key_table
    return None

def get_c2(md: capstone.Cs, content: bytes, pe: pefile.PE, matches: list, file: object) -> Optional[tuple[str, str]]:
    ip = None
    port = None
    match_counter = 0
    for m in matches:
        for s in m.strings:
            if s.identifier == "$decryptC2":
                for i in s.instances:
                    instructions = md.disasm(content[i.offset:i.offset+500], get_virtual_address_from_offset(pe, i.offset))
                    for ins in instructions:
                        if ins.mnemonic == "mov" and ins.operands[1].type == X86_OP_IMM:
                            mov_address = ins.operands[1].imm
                            mov_offset = pe.get_offset_from_rva(mov_address - pe.OPTIONAL_HEADER.ImageBase)
                            file.seek(mov_offset)
                            enc_end = mov_offset
                            size = 0
                            current_data = file.read(1)
                            while current_data != b'\x00':
                                enc_end = enc_end + 1
                                size = size + 1
                                file.seek(enc_end)
                                current_data = file.read(1)

                            file.seek(mov_offset)
                            enc_content = file.read(size)
                            add, xor = get_key(md, content, pe, matches)
                            dec_string = decrypt_string(enc_content, add, xor)
                            match_counter += 1
                            if match_counter == 1:
                                ip = dec_string

                            if match_counter == 2:
                                port = dec_string
                                return ip.decode("utf-8"), port.decode("utf-8")
    return None

def main() -> None:
    file_path = sys.argv[1]
    rule = yara.compile(source="""rule kkRAT
    {

        strings:
            $decryptC2 = {
                BE ?? ?? ?? ??
                56
                E8 ?? ?? ?? ??
                A3 ?? ?? ?? ??
                C7 04 24 ?? ?? ?? ??
                E8 ?? ?? ?? ??
                50
                E8 ?? ?? ?? ??
                59
                59
                68 00 00 00 02
                6A 00
                68 ?? ?? ?? ??
                A3 ?? ?? ?? ??
                FF 15 
            }
            $key = {
            8A 14 01
            80 C2 ??
            80 F2 ??
            88 14 01
            41
            3B CE
            }
            $groupandVersion = {
            68 ?? ?? ?? ??
            E8 ?? ?? ?? ??
            50
            8D 85 ?? ?? ?? ??
            50
            E8 ?? ?? ?? ??
            83 C4 ??
            57
            8D 85 ?? ?? ?? ??
            50
            FF B5 ?? ?? ?? ??
            C7 45 ?? ?? ?? ?? ??
            C7 45 ?? ?? ?? ?? ??
            E8 ?? ?? ?? ??
            83 C4 ??
            5F
            5E
            5B
            85 C0
            75 ??
            68 ?? ?? ?? ??
            E8 ?? ?? ?? ??
        }
            $nwkeyTable = {
            83 FA 01
            75 ??
            8A 80 ?? ?? ?? ??
            D0 E8
            EB ??
            83 FA 02
            75 ??
            8A 80 ?? ?? ?? ??
            C0 E0 02
            28 04 31
            EB ??
        }

        condition:
            all of them

    }""")
    file = open(file_path, "rb")
    content = file.read()
    matches = rule.match(data=content)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    pe = pefile.PE(data=content)

    ip, port = get_c2(md, content, pe, matches, file)
    version, group = get_group_and_version(md, content, pe, matches, file)
    key_table = get_network_key_table(md, content, pe, matches, file)
    print(f"IP : {ip}, Port : {port}, Group : {group}, Version : {version} , Network Key: {key_table}")

if __name__ == "__main__":
    main()





