#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Blog reference: https://www.zscaler.com/blogs/security-research/technical-analysis-trigona-ransomware
# Description: This is a Python tool to decrypt Trigona's ransomware configuration
# Follow us on Twitter: @ThreatLabz

import sys
import pefile
import json
import hashlib
import struct
from Crypto.Cipher._mode_cbc import CbcMode
from Crypto.Cipher.AES import _create_base_cipher


class AESCBCRBT(CbcMode):
    def _reset_state(self):
        self._next = [self.encrypt, self.decrypt]

    def decrypt(self, ciphertext, output=None):
        self._reset_state()
        return super().decrypt(ciphertext, output)

    def encrypt(self, plaintext, output=None):
        self._reset_state()
        return super().encrypt(plaintext, output)


class Stream:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def read_byte(self):
        data = self.data[self.offset]
        self.offset += 1
        return data

    def read_bytes(self, num_bytes):
        data = self.data[self.offset:self.offset + num_bytes]
        self.offset += num_bytes
        return data

    def read_dword(self):
        data = self.data[self.offset:self.offset+4]
        self.offset += 4
        return data

    def read_int_dword(self):
        return struct.unpack(">I", self.read_dword())[0]

    def read_data_block(self):
        size = self.read_int_dword()
        return self.read_bytes(size)

    def seek_bytes(self, num_bytes):
        return self.data[self.offset:self.offset+num_bytes]

    def seek_all(self):
        return self.data[self.offset:]


class Config:
    def __init__(self):
        self.cid = None
        self.vid = None
        self.file_rsa_pub_key = None
        self.ransom_rsa_pub_key = None
        self.ransom_note_aes_key = None
        self.extension_whitelist = []
        self.dir_whitelist = []
        self.email_contact = ""
        self.ransom_note = ""
        self.extensions = []

    def get_config(self):
        return {
            "cid": self.cid.decode("ascii"),
            "vid": self.vid.decode("ascii"),
            "file_rsa_pubkey": self.file_rsa_pub_key[4:4+0x202].hex(),
            "ransom_note_rsa_pubkey": self.ransom_rsa_pub_key[4:4+0x200].hex(),
            "ransom_note_aes_key": self.ransom_note_aes_key.hex(),
            "extension_whitelist": str(self.extension_whitelist),
            "directory_whitelist": str(self.dir_whitelist),
            "email_contact": str(self.email_contact.decode("ascii")),
            "ransom_note_template": self.ransom_note.decode("utf-8"),
            "extensions": self.extensions
        }

    def print_config(self):
        print(json.dumps(self.get_config(), indent=4))


def get_config_resource(pe):
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            if entry.name is not None:
                if entry.name.__str__() == "CFGS":
                    offset = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size
                    data = pe.get_data(offset, size)
                    return {"data": data, "size": size}
    return None


def parse_sections(data):
    cfg = Config()
    config_stream = Stream(data)
    padding_bytes = config_stream.read_byte()
    config_stream.read_bytes(padding_bytes)
    config_md5 = config_stream.read_bytes(16)
    cfg_data = config_stream.seek_all()
    actual_cfg_md5 = hashlib.md5(cfg_data).hexdigest()
    if actual_cfg_md5 != config_md5.hex():
        print("invalid config!")
        return None

    section1_size = config_stream.read_int_dword()
    section1 = config_stream.read_bytes(section1_size)
    parse_section1_stream(cfg, section1)

    section2_size = config_stream.read_int_dword()
    section2 = config_stream.read_bytes(section2_size)
    extensions = parse_section2_stream(section2)
    cfg.extensions = extensions

    section3_size = config_stream.read_int_dword()
    ransom_note = config_stream.read_bytes(section3_size)
    cfg.ransom_note = ransom_note
    return cfg


def parse_section1_stream(cfg, data):
    section1 = Stream(data)
    if section1.seek_bytes(4) == (b"\x00" * 4):
        section1.read_bytes(2)
    file_rsa_pub_key = section1.read_data_block()
    ransom_note_rsa_pub_key = section1.read_data_block()
    vid = section1.read_data_block()
    cid = section1.read_data_block()
    section1.read_data_block()  # unk1
    extension_whitelist = section1.read_data_block()
    contact_email = section1.read_data_block()
    dir_whitelist = section1.read_data_block()
    section1.read_data_block()  # unk2
    section1.read_data_block()  # unk3
    section1.read_data_block()  # unk4
    section1.read_data_block()  # unk5
    ransom_note_aes_key = section1.read_bytes(32)

    cfg.file_rsa_pub_key = file_rsa_pub_key
    cfg.ransom_rsa_pub_key = ransom_note_rsa_pub_key
    cfg.vid = vid
    cfg.cid = cid
    cfg.ransom_note_aes_key = ransom_note_aes_key
    if len(dir_whitelist) > 1:
        cfg.dir_whitelist = dir_whitelist.decode("ascii").strip().split("\r\n")
    if len(extension_whitelist) > 1:
        cfg.extension_whitelist = extension_whitelist.decode("ascii").strip().split("\r\n")
    cfg.email_contact = contact_email


def parse_section2_stream(data):
    section2 = Stream(data)
    extension_cnt = 0
    extensions_list = []
    for i in range(13):
        extensions_size = section2.read_int_dword()
        extensions = section2.read_bytes(extensions_size)
        ext_stream = Stream(extensions)
        while ext_stream.offset < extensions_size:
            size = ext_stream.read_byte()
            extension = ext_stream.read_bytes(size)
            extensions_list.append(extension.decode('ascii'))
            extension_cnt += 1
    return extensions_list


def aes_decrypt(aes_key, aes_iv, data):
    aes = AESCBCRBT(_create_base_cipher({"key": aes_key}), aes_iv)
    blocks = int(len(data) / 16)
    dec = aes.decrypt((data[:16*blocks]))
    xor_key = aes.encrypt(b"\x00" * 16)
    for j, i in enumerate(data[16 * blocks:]):
        dec += (i ^ xor_key[j % 16]).to_bytes(1, "little")
    return dec


def print_usage():
    header = "Author: Zscaler ThreatLabz (@threatlabz)\r\nDescription: Trigona ransomware configuration extraction " \
             "tool\r\n"
    print(f"{header}\r\nUsage: python3 {sys.argv[0]} [trigona.exe]")


def main():

    if len(sys.argv) != 2:
        print_usage()
        sys.exit(1)

    try:
        pe = pefile.PE(sys.argv[1])
    except:
        print("[ERROR] Invalid PE file")
        sys.exit(1)
    cfg = get_config_resource(pe)
    if cfg is None:
        print("[ERROR] Could not find Trigona ransomware config")
        sys.exit(1)
    data = cfg['data']
    layer1 = aes_decrypt(data[:32], data[32:48], data[48:])
    dec_data = aes_decrypt(layer1[16:48], layer1[:16], layer1[48:])
    cfg = parse_sections(dec_data)
    if cfg is None:
        print("[ERROR] Could not extract config")
    else:
        cfg.print_config()


if __name__ == "__main__":
    main()
