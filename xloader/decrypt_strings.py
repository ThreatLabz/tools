#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Blog reference: https://www.zscaler.com/blogs/security-research/technical-analysis-xloaders-code-obfuscation-version-43
# Description: This is a Python reimplementation of Xloader's string decryption algorithm
# Follow us on Twitter: @ThreatLabz

def collect_decrypted_strings(self):
    v = b"\xCC\xC0\xFC\x03"
    v2 = b"\x93\x10\x01\xE4\xFE\xD4\x05\xB3\x72\xE8\xF5\x5B\x72\xFC\x05\xFF\x1F\x6C\x0E\xD3"
    pushebp_blk_1 = list(self.pushebp_decrypted_blocks.values())[0]
    pushebp_blk_5 = list(self.pushebp_decrypted_blocks.values())[4]
    pushebp_blk_6 = list(self.pushebp_decrypted_blocks.values())[5]
    pushebp_blk_5_sha = self.sha1_revert(hashlib.sha1(pushebp_blk_5).digest())
    key1 = self.custom_rc4(pushebp_blk_6, pushebp_blk_5_sha)
    key2 = xor(v2, v)
    key2_sha = self.sha1_revert(hashlib.sha1(key2).digest())
    key3 = self.custom_rc4(key1, key2_sha)
    key3_sha = self.sha1_revert(hashlib.sha1(key3).digest())
    key4 = self.custom_rc4(key2, key3_sha)
    n_string = 0
    i = 0
    while i < len(pushebp_blk_1):
        s = pushebp_blk_1[i + 1: i + 1 + pushebp_blk_1[i]]
        print(f"{n_string}:{self.custom_rc4(s, key4)[0:-1]}")
        i += (1 + pushebp_blk_1[i])
        n_string += 1
