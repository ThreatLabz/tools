#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Blog reference: https://www.zscaler.com/blogs/security-research/technical-analysis-xloaders-code-obfuscation-version-43
# Description: This is a Python reimplementation of Xloader's custom SHA1 algorithm
# Follow us on Twitter: @ThreatLabz

import hashlib
import struct

def sha1_revert(digest):
    tuples = struct.unpack("<IIIII", digest)
    output_hash = bytes()
    for item in tuples:
        output_hash += struct.pack(">I", item)
    return output_hash

def custom_sha1(blk):
    return sha1_revert(hashlib.sha1(blk).digest())
