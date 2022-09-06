#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Blog reference: https://www.zscaler.com/blogs/security-research/ares-banking-trojan-learns-old-tricks-adds-defunct-qakbot-dga
# Description: This is a tool to generate the import hashes used by the latest version of Ares
# Last updated in August 2022
# Follow us on Twitter: @ThreatLabz

import sys
import argparse

# The standard CRC64 implementation was originally derived from:
# https://code.activestate.com/recipes/259177-crc64-calculate-the-cyclic-redundancy-check/
POLY64REVh = 0xd8000000
CRCTableh = [0] * 256
CRCTablel = [0] * 256
isInitialized = False

def CRC64(aString):
    global isInitialized
    crcl = 0
    crch = 0
    if (isInitialized is not True):
        isInitialized = True
        for i in range(256): 
            partl = i
            parth = 0
            for j in range(8):
                rflag = partl & 1
                partl >>= 1          
                if (parth & 1):
                    partl |= (1 << 31)
                parth >>= 1
                if rflag:
                    parth ^= POLY64REVh
                    partl ^= 0x10 # modify the lower 32-bits from 0x0 to 0x10
            CRCTableh[i] = parth;
            CRCTablel[i] = partl;

    for item in aString:
        shr = 0
        shr = (crch & 0xFF) << 24
        temp1h = crch >> 8
        temp1l = (crcl >> 8) | shr                        
        tableindex = (crcl ^ ord(item)) & 0xFF
        
        crch = temp1h ^ CRCTableh[tableindex]
        crcl = temp1l ^ CRCTablel[tableindex]
    return (crch, crcl)

def CRC64digest(aString):
    return "%08X%08X" % (CRC64(aString))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage="%(prog)s --f [function_name]")
    parser.add_argument("-f", "--function-name",
                        help="function_name", required=True)
    args = parser.parse_args()

    digest = CRC64digest(args.function_name)
    out = ""
    for i in range(len(digest)):
        if i & 1 != 0:
            val = ord(digest[i]) % 9 + ord('0')
        else:
            val = ord(digest[i]) % 25 + ord('A')    
        out += chr(val)
    print(out)
    
