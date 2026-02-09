from ida_defines import *

def xor(a, b):
    out = b""
    for i in range(0, len(a)):
        out += (a[i] ^ b[i]).to_bytes(1, byteorder='little')
    return out

def cut_ascii(s):
    sout = b""
    for e in s:
        if (e>=0x20 and e<0x7f) or e==0x0d or e==0x0a:
            sout += e.to_bytes(1, byteorder='little')
        else:
            break
    return sout

def check_wide(s):
    if len(s) > 5:
        if s[1] == 0 and s[3] == 0 and s[5] == 0 and \
           s[0] != 0 and s[2] != 0 and s[4] != 0:
            return True

def enum_decrypted_strings():
    candidates = list()
    for segea in IDAAPI_Segments():
        segea_start = IDAAPI_SegStart(segea)
        segea_end = IDAAPI_SegEnd(segea)
        for ea in range(segea_start, segea_end-0x105):
            buf = IDAAPI_GetManyBytes(ea, 0x105)
            if buf[0] == 0xe8 and buf[3] == 0xff and buf[4] == 0xff:
                candidate = buf[5+4:5+4+100] # +4 candidate enc string
                candidates.append((ea+5+4, candidate))
                candidate = buf[5:5+100] # candidate key
                candidates.append((ea+5, candidate))
    for candidate1 in candidates:
        for candidate2 in candidates:
            xored = xor(candidate1[1], candidate2[1])
            xored_cut = cut_ascii(xored)
            if len(xored_cut) >= 5:
                print("Candidate decrypted string - addr1 %x addr2 %x string %s" % 
                       (candidate1[0], candidate2[0], xored_cut))
            elif check_wide(xored):
                xored_cut = cut_ascii(xored.replace(b'\x00', b''))
                if len(xored_cut) >= 5:
                    print("Candidate wide decrypted string - addr1 %x addr2 %x string %s" % 
                           (candidate1[0], candidate2[0], xored_cut))

enum_decrypted_strings()