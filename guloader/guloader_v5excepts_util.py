from ida_defines import *

def is_disasm_code(ea, n_ins):
    while n_ins:
        IDAAPI_DelItems(ea)
        IDAAPI_MakeCode(ea)
        d = IDAAPI_GetDisasmEx(ea, 1)
        if d.startswith('db ') or d.startswith('in ') or d.startswith('out ') or d.startswith('insb') or d.startswith('outsb') or \
           d.startswith('insw') or d.startswith('outsw') or d.startswith('insd') or d.startswith('outsd'):
            return False
        ea = ea + IDAAPI_ItemSize(ea)
        n_ins -= 1
    return True

def djb2_custom_hash(inString, xor_key):
	val = 0x1505
	for ch in inString:  
		val += (val << 5)  
		val &= 0xFFFFFFFF  
		val += ord(ch)
		val &= 0xFFFFFFFF 
		val ^= xor_key 
	return val

def xor(data, key):
    r = []
    for i, b in enumerate(data):
        r.append(b ^ key[i % len(key)])
    return bytes(r)

def extract_ascii(s):
    sout = b""
    for e in s:
        if (e>=0x20 and e<0x7f) or e==0x0d or e==0x0a:
            sout += e.to_bytes(1, byteorder='little')
        else:
            pass
    return sout

def cut_starting_ascii(s):
    sout = b""
    for e in s:
        if (e>=0x20 and e<0x7f) or e==0x0d or e==0x0a:
            sout += e.to_bytes(1, byteorder='little')
        else:
            break
    return sout

def is_ascii(s):
    for e in s:
        if not ((e>=0x20 and e<0x7f) or e==0x0d or e==0x0a):
            return False
    return True

def is_ascii_or_zero(s):
    for e in s:
        if not ((e>=0x20 and e<0x7f) or e==0x0d or e==0x0a or e==0x00):
            return False
    return True

def clean_undefined():
    for ea in IDAAPI_Segments():
        for ea in range(IDAAPI_SegStart(ea), IDAAPI_SegEnd(ea)):
            if IDAAPI_GetDisasm(ea).startswith('db '):
                for i in range(0, 16): IDAAPI_DelItems(ea + i)
                IDAAPI_MakeCode(ea)