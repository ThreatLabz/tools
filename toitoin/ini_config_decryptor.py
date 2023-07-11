#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Description: TOITOIN INI Configuration Decryptor
# Reference blog: https://www.zscaler.com/blogs/security-research/toitoin-trojan-analyzing-new-multi-stage-attack-targeting-latam-region
# Follow us on Twitter: @ThreatLabz

def reverse_string(enc_str):  
    do_rev = ""   
    for i in enc_str:  
        do_rev = i + do_rev  
    return do_rev    
     
def decrypt_string(rev_string):
            string = rev_string
            data = ""
            final_dec_str = bytes.fromhex(string).decode('utf-8')
            data = final_dec_str
            
            return data
            
def decryptcnc(enc_cnc):
            data = ""
            i = 0
            j = 2
            k = 0
            f_len = len(enc_cnc)

            while k < f_len:
            
                    str1 = enc_cnc[i:j]
                    k = j + 2
                    str2 = enc_cnc[j:k]
                    int_conv1 = int(str2, 16)
                    
                    val2 = "31"
                    int_conv2 = int(val2, 16)
                        
                    xor_dec_int = int_conv1 ^ int_conv2
                    xor_dec_hex = hex(xor_dec_int)[2:]
                     
                    int_cony1 = int(xor_dec_hex, 16)             
                    int_cony2 = int(str1, 16)
                    
                    offset = "FF"
                    fff = int(offset, 16)
                     
                    if int_cony1 < int_cony2:
                            
                            xor_dec_intny = (int_cony1 - int_cony2)
                            add_xor_offset = xor_dec_intny + fff
                            xor_dec_hexy = hex(add_xor_offset)[2:]
                              
                    else:   
                        xor_dec_intny = int_cony1 - int_cony2
                        xor_dec_hexy = hex(xor_dec_intny)[2:]
 
                    final_dec_stry = bytes.fromhex(xor_dec_hexy).decode('utf-8')                   
                    data += final_dec_stry  
                    i = i + 2
                    j = j + 2
                    
            return data
            
print("\n======INI Decryptor=====\n")
enc_str = input("[+] Encoded INI Data: ")  
rev_string = reverse_string(enc_str)
dec_string = decrypt_string(rev_string)
print("\n[+] Decoded INI Data: " + dec_string)
enc_cnc = input("[+] Encrypted INI Data: ")
dec_cnc = decryptcnc(enc_cnc)
print("[+] Final Decrypted Data: " + dec_cnc)


