#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Description: TOITOIN Downloader String Decryptor
# Reference blog: https://www.zscaler.com/blogs/security-research/toitoin-trojan-analyzing-new-multi-stage-attack-targeting-latam-region
# Follow us on Twitter: @ThreatLabz

def reverse_string(enc_str):  
    do_rev = ""   
    for i in enc_str:  
        do_rev = i + do_rev  
    return do_rev  
     
def decrypt_string(rev_string):
            string = rev_string
            i = 0
            j = 2
            k = 0
            data = ""
            f_len = len(string)/4

            while k < f_len:
                if (i>=2):
                    i+=2
                    j+=2
                    
                val1 = string[i:j]
                
                i+=2
                j+=2
                val2 = string[i:j]
               
                int_conv1 = int(val1, 16)
                int_conv2 = int(val2, 16)
                
                xor_dec_int = int_conv1 ^ int_conv2
                xor_dec_hex = hex(xor_dec_int)[2:]
                
                final_dec_str = bytes.fromhex(xor_dec_hex).decode('utf-8')
                data += final_dec_str
                
                
                k = k + 1
            
            return data
            
print("\n======String Decryptor=====")
enc_str = input("[+] Encrypted String: ")  
rev_string = reverse_string(enc_str)
dec_string = decrypt_string(rev_string)
print("\n[+] Decrypted String: " + dec_string)


