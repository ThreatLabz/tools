#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Blog reference: https://www.zscaler.com/blogs/security-research/technical-analysis-cryptnet-ransomware
# Description: CryptNet ransomware string decryption tool
# Follow us on Twitter: @ThreatLabz

import argparse

def decrypt_strings(key_bytes, buffer):
    num_padding_bytes = len(buffer) % 4
    num_blocks = len(buffer) // 4
    decrypted_data = bytearray(len(buffer))
    num_key_blocks = len(key_bytes) // 4
    final_key = 0

    if num_padding_bytes > 0:
        num_blocks += 1

    for i in range(num_blocks):
        key_block_idx = i % num_key_blocks
        data_block_idx = i * 4
        key_offset = key_block_idx * 4
        key_value = (key_bytes[key_offset + 3] << 24) | (key_bytes[key_offset + 2] << 16) | \
                   (key_bytes[key_offset + 1] << 8) | key_bytes[key_offset]
        bitmask = 0xff
        shift_amount = 0
    
        if i == num_blocks - 1 and num_padding_bytes > 0:
            data_value = 0
            final_key += key_value
    
            for j in range(num_padding_bytes):
                if j > 0:
                    data_value <<= 8
                data_value |= buffer[len(buffer) - (1 + j)]
        else:
            final_key += key_value
            data_offset = data_block_idx
            data_value = (buffer[data_offset + 3] << 24) | (buffer[data_offset + 2] << 16) | \
                            (buffer[data_offset + 1] << 8) | buffer[data_offset]
    
        final_key += 0x3b7d9c6e
    
        if i == num_blocks - 1 and num_padding_bytes > 0:
            decrypted_value = final_key ^ data_value
    
            for k in range(num_padding_bytes):
                if k > 0:
                    bitmask <<= 8
                    shift_amount += 8
                decrypted_data[data_block_idx + k] = (decrypted_value & bitmask) >> shift_amount
        else:
            decrypted_value = final_key ^ data_value
            decrypted_data[data_block_idx] = decrypted_value & 0xff
            decrypted_data[data_block_idx + 1] = (decrypted_value & 0xff00) >> 8
            decrypted_data[data_block_idx + 2] = (decrypted_value & 0xff0000) >> 16
            decrypted_data[data_block_idx + 3] = (decrypted_value & 0xff000000) >> 24

    return decrypted_data


if __name__ == "__main__":
	key = None
	file = None

	parser = argparse.ArgumentParser()
	parser.add_argument("-k", "--key", dest="key", required=True, help="Key file")
	parser.add_argument("-f", "--file", dest="file", required=True, help="Encrypted file")
	args = parser.parse_args()
	
	with open(args.key, "rb") as k:
		key = k.read()
	with open(args.file, "rb") as f:
		file = f.read()

	print(decrypt_strings(key, file))
