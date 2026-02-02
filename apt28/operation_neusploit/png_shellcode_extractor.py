'''
Below script was written to extract the shellcode from PNG image
Steganography is used by APT28 to hide the shellcode inside the PNG
'''

import struct
import sys
from PIL import Image

def extract_payload(png_path, output_path):
    img = Image.open(png_path).convert("RGBA")
    image_data = img.tobytes()
    image_size = len(image_data)
    print(f"Raw buffer size: {image_size} bytes")

    def extract_byte(start_offset, buf_size, data):
        val = 0
        for i in range(8):
            bit_cursor = start_offset - 2 + i
            byte_index = bit_cursor % buf_size
            bit_shift = bit_cursor // buf_size
            extracted_bit = (data[byte_index] >> bit_shift) & 1
            val |= (extracted_bit << i)
        return val

    size_bytes = bytearray()
    cursor = 2
    
    for _ in range(4):
        b = extract_byte(cursor, image_size, image_data)
        size_bytes.append(b)
        cursor += 8
        
    payload_size = struct.unpack('<I', size_bytes)[0]
    print(f"Payload Size: {payload_size} bytes")
    
    print("Extracting shellcode...")
    shellcode = bytearray()
    cursor = 34
    
    for _ in range(payload_size):
        b = extract_byte(cursor, image_size, image_data)
        shellcode.append(b)
        cursor += 8
        
        if len(shellcode) % 10000 == 0:
            print(f"    Extracted {len(shellcode)} bytes...", end='\r')
            
    print(f"Extraction complete.")
    
    with open(output_path, 'wb') as f:
        f.write(shellcode)
    print(f"Shellcode saved to {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extractor.py <path_to_png> <output_file>")
    else:
        extract_payload(sys.argv[1], sys.argv[2])
