#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Blog reference: https://www.zscaler.com/blogs/security-research/technical-analysis-pikabot
# Description: This is a Python script to reproduce the bot ID generation code used by Pikabot
# Follow us on Twitter: @ThreatLabz

import argparse
from typing import Optional


def checksum(data: int) -> int:
    return (0x75BCD15 * (data + 1)) & 0xffffffff


def generate_bot_id(host_info: bytes, volume_serial_number: int) -> Optional[str]:
    output = 0
    original_vol_id = volume_serial_number
    for current_character in host_info:
        volume_serial_number *= 5
        volume_serial_number += current_character
        output = volume_serial_number & 0xffffffff

    if not output:
        return
    checksum_1 = checksum(output)
    vol_id = checksum(original_vol_id)
    vol_id = checksum(vol_id) & 0xffff
    checksum_2 = vol_id

    result = bytearray()
    for _ in range(8):
        vol_id = checksum(vol_id)
        result.extend(bytes([vol_id & 0xff]))
    checksum_3 = int.from_bytes(result[4:], byteorder='little')
    bot_id = f"{checksum_1:07X}{checksum_2:09X}{checksum_3}"
    return bot_id


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-cn', '--computer_name', help="Computer name of compromised host", type=str, required=True)
    parser.add_argument('-u', '--username', help="Username of compromised host", type=str, required=True)
    parser.add_argument('-p', '--product', help="Windows product version. This is the buffer of variable "
                                                "'pdwReturnedProductType' of GetProductInfo", type=str, required=True)
    parser.add_argument('-vsi', '--volume_serial_id', help="Volume serial number of C: drive", type=str,
                        required=True)
    args = parser.parse_args()
    host_info = f"{args.computer_name}\\{args.username}|{args.product}"
    if bot_id := generate_bot_id(host_info.lower().encode('utf-8'), int(args.volume_serial_id, 16)):
        print(bot_id)


if __name__ == '__main__':
    main()
