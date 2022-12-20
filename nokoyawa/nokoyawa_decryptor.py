#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Description: This is a proof-of-concept tool to decrypt files (with a victim's Curve25519 private key) that are encrypted by the Rust-based Nokoyawa ransomware 2.0
# Blog reference: https://www.zscaler.com/blogs/security-research/nokoyawa-ransomware-rust-or-bust
# Follow us on Twitter: @ThreatLabz

import sys
import os
import argparse
import logging
import binascii
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from Crypto.Cipher import Salsa20
from pathlib import Path

def decrypt_file(filename, private_key):
    logger.info(f"attempting to decrypt filename: {filename}")
    file_data = open(filename, "rb").read()

    # extract the footer
    footer = file_data[-40:]
    ephemeral_public_key = footer[:32]
    nonce = footer[-8:]

    file_data = file_data[:-40] #  strip off the foooter

    logger.debug(f"private key: {private_key}")
    logger.debug(f"ephemeral public key: {ephemeral_public_key.hex()}")
    logger.debug(f"nonce: {nonce.hex()}")

    block_len = 0x80000 # set the encrypted block length
    filesize = len(file_data)
    logger.debug(f"filesize: {filesize} ({hex(filesize)})")
    num_block_magic = 30 * (filesize >> 19)
    bytes_to_skip = 0
    bytes_unencrypted = 0
    if num_block_magic > 50099:
        num_blocks = 500
    elif num_block_magic < 100:
        num_blocks = 1
    else:
        num_blocks = (5243 * (num_block_magic >> 2)) >> 17
    logger.debug(f"num blocks: {num_blocks}")
    if num_block_magic >= 200:
        bytes_unencrypted = filesize - (num_blocks << 19)
        bytes_to_skip = int(bytes_unencrypted / (num_blocks - 1))

    priv_key = X25519PrivateKey.from_private_bytes(binascii.unhexlify(private_key))
    peer_public_key = X25519PublicKey.from_public_bytes(ephemeral_public_key)
    shared_key = priv_key.exchange(peer_public_key)
    logger.debug(f"shared key: {shared_key.hex()}")
    dec = bytearray()
    cc = Salsa20.new(key=shared_key[:32], nonce=nonce)
    offset = 0
    if num_blocks > 1:
        for i in range(num_blocks-1):
            print(f"Processing block: {i}/{num_blocks} ({100 * i / num_blocks:.2f}%)\r", end="")
            dec += cc.decrypt(file_data[offset:offset+block_len])
            dec += file_data[offset+block_len:offset+block_len+bytes_to_skip]
            offset += block_len + bytes_to_skip
        dec += file_data[offset:] # add the last block
    else:
        if filesize >= block_len:
            dec += cc.decrypt(file_data[offset:offset+block_len])
            dec += file_data[offset+block_len:offset+block_len+bytes_to_skip]
            offset += block_len + bytes_to_skip
            dec += file_data[offset:] # add the last block
        else:
            dec += cc.decrypt(file_data[offset:]) # encrypt the full file

    offset = str(filename).rfind(".")
    out_name = str(filename)[:offset]
    logger.info(f"writing decrypted file to {out_name}")
    o = open(out_name, "wb")
    o.write(dec)
    o.close()
    logger.info("done!")


def process_path(input_path, privatekey):
    logger.info(f'Processing path: {input_path}')
    if os.path.exists(input_path):
        if os.path.isdir(input_path):
            for filename in os.listdir(input_path):
                f = os.path.join(input_path, filename)
                process_path(f, privatekey)
        else:
            decrypt_file(input_path, privatekey)
    else:
        exit("Input path not found!")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=f'Nokoyawa Ransomware 2.0 Proof-of-Concept Decryptor',
        epilog="Developed by Zscaler ThreatLabz (@threatlabz)")
    parser.add_argument('--path', help='Encrypted file path or folder containing encrypted files', type=str,
                        required=True)
    parser.add_argument('-k', '--privatekey', help='Curve25519 private key', type=str, required=True)
    parser.add_argument('--debug', help='Debug mode', action='store_true', default=False, required=False)
    args = parser.parse_args()
    input_path = Path(args.path).resolve()

    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format='%(asctime)s:%(name)s:%(levelname)s - %(message)s', level=level, datefmt='%Y-%m-%d %I:%M:%S %p')
    logger = logging.getLogger('[Nokoyawa 2.0 Decryptor]')

    process_path(input_path, args.privatekey)
