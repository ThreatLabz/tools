#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Description: This is a proof-of-concept tool to decrypt files (with a victim's RSA private key) that are encrypted by BlackBasta ransomware
# Follow us on Twitter: @ThreatLabz

import os
import rsa
import logging
import argparse
import struct
from Crypto.Cipher import ChaCha20
from pathlib import Path


def decrypt_file(fpath, key_n, key_d, logger):
    if not os.path.isfile(fpath):
        logger.debug('Encrypted file does not exist.')
        return
    encrypted_size = os.stat(fpath).st_size
    if encrypted_size < 512:
        logger.error('Encrypted file size is less than minimum encrypted file size.')
        return

    f = open(fpath,"rb").read()

    # extract the encrypted chacha key and nonce
    enc_blob_size = struct.unpack("<I", f[-4:])[0] + 4  # add additional 4 bytes for the size
    logger.debug(f'Encrypted key blob size: {hex(enc_blob_size)}')

    if enc_blob_size > 0x204:
        logger.error("Invalid blob size!")
        return

    ciphertext = f[-enc_blob_size:-4]
    ciphertext_b = rsa.transform.bytes2int(ciphertext)

    enc_key = rsa.core.decrypt_int(ciphertext_b, key_d, key_n)
    logger.debug(f'Decrypted Chacha params: {hex(enc_key)}')

    chacha_key = rsa.transform.int2bytes(enc_key)[:32]
    chacha_nonce = rsa.transform.int2bytes(enc_key)[32:40]

    logger.debug(f'Chacha key: {chacha_key.hex()}')
    logger.debug(f'Chacha nonce: {chacha_nonce.hex()}')

    if chacha_key[0] != 0x69:
        logging.error('Invalid chacha key! failed to decrypt file.')
        return

    cc = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)

    offset = 0
    data = f[:len(f) - enc_blob_size]
    logger.debug(f'Original filesize: {len(data)}')
    dec = b""

    if len(data) < 64 * 11:
        dec += cc.decrypt(data[offset:])
    else:
        blocks = int(len(data) / 64)
        div = int(float(blocks / 100) * 30)
        mod = round(blocks / div)
        if mod < 2:
            mod = 2

        i = 0
        while i < blocks:
            if i % mod == 0:
                dec += cc.decrypt(data[offset:offset + 64])
            else:
                dec += data[offset:offset + 64]
            offset += 64
            i += 1

        bytes_remaining = len(data) - offset
        if bytes_remaining > 0:
            dec += cc.decrypt(data[offset:])

    orig_filename, basta = os.path.splitext(fpath)
    logger.info(f'Saving decrypted file to {orig_filename}')
    with open(f'{orig_filename}', 'wb') as fl:
        fl.write(dec)


def process_path(input_path, key_n, key_d, logger):
    logger.info(f'Processing path: {input_path}')

    if os.path.exists(input_path):
        if os.path.isdir(input_path):
            for filename in os.listdir(input_path):
                f = os.path.join(input_path, filename)
                process_path(f, key_n, key_d, logger)
        else:
            decrypt_file(input_path, key_n, key_d, logger)
    else:
        exit("Input path not found!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=f'BlackBasta ransomware decryptor POC')
    parser.add_argument('--path', help='Encrypted file path or Folder containing encrypted files', type=str,
                        required=False)
    parser.add_argument('-n', '--modulus', help='RSA Private key n/modulus', type=str, required=True)
    parser.add_argument('-d', '--exponent', help='RSA Private key d/exponent', type=str, required=True)
    parser.add_argument('--debug', help='Debug mode', action='store_true', default=False, required=False)
    args = parser.parse_args()
    input_path = Path(args.path).resolve()

    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format='%(name)s: %(message)s', level=level)
    logger = logging.getLogger('BlackBastaDecryptor')

    n = rsa.transform.bytes2int(bytes.fromhex(args.modulus))
    d = rsa.transform.bytes2int(bytes.fromhex(args.exponent))

    process_path(input_path, n, d, logger)
