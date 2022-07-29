#!/usr/bin/env python3

import os
import rsa
import logging
import argparse
from Crypto.Cipher import DES3
from pathlib import Path


def decrypt_file(fpath, key_n, key_d, logger):
    if not os.path.isfile(fpath):
        logger.debug('Encrypted file does not exist.')
        return
    encrypted_size = os.stat(fpath).st_size
    if encrypted_size < 0x9C:
        logger.error('Encrypted file size is less than minimum encrypted file size.')
        return

    original_size = None
    encrypted_key_blob = None
    encrypted_data = None
    with open(fpath, 'rb') as fl:
        fl.seek(-4, 2)
        marker = fl.read()
        if marker != b'\xef\xbe\xed\xfe':
            logger.warning('Marker not found, File not encrypted...')
            return
        # get original file size
        fl.seek(-12, 2)
        original_size = int.from_bytes(fl.read(8), 'little')

        # len(data+padding) = len(encryptedfile) - len(marker) - len(size) - len(encrypted key blob)
        # Encrypted len(data+padding) < originalsize
        if (encrypted_size - 0x88) < original_size:
            logger.warning('Encrypted data size is less than expected original size from structure.')
            return

        # read encrypted key blob
        encrypted_data_end_offset = fl.seek(-0x88, 1)
        logger.debug(hex(encrypted_data_end_offset))
        encrypted_key_blob = fl.read(0x80)

        # Read encrypted data
        fl.seek(0)
        encrypted_data = fl.read(encrypted_data_end_offset)
    
    if not all([original_size, encrypted_key_blob, encrypted_data]):
        logger.debug('Error reading encrypted file structure from file.')
        return

    logger.debug(f'Original Size: {original_size}')
    logger.debug(f'encrypted_key_blob size: {hex(len(encrypted_key_blob))}')
    logger.debug(f'encrypted_key_blob: {encrypted_key_blob.hex()}')
    logger.debug(f'encrypted_data size: {hex(len(encrypted_data))}')
    logger.debug(f'encrypted_data: {encrypted_data.hex()}')
    decrypted_blob = rsa.core.decrypt_int(rsa.transform.bytes2int(encrypted_key_blob), key_d, key_n)
    decrypted_blob = int.to_bytes(decrypted_blob, 0x80, 'big')

    if decrypted_blob[:2] != b'\x00\x02' and decrypted_blob[-0x31] != 0:
        logging.error('Failed to decrypt file.')
        return

    des3_key = decrypted_blob[-0x30:-0x30+24]
    des3_iv = decrypted_blob[-24:-24+8]

    logger.debug(f'decrypted_blob: {decrypted_blob.hex()}')
    logger.debug(f'des3_key: {des3_key.hex()}')
    logger.debug(f'des3_iv: {des3_iv.hex()}')
    des_cipher = DES3.new(des3_key, DES3.MODE_CBC, des3_iv)
    decrypted = des_cipher.decrypt(encrypted_data)[:original_size]
    logger.info(f'Saving decrypted file to {fpath}.decrypted')
    with open(f'{fpath}.decrypted', 'wb') as fl:
        fl.write(decrypted)


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
        exit("input path not found!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=f'Industrial Spy decryptor POC')
    parser.add_argument('--path', help='Encrypted file path or Folder containing encrypted files', type=str,
                        required=False)
    parser.add_argument('-n', '--modulus', help='RSA Private key n/modulus', type=str, required=True)
    parser.add_argument('-d', '--exponent', help='RSA Private key d/exponent', type=str, required=True)
    parser.add_argument('--debug', help='Debug mode', action='store_true', default=False, required=False)
    args = parser.parse_args()
    input_path = Path(args.path).resolve()

    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format='%(name)s: %(message)s', level=level)
    logger = logging.getLogger('IndustrialSpyDecryptor')

    n = rsa.transform.bytes2int(bytes.fromhex(args.modulus))
    d = rsa.transform.bytes2int(bytes.fromhex(args.exponent))

    process_path(input_path, n, d, logger)
