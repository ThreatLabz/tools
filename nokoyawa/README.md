# Nokoyawa Ransomware Decryption tool

# Description
This is a proof-of-concept decryptor for Nokoyawa ransomware. Note the Curve25519 private key is required to decrypt files.

# Usage
usage: nokoyawa_decryptor.py [-h] --path PATH -k PRIVATEKEY [--debug]

Nokoyawa Ransomware 2.0 Proof-of-Concept Decryptor

options:
  -h, --help            show this help message and exit
  --path PATH           Encrypted file path or folder containing encrypted
                        files
  -k PRIVATEKEY, --privatekey PRIVATEKEY
                        Curve25519 private key
  --debug               Debug mode

Developed by Zscaler ThreatLabz (@threatlabz)


# Example
```
python3 nokoyawa_decryptor.py  -k 100c52972269a65098aaf138851cb24c5a01f94bd6e9003f9290f49f9ac4ca52 --path Server.vmdk.nokoyawa --debug
2022-12-19 04:59:54 PM:[Nokoyawa 2.0 Decryptor]:INFO - Processing path: /home/nobody/nokoyawa/Server.vmdk.nokoyawa
2022-12-19 04:59:54 PM:[Nokoyawa 2.0 Decryptor]:INFO - attempting to decrypt filename: /home/nobody/nokoyawa/Server.vmdk.nokoyawa
2022-12-19 05:00:14 PM:[Nokoyawa 2.0 Decryptor]:DEBUG - private key: 100c52972269a65098aaf138851cb24c5a01f94bd6e9003f9290f49f9ac4ca52
2022-12-19 05:00:14 PM:[Nokoyawa 2.0 Decryptor]:DEBUG - ephemeral public key: 6ea2ee67a3f08d1a3efef81913c43d2f51b76b17eee396912718e5fb90c5fa78
2022-12-19 05:00:14 PM:[Nokoyawa 2.0 Decryptor]:DEBUG - nonce: 617761796f6b6f6e
2022-12-19 05:00:14 PM:[Nokoyawa 2.0 Decryptor]:DEBUG - filesize: 938843136 (0x37f59c00)
2022-12-19 05:00:14 PM:[Nokoyawa 2.0 Decryptor]:DEBUG - num blocks: 500
2022-12-19 05:00:14 PM:[Nokoyawa 2.0 Decryptor]:DEBUG - shared key: eb388f543fa0082ee1454bf8128487753978575877b2449efed4146721fb7658
2022-12-19 05:00:15 PM:[Nokoyawa 2.0 Decryptor]:INFO - writing decrypted file to /home/nobody/nokoyawa/Server.vmdk
2022-12-19 05:00:17 PM:[Nokoyawa 2.0 Decryptor]:INFO - done!

```
