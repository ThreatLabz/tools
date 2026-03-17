import hashlib
import base58

def calculate_systemid(computername :str, username :str, cpu_signature :int, volume_serial_root_dir :int) -> bytes:
    key = bytes(range(0, 0x80, 4))
    nonce = bytes(range(0, 0x30, 4))
    xored = (volume_serial_root_dir ^ cpu_signature) & 0xFFFFFFFF
    data = computername.encode("utf-16le") + username.encode("utf-16le") + struct.pack("<I", xored)
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(data)
    hash = ripemd160.digest()
    tag = chacha20poly1305_tag(key, nonce, hash)
    system_id_full = base58.b58encode(tag)
    if len(system_id_full) < 8:
        system_id_full = base58.b58encode(data)
        if len(system_id_full) < 8:
            system_id_full = system_id_full + ("0" * (8 - len(system_id_full)))

    system_id = system_id_full[:8].upper()
    return system_id