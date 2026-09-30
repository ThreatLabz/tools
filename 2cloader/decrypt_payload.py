import argparse
import ctypes
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

import pefile
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


FOOTER_SIZE = 0xDC
FOOTER_MAGIC = 0x5F4E3D2C
RTL_COMPRESSION_FORMAT_XPRESS_HUFF = 4
IMAGE_SCN_MEM_EXECUTE = 0x20000000


def fail() -> None:
    print("[-]Decrpytion Failed")
    raise SystemExit(1)


@dataclass
class configfooter:
    magic: int
    fl: int
    final_payload_size: int
    aes_gcm_nonce_size: int
    aes_gcm_tag_size: int
    aes_gcm_nonce: bytes
    aes_gcm_tag: bytes
    sha256_seed_xor2: bytes
    sha256_seed_xor1: bytes
    sum_of_bytes_checksum: int
    persistence: int
    opt_flag: int
    optional_payload_size: int
    optional_message_size: int
    xor_add_after_rolling_xor: int
    xor_key_after_rolling_xor: int
    rolling_xor_seed: int
    unk_67: int
    sleeptime: int
    beacon_id: bytes
    target_executable_name_used_in_injection: bytes
    bt: int
    pn: bytes
    unk_D0: int
    scheduled_tasks_trigger_interval_hours: int
    decompressed_buffer_size: int

    @property
    def total_body_size(self) -> int:
        return self.final_payload_size + self.optional_payload_size + self.optional_message_size


def iterate_resouce(pe: pefile.PE):
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return

    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if not hasattr(type_entry, "directory"):
            continue
        type_id = type_entry.id if type_entry.name is None else str(type_entry.name)

        for name_entry in type_entry.directory.entries:
            if not hasattr(name_entry, "directory"):
                continue
            name_id = name_entry.id if name_entry.name is None else str(name_entry.name)

            for lang_entry in name_entry.directory.entries:
                data_rva = lang_entry.data.struct.OffsetToData
                data_size = lang_entry.data.struct.Size
                blob = pe.get_data(data_rva, data_size)
                if blob and len(blob) == data_size:
                    yield type_id, name_id, lang_entry.id, blob


def parse_footer(footer_bytes: bytes) -> configfooter:

    if struct.unpack_from("<I", footer_bytes, 0)[0] != FOOTER_MAGIC:
        fail()

    dwords = struct.unpack("<55I", footer_bytes)
    return configfooter(
        magic=dwords[0],
        fl=dwords[1],
        final_payload_size=dwords[2],
        aes_gcm_nonce_size=dwords[3],
        aes_gcm_tag_size=dwords[4],
        aes_gcm_nonce=footer_bytes[0x14:0x20],
        aes_gcm_tag=footer_bytes[0x20:0x30],
        sha256_seed_xor2=footer_bytes[0x30:0x40],
        sha256_seed_xor1=footer_bytes[0x40:0x50],
        sum_of_bytes_checksum=dwords[20],
        persistence=dwords[21],
        opt_flag=dwords[22],
        optional_payload_size=dwords[23],
        optional_message_size=dwords[24],
        xor_add_after_rolling_xor=footer_bytes[0x64],
        xor_key_after_rolling_xor=footer_bytes[0x65],
        rolling_xor_seed=footer_bytes[0x66],
        unk_67=footer_bytes[0x67],
        sleeptime=dwords[26],
        beacon_id=footer_bytes[0x6C:0x7C],
        target_executable_name_used_in_injection=footer_bytes[0x7C:0xBC],
        bt=dwords[47],
        pn=footer_bytes[0xC0:0xD0],
        unk_D0=dwords[52],
        scheduled_tasks_trigger_interval_hours=dwords[53],
        decompressed_buffer_size=dwords[54],
    )


def find_footer_resource(pe_path: str | Path):
    pe = pefile.PE(str(pe_path), fast_load=False)

    for type_id, name_id, lang_id, blob in iterate_resouce(pe):
        if len(blob) < FOOTER_SIZE:
            continue

        footer_bytes = blob[-FOOTER_SIZE:]
        if struct.unpack_from("<I", footer_bytes, 0)[0] != FOOTER_MAGIC:
            continue

        footer = parse_footer(footer_bytes)
        body_size = footer.total_body_size
        if len(blob) < body_size + FOOTER_SIZE:
            fail()

        body_offset = len(blob) - FOOTER_SIZE - body_size
        return {
            "type_id": type_id,
            "name_id": name_id,
            "lang_id": lang_id,
            "blob": blob,
            "body": blob[body_offset:body_offset + body_size],
            "footer": footer,
        }

    fail()


def decode_resource_stage(body: bytes, rolling_xor_seed: int) -> bytes:
    return bytes(b ^ ((rolling_xor_seed + i) & 0xFF) for i, b in enumerate(body))


def xor_decrypt_payload(decoded_payload: bytearray, low: int, high: int) -> bytes:
    for i in range(len(decoded_payload)):
        decoded_payload[i] ^= (high + i * low) & 0xFF
    return bytes(decoded_payload)


def compute_section_sha256_seed(pe_path: str | Path) -> bytes:
    pe = pefile.PE(str(pe_path), fast_load=False)

    chosen = None
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00")
        if name == b".text":
            chosen = section
            break

    if chosen is None:
        for section in pe.sections:
            if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                chosen = section
                break

    if chosen is None:
        fail()

    raw = pe.get_data(chosen.VirtualAddress, chosen.Misc_VirtualSize)
    if not raw:
        fail()

    return hashlib.sha256(raw).digest()


def generate_aes_key(footer: configfooter, sha256_seed: bytes) -> bytes:
    if len(sha256_seed) != 32:
        fail()

    seed = bytearray(sha256_seed)
    for i in range(16):
        seed[i] ^= footer.sha256_seed_xor2[i]
        seed[16 + i] ^= footer.sha256_seed_xor1[i]

    checksum = sum(seed) & 0xFFFFFFFF
    if checksum != footer.sum_of_bytes_checksum:
        fail()

    return bytes(seed)


def aes_gcm_decrypt(ciphertext: bytes, footer: configfooter, key: bytes) -> bytes:
    nonce = footer.aes_gcm_nonce[:footer.aes_gcm_nonce_size]
    tag = footer.aes_gcm_tag[:footer.aes_gcm_tag_size]

    if len(key) != 32:
        fail()
    if not nonce:
        fail()
    if not tag:
        fail()

    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, None)
    except InvalidTag:
        fail()


def decompress_final_payload(payload: bytes, footer: configfooter) -> bytes:
    if footer.final_payload_size > len(payload):
        fail()

    if footer.decompressed_buffer_size == 0:
        return payload

    compressed = payload[:footer.final_payload_size]
    tail = payload[footer.final_payload_size:]
    output_size = footer.decompressed_buffer_size

    ntdll = ctypes.WinDLL("ntdll")
    rtl_get_workspace = ntdll.RtlGetCompressionWorkSpaceSize
    rtl_get_workspace.argtypes = [
        ctypes.c_ushort,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    rtl_get_workspace.restype = ctypes.c_long

    rtl_decompress_buffer_ex = ntdll.RtlDecompressBufferEx
    rtl_decompress_buffer_ex.argtypes = [
        ctypes.c_ushort,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_void_p,
    ]
    rtl_decompress_buffer_ex.restype = ctypes.c_long

    rtl_decompress_buffer = ntdll.RtlDecompressBuffer
    rtl_decompress_buffer.argtypes = [
        ctypes.c_ushort,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    rtl_decompress_buffer.restype = ctypes.c_long

    out_buf = (ctypes.c_ubyte * output_size)()
    in_buf = (ctypes.c_ubyte * len(compressed)).from_buffer_copy(compressed)
    final_size_written = ctypes.c_ulong(0)

    status_ex = None
    workspace_size = ctypes.c_ulong(0)
    workspace_fragment_size = ctypes.c_ulong(0)
    status_workspace = rtl_get_workspace(
        RTL_COMPRESSION_FORMAT_XPRESS_HUFF,
        ctypes.byref(workspace_size),
        ctypes.byref(workspace_fragment_size),
    )
    if status_workspace == 0 and workspace_size.value:
        workspace = (ctypes.c_ubyte * workspace_size.value)()
        status_ex = rtl_decompress_buffer_ex(
            RTL_COMPRESSION_FORMAT_XPRESS_HUFF,
            out_buf,
            output_size,
            in_buf,
            len(compressed),
            ctypes.byref(final_size_written),
            workspace,
        )
        if status_ex == 0:
            if final_size_written.value != output_size:
                fail()
            return bytes(out_buf[:output_size]) + tail

    final_size_written.value = 0
    status = rtl_decompress_buffer(
        RTL_COMPRESSION_FORMAT_XPRESS_HUFF,
        out_buf,
        output_size,
        in_buf,
        len(compressed),
        ctypes.byref(final_size_written),
    )
    if status != 0:
        fail()
    if final_size_written.value != output_size:
        fail()

    return bytes(out_buf[:output_size]) + tail


def split_body_parts(payload: bytes, footer: configfooter) -> tuple[bytes, bytes, bytes]:
    main_size = footer.decompressed_buffer_size if footer.decompressed_buffer_size else footer.final_payload_size
    part1_size = footer.optional_payload_size
    part2_size = footer.optional_message_size

    if len(payload) < main_size + part1_size + part2_size:
        fail()

    main_payload = payload[:main_size]
    dropped_payload = payload[main_size:main_size + part1_size]
    message_block = payload[main_size + part1_size:main_size + part1_size + part2_size]
    return main_payload, dropped_payload, message_block


def extract_decode_and_write(pe_path: str | Path, out_dir: str | Path):
    resource = find_footer_resource(pe_path)
    footer = resource["footer"]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    section_sha256_seed = compute_section_sha256_seed(pe_path)
    stage1 = decode_resource_stage(resource["body"], footer.rolling_xor_seed)
    stage2 = xor_decrypt_payload(bytearray(stage1), footer.xor_add_after_rolling_xor, footer.xor_key_after_rolling_xor)
    aes_key = generate_aes_key(footer, section_sha256_seed)
    aes_plaintext = aes_gcm_decrypt(stage2, footer, aes_key)
    final_buffer = decompress_final_payload(aes_plaintext, footer)
    main_payload, dropped_payload, message_block = split_body_parts(final_buffer, footer)

    (out_dir / "resource_footer.bin").write_bytes(resource["blob"][-FOOTER_SIZE:])
    (out_dir / "payload_final.bin").write_bytes(main_payload)

    dropped_path = None
    if footer.optional_payload_size and dropped_payload:
        dropped_path = out_dir / "optional_payload_dropped.bin"
        dropped_path.write_bytes(dropped_payload)

    message_path = None
    if footer.optional_message_size and message_block:
        message_path = out_dir / "messagebox_block.bin"
        message_path.write_bytes(message_block)

    return {
        "[+] Final Payload decrpted and written to ": str(out_dir),
        "optional_payload_path": str(dropped_path) if dropped_path else None,
        "message_block_path": str(message_path) if message_path else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_path")
    args = parser.parse_args()

    try:
        info = extract_decode_and_write(args.input_path, Path.cwd())
    except SystemExit:
        raise
    except Exception:
        fail()
    for key, value in info.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
