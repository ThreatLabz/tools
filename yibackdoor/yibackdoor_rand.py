import ctypes
import os
import struct
from ctypes import wintypes
from fnvhash import fnv1a_32

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
 
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

class YiBackdoorRandom:
    def __init__(self):
        self.bot_id = self.initialize_bot_id()
        self.alpha_charset = "abcedfikmnopsutw"
        self.beta_charset = "bcdfghjklmnpqrstvwxyz"
        self.magic_charset = "aeiou"

    @staticmethod
    def ms_lcg(seed: int) -> bytes:
        return struct.pack("<L", ( 0x343FD * seed + 0x269EC3) & 0xFFFFFFFF)

    def derive_rand_int_from_bot_id(self) -> bytes:
        rand_int = self.ms_lcg(seed=self.bot_id)
        self.bot_id = struct.unpack("<L", rand_int)[0]
        return rand_int

    def rand_word(self) -> int:
        rand_int = self.derive_rand_int_from_bot_id()
        pseudo_rand_int = rand_int[2] << 8
        rand_int = self.derive_rand_int_from_bot_id()
        return rand_int[2] | pseudo_rand_int

    def rand_int(self) -> int:
        return self.rand_word() << 16 | self.rand_word()

    @staticmethod
    def rand_byte_from_str(data: bytes, iterations: int) -> int:
        initial = 0xff

        for idx in range(iterations):
            initial ^= data[idx]
            initial &= 0xff
            for _ in range(8):
                is_msb_set = initial >> 7 & 1
                initial *= 2
                initial &= 0xff
                if is_msb_set:
                    initial ^= 0x31
                    initial &= 0xff
        result = (32 * initial) | (initial >> 3)
        result &= 0xff
        return result

    def is_filename_botid_derived(self, filename: str) -> bool:
        counter = 0
        for f_character in filename:
            if not f_character.isalpha():
                break
            counter += 1
        if counter < 4:
            return False
        rand_index = self.rand_byte_from_str(filename.encode(), counter - 2)
        return self.alpha_charset[rand_index & 0xF] == filename[counter - 2] and self.alpha_charset[rand_index >> 4] == filename[counter - 1]  

    def generate_registry_value_name(self, number_of_iterations: int = 10) -> str:
        for _ in range(number_of_iterations):
            self.derive_rand_int_from_bot_id()
        seed = self.derive_rand_int_from_bot_id()
        out = bytearray()
        if seed[2] & 1:
            out = self.gen_str_from_magic_alphabets_rand(minimum_range=3, maximum_range=5) + b"_"
        return out.decode() + self.get_random_guid(number_of_iterations=number_of_iterations, is_guid=True)

    def magic_alphabets_rand(self) -> tuple[str,str]:
        rand1 = self.derive_rand_int_from_bot_id()    
        if (rand1[2] & 1) == 0:
            rand2 = self.derive_rand_int_from_bot_id()
            rand_char = self.beta_charset[rand2[2] % len(self.beta_charset)]
            rand3 = self.derive_rand_int_from_bot_id()
            rand2_char = self.magic_charset[rand3[2] % len(self.magic_charset)]
        else:
            rand2 = self.derive_rand_int_from_bot_id()
            rand_char = self.magic_charset[rand2[2] % len(self.magic_charset)]
            rand3 = self.derive_rand_int_from_bot_id()
            # Or use optimized version using a lookup table
            # num = (0x86186187 * rand3[2]) >> 32
            # rand_char_index = 21 * ( ( num + ( (rand3[2] - num) >> 1) ) >> 4 )
            rand_char_index = (rand3[2] // 21) * 21
            rand_char_index &= 0xFF
            rand_char_index = rand3[2] - rand_char_index
            rand2_char = self.beta_charset[rand_char_index]
        return rand_char, rand2_char

    def gen_str_from_magic_alphabets_rand(self, minimum_range: int, maximum_range: int) -> bytearray:
        if maximum_range > minimum_range:
            seed = self.derive_rand_int_from_bot_id()
            minimum_range = seed[2] % (maximum_range - minimum_range + 1) + minimum_range
        rand_string = bytearray()
        for _ in range(minimum_range):
            rand_char1, rand_char2 = self.magic_alphabets_rand()
            rand_string += rand_char1.encode()
            rand_string += rand_char2.encode()
        return rand_string

    def derive_rand_name_and_append_str(self, charset_index: int, extension: str, is_additional_rand_required: bool) -> bytes:
        uint8t_array = [1, 2, 3, 4, 32, 64]

        for _ in range(charset_index):
            self.derive_rand_int_from_bot_id()
        rand_str = self.gen_str_from_magic_alphabets_rand(minimum_range=2, maximum_range=3)
        if charset_index:
            rand_char_index = ror(charset_index, 3, 8)
            rand_str += self.alpha_charset[rand_char_index & 0xF].encode()
            rand_str += self.alpha_charset[rand_char_index >> 4].encode()
        gen_seed = self.derive_rand_int_from_bot_id()
        if (gen_seed[2] & 1) == 0:
            # Uppercase
            rand_str[0] -= 0x20
        if is_additional_rand_required:
            rand_int_str_based = self.rand_byte_from_str(rand_str, len(rand_str))
            rand_str += self.alpha_charset[rand_int_str_based & 0xF].encode()
            rand_str += self.alpha_charset[rand_int_str_based >> 4].encode()
        gen_seed = self.derive_rand_int_from_bot_id()
        if gen_seed[2] & 1:
            gen_seed = self.derive_rand_int_from_bot_id()
            rand_str += str(uint8t_array[gen_seed[2] % 6]).encode()
        if extension:
            rand_str += extension.encode()
        return rand_str.decode()

    def generate_mutex_name(self, minimum_range=0x14, maximum_range=0x18) -> str:
        number_of_iterations = minimum_range
        if maximum_range > minimum_range:
            gen_seed = self.derive_rand_int_from_bot_id()
            number_of_iterations = gen_seed[2] % (maximum_range - minimum_range + 1) + minimum_range
        rand_string = bytearray()
        for _ in range(number_of_iterations):
            rand_char1, rand_char2 = self.magic_alphabets_rand()
            rand_string += rand_char1.encode()
            rand_string += rand_char2.encode()
        return rand_string.decode()

    def get_random_guid(self, number_of_iterations: int, is_guid: bool) -> str:
        for _ in range(number_of_iterations):
            self.derive_rand_int_from_bot_id()
        out = bytearray()
        for _ in range(4):
            out += self.rand_int().to_bytes(4, "little")
        if number_of_iterations:
            guid_part = struct.unpack("<L", out[8:12])[0] & 0xFFFFF00F | (16 * ((number_of_iterations >> 3) | (32 * number_of_iterations) & 0xff))
            guid_part &= 0xFFFFFFFF
            out[8:12] = guid_part.to_bytes(4, 'little')
        if is_guid:
            guid_part = struct.unpack("<L", out[:4])[0] + struct.unpack("<L", out[4:8])[0] + struct.unpack("<L", out[8:12])[0]
            guid_part &= 0xFFFFFFFF
            out[12:16] = guid_part.to_bytes(4, 'little')
        return f'{{{out[:4][::-1].hex()}-{out[4:6][::-1].hex()}-{out[6:8][::-1].hex()}-{out[8:10].hex()}-{out[10:16].hex()}}}'.upper()

    def derive_persistence_directory_name(self, number_of_iterations: int) -> str:
        random_guid = None
        seed_value = self.derive_rand_int_from_bot_id()
        if seed_value[2] % 3:
            if not (seed_value[2] % 3) - 1:
                random_guid = self.get_random_guid(number_of_iterations=number_of_iterations, is_guid=False)
            elif (seed_value[2] % 3) - 1 == 1:
                random_guid = self.derive_rand_name_and_append_str(number_of_iterations, "", False)
        else:
            random_guid = os.environ.get('USERNAME')
        return random_guid
   
    def initialize_persistence_directory_name(self, number_of_iterations: int = 10) -> bytes:
        for _ in range(number_of_iterations):
            self.derive_rand_int_from_bot_id()
        rand_clsid_value = self.derive_rand_int_from_bot_id()
        CSIDL_APPDATA = 26
        CSIDL_LOCAL_APPDATA = 28
        rand_clsid_value = 2 * ((rand_clsid_value[2] & 1) == 0) + CSIDL_APPDATA
        if rand_clsid_value == CSIDL_APPDATA:
            target_windows_path = "%APPDATA%\\"
        elif rand_clsid_value == CSIDL_LOCAL_APPDATA:
            target_windows_path = "%LOCALAPPDATA%\\"
        else:
            target_windows_path = "C:\\ProgramData\\"
        rand_dir_name = self.derive_persistence_directory_name(number_of_iterations=number_of_iterations)
        rand_value = self.derive_rand_int_from_bot_id()
        if rand_value[2] & 1:
            rand_dir_name += "\\" + self.derive_persistence_directory_name(number_of_iterations=ror(number_of_iterations, 3, 8))
        return target_windows_path + rand_dir_name

    @staticmethod
    def get_account_sid() -> str:
        LookupAccountName = ctypes.windll.advapi32.LookupAccountNameW 
        LookupAccountName.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPVOID,
                                      ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
                                      ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
        LookupAccountName.restype = wintypes.BOOL
        sid_size = wintypes.DWORD(0)
        sid_use = wintypes.DWORD()
        domain_size = wintypes.DWORD(0)
        result = LookupAccountName(None, os.environ["COMPUTERNAME"], None, ctypes.byref(sid_size),
                                    None, ctypes.byref(domain_size), ctypes.byref(sid_use))
        if not result and ctypes.GetLastError() != 122:
            raise ctypes.WinError(ctypes.GetLastError())
        sid = ctypes.create_string_buffer(sid_size.value)
        domain_name = ctypes.create_unicode_buffer(domain_size.value)
        result = LookupAccountName(None, os.environ["COMPUTERNAME"], sid, ctypes.byref(sid_size),
                                   domain_name, ctypes.byref(domain_size), ctypes.byref(sid_use))
        if not result:
            raise ctypes.WinError(ctypes.GetLastError())

        ConvertSidToStringSid = ctypes.windll.advapi32.ConvertSidToStringSidW
        ConvertSidToStringSid.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
        ConvertSidToStringSid.restype = wintypes.BOOL
        sid_string = ctypes.c_wchar_p()
        if not ConvertSidToStringSid(sid, ctypes.byref(sid_string)):
            raise ctypes.WinError(ctypes.GetLastError())
        return sid_string.value
    
    def initialize_bot_id(self) -> int:
        account_sid = self.get_account_sid()
        return fnv1a_32(account_sid.encode())
