#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ROR4(x, r) ((uint32_t)((x) >> (r) | (x) << (32 - (r))))

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

int64_t cipher_init(__int128 *state_ptr, int64_t output_keystream_addr) {
    // Grouping related variables for clarity
    int64_t blocks_remaining, keystream_base_addr, keystream_cursor;
    int64_t stream_cursor_81, stream_cursor_83, stream_cursor_85, stream_cursor_87;
    int64_t state_ptr_offset_2, state_ptr_offset_minus_2, state_ptr_offset_minus_6;
    int64_t state_ptr_offset_minus_6_v2, state_ptr_offset_minus_10, state_ptr_offset_minus_10_v2;
    
    char *keystream_ptr_offset_0, *keystream_ptr_offset_2, *keystream_ptr_offset_4, *keystream_ptr_offset_8;
    
    int loop_offset, temp_val_45;
    int mix_idx_0, mix_idx_1, mix_idx_2, mix_idx_3, mix_idx_4, mix_idx_5, mix_idx_6, mix_idx_7;
    int mixed_res_0, mixed_res_1, mixed_res_2, mixed_res_3, mixed_res_4, mixed_res_5, mixed_res_6, mixed_res_7;
    
    __int128 *state_ref;
    uint8_t *mem_ptr = (uint8_t *)state_ptr;

    // Load 128-bit blocks
    __uint128_t b0 = ((__uint128_t *)mem_ptr)[0];
    __uint128_t b1 = ((__uint128_t *)mem_ptr)[1];
    __uint128_t b2 = ((__uint128_t *)mem_ptr)[2];
    __uint128_t b3 = ((__uint128_t *)mem_ptr)[3];

    // Extract 32-bit words
    uint32_t round_idx = 0;
    uint32_t word_0  = (uint32_t)(b0 >> 96);
    uint32_t word_4  = (uint32_t)(b1 >> 96);
    uint32_t word_5  = (uint32_t)((b1 >> 64) & 0xFFFFFFFF);
    uint32_t word_6  = (uint32_t)((b1 >> 32) & 0xFFFFFFFF);
    uint32_t word_7  = (uint32_t)(b1 & 0xFFFFFFFF);
    uint32_t word_8  = (uint32_t)(b2 >> 96);
    uint32_t word_9  = (uint32_t)((b2 >> 64) & 0xFFFFFFFF);
    uint32_t word_10 = (uint32_t)((b2 >> 32) & 0xFFFFFFFF);
    uint32_t word_11 = (uint32_t)(b2 & 0xFFFFFFFF);
    uint32_t word_12 = (uint32_t)(b3 >> 96);
    uint32_t word_13 = (uint32_t)((b3 >> 64) & 0xFFFFFFFF);
    uint32_t word_14 = (uint32_t)((b3 >> 32) & 0xFFFFFFFF);

    uint32_t const_be_init = 0xBE;
    uint32_t const_port = 0x74726F70;
    uint32_t rolling_be = 0xBE;
    uint64_t mixed_state_64 = 0x6D75747363657273ULL;
    unsigned int word_temp_final;

    do {
        if ((round_idx & 1) != 0) {
            uint32_t arx_a = word_6 + const_port;
            uint32_t arx_b = ROR4(arx_a ^ word_12, 17);
            uint32_t arx_c = ROR4((word_9 + arx_b) ^ word_6, 21);
            uint32_t arx_d = arx_c + arx_a;
            uint32_t arx_e = word_5 + (uint32_t)mixed_state_64;
            
            word_temp_final = arx_d; 
            word_12 = ROR4(arx_b ^ arx_d, 23); 
            word_9 += word_12 + arx_b;
            
            uint32_t arx_f = ROR4(rolling_be ^ (word_5 + (uint32_t)mixed_state_64), 17);
            word_6 = ROR4(word_9 ^ arx_c, 26); 
            uint32_t arx_g = ROR4((word_8 + arx_f) ^ word_5, 21);
            
            mixed_state_64 = ((uint64_t)(arx_g + arx_e)) | (mixed_state_64 & 0xFFFFFFFF00000000ULL);
            
            uint32_t arx_h = word_4 + (uint32_t)(mixed_state_64 >> 32); 
            rolling_be = ROR4(arx_f ^ (uint32_t)mixed_state_64, 23); 
            word_8 += arx_f + rolling_be;
            
            uint32_t arx_i = ROR4(word_14 ^ arx_h, 17); 
            word_5 = ROR4(word_8 ^ arx_g, 26);
            
            b2 = (b2 & (((__uint128_t)0xFFFFFFFFULL << 48) | 0xFFFFFFFFULL)) | ((__uint128_t)word_8 << 96);
            b1 = (b1 & (((__uint128_t)0xFFFFFFFFULL << 48) | 0xFFFFFFFFULL)) | ((__uint128_t)word_5 << 64);
            
            uint32_t arx_j = ROR4((arx_i + word_11) ^ word_4, 21);
            uint32_t arx_k = arx_j + arx_h;
            uint32_t arx_l = word_7 + word_0;
            
            mixed_state_64 = ((uint64_t)arx_k << 32) | (uint32_t)mixed_state_64; 
            word_14 = ROR4(arx_i ^ arx_k, 23); 
            word_11 += arx_i + word_14;
            
            uint32_t arx_m = ROR4((word_7 + word_0) ^ word_13, 17); 
            b2 = (b2 & ((__uint128_t)0xFFFFFFFFFFFFFFFULL << 32)) | word_11;
            
            uint32_t arx_n = ROR4((word_10 + arx_m) ^ word_7, 21); 
            word_4 = ROR4(word_11 ^ arx_j, 26); 
            word_0 = arx_n + arx_l; 
            word_13 = ROR4((arx_m ^ (arx_n + arx_l)), 23); 
            word_10 += arx_m + word_13;
            
            b2 = (b2 & ((__uint128_t)0xFFFFFFFFULL << 64)) | ((((__uint128_t)word_9 << 32) | word_10) << 32) | (b2 & 0xFFFFFFFFULL);
            word_7 = ROR4(word_10 ^ arx_n, 26); 
            ((uint64_t *)&b1)[0] = ((uint64_t)word_6 << 32) | word_7;
        } else {
            uint32_t w18 = word_7 + const_port;
            uint32_t w19 = ROR4(w18 ^ const_be_init, 17);
            uint32_t w20 = ROR4(word_7 ^ (word_11 + w19), 21);
            
            word_temp_final = w20 + w18; 
            rolling_be = ROR4(w19 ^ (w20 + w18), 23); 
            word_11 += w19 + rolling_be;
            
            b2 = (b2 & ((__uint128_t)0xFFFFFFFFFFFFFFFULL << 32)) | word_11;
            
            uint32_t w21 = ROR4((word_6 + (uint32_t)mixed_state_64) ^ word_14, 17); 
            word_7 = ROR4(w20 ^ word_11, 26); 
            b1 = (b1 & ((__uint128_t)0xFFFFFFFFFFFFFFFULL << 32)) | word_7;
            
            uint32_t w22 = ROR4(word_6 ^ (word_10 + w21), 21); 
            mixed_state_64 = ((uint64_t)(w22 + word_6 + (uint32_t)mixed_state_64)) | (mixed_state_64 & 0xFFFFFFFF00000000ULL);
            
            word_14 = ROR4(w21 ^ (uint32_t)mixed_state_64, 23); 
            word_10 += w21 + word_14; 
            b2 = (b2 & (((__uint128_t)0xFFFFFFFFULL << 64) | 0xFFFFFFFFULL)) | ((__uint128_t)word_10 << 32);
            
            uint32_t w23 = ROR4((word_5 + (uint32_t)(mixed_state_64 >> 32)) ^ word_13, 17); 
            word_6 = ROR4(w22 ^ word_10, 26); 
            b1 = (b1 & (((__uint128_t)0xFFFFFFFFULL << 64) | 0xFFFFFFFFULL)) | ((__uint128_t)word_6 << 32);
            
            uint32_t w24 = ROR4(word_5 ^ (word_9 + w23), 21); 
            mixed_state_64 = (mixed_state_64 & 0xFFFFFFFFULL) | (((uint64_t)(mixed_state_64 >> 32) + w24 + word_5) << 32);
            
            word_13 = ROR4(w23 ^ (uint32_t)(mixed_state_64 >> 32), 23); 
            word_9 += (w23 + word_13); 
            b2 = (b2 & (((__uint128_t)0xFFFFFFFFULL << 48) | 0xFFFFFFFFULL)) | ((__uint128_t)word_9 << 64);
            
            uint32_t w27 = w24 ^ word_9;
            uint32_t w28 = ROR4((word_4 + word_0) ^ word_12, 17); 
            word_5 = ROR4(w27, 26); 
            b1 = (b1 & (((__uint128_t)0xFFFFFFFFULL << 48) | 0xFFFFFFFFULL)) | ((__uint128_t)word_5 << 64);
            
            uint32_t w29 = ROR4((word_8 + w28) ^ word_4, 21); 
            word_0 = w29 + (word_4 + word_0); 
            word_12 = ROR4(w28 ^ word_0, 23); 
            word_8 += word_12 + w28;
            
            b2 = (b2 & (((__uint128_t)0xFFFFFFFFULL << 48) | 0xFFFFFFFFULL)) | ((__uint128_t)word_8 << 96); 
            word_4 = ROR4(word_8 ^ w29, 26);
        }

        b1 = (b1 & 0xFFFFFFFFFFFFFFFFULL) | ((__uint128_t)word_4 << 96);

        if (round_idx) {
            uint32_t ws; 
            word_temp_final ^= ROR4((uint32_t)mixed_state_64, 29);
            mixed_state_64 = ((uint64_t)(ROR4((uint32_t)(mixed_state_64 >> 32), 29) ^ (uint32_t)mixed_state_64)) | (mixed_state_64 & 0xFFFFFFFF00000000ULL);
            
            ws = ROR4(word_7, 29) ^ word_0; 
            mixed_state_64 = (mixed_state_64 & 0xFFFFFFFFULL) | ((uint64_t)(ROR4(word_0, 29) ^ (uint32_t)(mixed_state_64 >> 32)) << 32);
            
            word_7 ^= ROR4(word_6, 29); 
            word_0 = ws; 
            word_6 ^= ROR4(word_5, 29); 
            ((uint64_t *)&b1)[0] = ((uint64_t)word_6 << 32) | word_7;
            
            word_5 ^= ROR4(word_4, 29); 
            word_4 ^= ROR4(word_11, 29); 
            ((uint64_t *)&b1)[1] = ((uint64_t)word_4 << 32) | word_5;
            
            word_11 ^= ROR4(word_10, 29); 
            word_10 ^= ROR4(word_9, 29); 
            ((uint64_t *)&b2)[0] = ((uint64_t)word_10 << 32) | word_11;
            
            word_9 ^= ROR4(word_8, 29); 
            word_8 ^= ROR4(rolling_be, 29); 
            ((uint64_t *)&b2)[1] = ((uint64_t)word_8 << 32) | word_9;
            
            const_be_init = ROR4(word_14, 29) ^ rolling_be; 
            temp_val_45 = ROR4(word_13, 29) ^ word_14; 
            rolling_be = const_be_init; 
            word_14 = temp_val_45;
            
            word_13 ^= ROR4(word_12, 29); 
            word_12 ^= ROR4(word_temp_final, 29);
        } else { 
            temp_val_45 = word_14; 
            const_be_init = rolling_be; 
        }

        const_port = word_temp_final; 
        ++round_idx;
    } while (round_idx < 6);

    state_ref = state_ptr; 
    loop_offset = 2; 
    blocks_remaining = 4;
    
    *((uint64_t *)&b3 + 1) = ((uint64_t)word_temp_final << 32) | (uint32_t)mixed_state_64;
    *(uint32_t *)((char *)&b0) = word_12; 
    *(uint64_t *)((char *)&b0 + 4) = ((uint64_t)temp_val_45 << 32) | word_13;
    *(uint32_t *)((char *)&b0 + 12) = const_be_init; 
    
    keystream_base_addr = output_keystream_addr;
    *((uint64_t *)&b3) = ((uint64_t)((mixed_state_64) >> 32) << 32) | word_0;
    
    for (int i = 0; i < 16; i++);

    // Offset calculations
    keystream_ptr_offset_4 = (char *)&b0 - output_keystream_addr + 4; 
    keystream_ptr_offset_2 = (char *)&b0 - output_keystream_addr + 2;
    keystream_ptr_offset_8 = (char *)&b0 - output_keystream_addr + 8; 
    keystream_cursor = output_keystream_addr + 10;
    
    state_ptr_offset_minus_6 = (int64_t)state_ptr - output_keystream_addr - 6; 
    state_ptr_offset_minus_6_v2 = -6 - output_keystream_addr;
    state_ptr_offset_minus_2 = (int64_t)state_ptr - output_keystream_addr - 2; 
    stream_cursor_81 = -6 - output_keystream_addr;
    state_ptr_offset_2 = (int64_t)state_ptr - output_keystream_addr + 2; 
    keystream_ptr_offset_0 = (char *)&b0 - output_keystream_addr;
    state_ptr_offset_minus_10 = (int64_t)state_ptr - output_keystream_addr - 10; 
    stream_cursor_87 = -2 - output_keystream_addr;
    stream_cursor_85 = 2 - output_keystream_addr; 
    state_ptr_offset_minus_10_v2 = -10 - keystream_base_addr; 
    stream_cursor_83 = -10 - keystream_base_addr;

    do {
        mixed_res_0 = ((uint8_t)loop_offset - 2) & 3;
        
        if (mixed_res_0 != 0) {
            if (mixed_res_0 == 1) {
                mixed_res_1 = *(uint32_t *)&keystream_ptr_offset_0[keystream_cursor - 10] + 2 * *(uint32_t *)(state_ptr_offset_minus_10 + keystream_cursor);
            } else {
                mixed_res_2 = *(uint32_t *)((char *)state_ref + state_ptr_offset_minus_10_v2 + keystream_cursor);
                mixed_res_3 = *(uint32_t *)&keystream_ptr_offset_0[keystream_cursor - 10];
                mixed_res_1 = (mixed_res_0 == 2) ? (mixed_res_2 + 16843009 * mixed_res_3) : (mixed_res_3 + mixed_res_2);
                state_ptr_offset_minus_6_v2 = stream_cursor_81;
            }
        } else {
            mixed_res_1 = (*(uint32_t *)&keystream_ptr_offset_0[keystream_cursor - 10] + *(uint32_t *)(state_ptr_offset_minus_10 + keystream_cursor)) ^ 0x5A5A5A5A;
        }
        
        *(uint32_t *)&keystream_ptr_offset_0[keystream_cursor - 10] = *(uint32_t *)(keystream_cursor - 10) = mixed_res_1;

        mix_idx_4 = (loop_offset - 1) % 4;
        if (mix_idx_4) {
            if (mix_idx_4 == 1) {
                mixed_res_5 = *(uint32_t *)&keystream_ptr_offset_4[keystream_cursor - 10] + 2 * *(uint32_t *)(state_ptr_offset_minus_6 + keystream_cursor);
            } else {
                mixed_res_6 = *(uint32_t *)((char *)state_ref + state_ptr_offset_minus_6_v2 + keystream_cursor);
                mix_idx_0 = *(uint32_t *)&keystream_ptr_offset_4[keystream_cursor - 10];
                mixed_res_5 = (mix_idx_4 == 2) ? (mixed_res_6 + 16843009 * mix_idx_0) : (mix_idx_0 + mixed_res_6);
            }
        } else {
            mixed_res_5 = (*(uint32_t *)&keystream_ptr_offset_4[keystream_cursor - 10] + *(uint32_t *)(state_ptr_offset_minus_6 + keystream_cursor)) ^ 0x5A5A5A5A;
        }
        
        *(uint16_t *)(keystream_cursor - 6) = (uint16_t)mixed_res_5; 
        *(uint32_t *)&keystream_ptr_offset_4[keystream_cursor - 10] = mixed_res_5;
        *(uint8_t *)(keystream_cursor - 4) = (uint8_t)((mixed_res_5 >> 16) & 0xFF); 
        *(uint8_t *)(keystream_cursor - 3) = (uint8_t)((mixed_res_5 >> 24) & 0xFF);

        mix_idx_5 = loop_offset % 4;
        if (mix_idx_5) {
            if (mix_idx_5 == 1) {
                mixed_res_7 = *(uint32_t *)&keystream_ptr_offset_8[keystream_cursor - 10] + 2 * *(uint32_t *)(state_ptr_offset_minus_2 + keystream_cursor);
            } else {
                mixed_res_3 = *(uint32_t *)((char *)state_ref + stream_cursor_87 + keystream_cursor);
                mix_idx_1 = *(uint32_t *)&keystream_ptr_offset_8[keystream_cursor - 10];
                mixed_res_7 = (mix_idx_5 == 2) ? (mixed_res_3 + 16843009 * mix_idx_1) : (mix_idx_1 + mixed_res_3);
            }
        } else {
            mixed_res_7 = (*(uint32_t *)&keystream_ptr_offset_8[keystream_cursor - 10] + *(uint32_t *)(state_ptr_offset_minus_2 + keystream_cursor)) ^ 0x5A5A5A5A;
        }
        
        *(uint16_t *)(keystream_cursor - 2) = (uint16_t)mixed_res_7; 
        *(uint32_t *)&keystream_ptr_offset_8[keystream_cursor - 10] = mixed_res_7;
        *(uint8_t *)keystream_cursor = (uint8_t)((mixed_res_7 >> 16) & 0xFF); 
        *(uint8_t *)(keystream_cursor + 1) = (uint8_t)((mixed_res_7 >> 24) & 0xFF);

        mix_idx_6 = (loop_offset + 1) % 4;
        if (mix_idx_6) {
            if (mix_idx_6 == 1) {
                mixed_res_4 = *(uint32_t *)&keystream_ptr_offset_2[keystream_cursor] + 2 * *(uint32_t *)(state_ptr_offset_2 + keystream_cursor);
                *(uint32_t *)&keystream_ptr_offset_2[keystream_cursor] = mixed_res_4;
            } else {
                mix_idx_2 = *(uint32_t *)((char *)state_ref + stream_cursor_85 + keystream_cursor);
                mix_idx_3 = *(uint32_t *)&keystream_ptr_offset_2[keystream_cursor];
                mixed_res_4 = (mix_idx_6 == 2) ? (mix_idx_2 + 16843009 * mix_idx_3) : (mix_idx_3 + mix_idx_2);
                *(uint32_t *)&keystream_ptr_offset_2[keystream_cursor] = mixed_res_4;
            }
        } else {
            mixed_res_4 = (*(uint32_t *)&keystream_ptr_offset_2[keystream_cursor] + *(uint32_t *)(state_ptr_offset_2 + keystream_cursor)) ^ 0x5A5A5A5A;
            *(uint32_t *)&keystream_ptr_offset_2[keystream_cursor] = mixed_res_4;
        }

        *(uint32_t *)(keystream_cursor + 2) = mixed_res_4;
        state_ptr_offset_minus_6_v2 = stream_cursor_81; 
        loop_offset += 4; 
        state_ptr_offset_minus_10_v2 = stream_cursor_83; 
        keystream_cursor += 16;
    } while (--blocks_remaining);
    
    return 0;
}

void qmemcpy(void *dst, const void *src, size_t size) { 
    memcpy(dst, src, size); 
}

int64_t main_decryption_logic(int64_t output_context, uint64_t *input_buffer_props, uint64_t *key_material_info, int64_t nonce_val, int initial_xor_key) {
    int64_t processed_byte_count = 0;
    int64_t outer_loop_iter = 2;
    size_t total_data_len = input_buffer_props[2];
    char *allocated_result_buf, *keystream_buffer;
    uint64_t key_len_check = key_material_info[3];
    uint64_t current_byte_offset = 0;
    uint64_t block_counter, max_blocks;
    int step_indicator = 2, mix_val, mix_idx, mix_pos, xor_seed_val, nonce_low;
    int128_t internal_state[4] = {0};

    if (!(keystream_buffer = (char *)malloc(64))) {
        return -1;
    }
    memset(keystream_buffer, 0, 64);
    memset((void *)output_context, 0, 32);

    if (total_data_len) {
        allocated_result_buf = (char *)malloc(total_data_len);
        *(uint64_t *)output_context = (uint64_t)allocated_result_buf;
        *(uint64_t *)(output_context + 16) = (uint64_t)(allocated_result_buf + total_data_len);
        memset(allocated_result_buf, 0, total_data_len);
        *(uint64_t *)(output_context + 8) = (uint64_t)(allocated_result_buf + total_data_len);
    }
    
    qmemcpy(&internal_state[0], "portsrecstumscom", 16);

    do {
        for (int j = 0; j < 4; j++) {
            uint64_t *k_ptr = (key_len_check > 15) ? (uint64_t *)(*key_material_info) : key_material_info;
            
            uint32_t val;
            if (j % 2 == 0) {
                val = (uint8_t)(k_ptr[current_byte_offset / 8 + j / 2]) | 
                      ((uint8_t)(k_ptr[current_byte_offset / 8 + j / 2] >> 8) << 8) | 
                      ((uint16_t)(k_ptr[current_byte_offset / 8 + j / 2] >> 16) << 16);
            } else {
                val = (uint8_t)(k_ptr[current_byte_offset / 8 + j / 2] >> 32) | 
                      ((uint8_t)(k_ptr[current_byte_offset / 8 + j / 2] >> 40) << 8) | 
                      ((uint16_t)(k_ptr[current_byte_offset / 8 + j / 2] >> 48) << 16);
            }
            
            int sel;
            switch (j) {
                case 0: sel = ((uint8_t)step_indicator - 2) & 3; break;
                case 1: sel = (step_indicator - 1) % 4; break;
                case 2: sel = step_indicator % 4; break;
                default: sel = (step_indicator + 1) % 4; break;
            }
            
            int res;
            if (sel == 0)      res = initial_xor_key ^ val;
            else if (sel == 1) res = (val >> 8) + val;
            else if (sel == 2) res = ROR4(val, 29);
            else               res = ~val;
            
            ((uint32_t *)&internal_state[current_byte_offset / 16 + 1])[j] = res;
        }
        step_indicator += 4; 
        current_byte_offset += 16;
    } while (--outer_loop_iter);

    max_blocks = (uint64_t)(input_buffer_props[2] + 63ULL) >> 6; 
    xor_seed_val = (unsigned int)initial_xor_key;
    
    for (block_counter = 0; block_counter < max_blocks; block_counter++) {
        nonce_low = (int)nonce_val;
        ((uint32_t *)&internal_state[3])[0] = (uint32_t)block_counter + (uint8_t)initial_xor_key;
        ((uint32_t *)&internal_state[3])[1] = nonce_low;
        ((uint32_t *)&internal_state[3])[2] = (int)(nonce_val >> 32);
        ((uint32_t *)&internal_state[3])[3] = xor_seed_val;
        
        cipher_init(internal_state, (int64_t)keystream_buffer);
        
        for (mix_val = 0, mix_idx = 2; mix_val < 64; mix_val += 4, mix_idx += 4) {
            keystream_buffer[mix_val] ^= keystream_buffer[(mix_idx - 1) % 64];
            char mc = keystream_buffer[mix_val];
            keystream_buffer[mix_val + 1] ^= keystream_buffer[mix_idx % 64];
            mix_pos = (mix_idx + 1) % 64;
            keystream_buffer[mix_val + 2] ^= keystream_buffer[mix_pos];
            keystream_buffer[mix_val + 3] ^= mc;
        }
        
        uint64_t remaining_bytes = input_buffer_props[2] - processed_byte_count * 8;
        uint64_t bx = (remaining_bytes < 64) ? remaining_bytes : 64;
        
        for (uint64_t k = 0; k < bx; k++) {
            uint64_t *kd = (input_buffer_props[3] > 15) ? (uint64_t *)input_buffer_props[0] : input_buffer_props;
            *((uint8_t *)(processed_byte_count * 8 + *((uint64_t *)output_context) + k)) = keystream_buffer[k] ^ *((uint8_t *)&kd[processed_byte_count] + k);
        }
        processed_byte_count += 8;
    }
    
    free(keystream_buffer); 
    return 0;
}

int hex_to_bytes(const char* s, uint8_t* b, size_t m) {
    size_t l = strlen(s); 
    if (l % 2 || l / 2 > m) return 0;
    for (size_t i = 0; i < l; i += 2) {
        sscanf(s + i, "%2hhx", &b[i / 2]);
    }
    return l / 2;
}

int main() {
    const char *enc[] = {
        "18fd08c587205d22625c9de7", 
        "05e9238cd4097318664a8ab55841bbd4", 
        "00ca2181c21a0f0f67408fe67952"
    };
    
    uint8_t key_blob[] = {
        0x67, 0x77, 0x32, 0x51, 0x66, 0x6F, 0x4A, 0x6D, 
        0x45, 0x72, 0x37, 0x7A, 0x6D, 0x52, 0x6C, 0x61, 
        0x48, 0x70, 0x51, 0x30, 0x6E, 0x6D, 0x68, 0x6A, 
        0x59, 0x32, 0x54, 0x55, 0x4B, 0x33, 0x6C, 0x39
    };
    
    for (int i = 0; i < 3; i++) {
        size_t len = strlen(enc[i]) / 2;
        int64_t ctx = (int64_t)malloc(32); 
        uint8_t *dat = malloc(len);
        
        hex_to_bytes(enc[i], dat, len);
        
        uint64_t ip[4] = {(uint64_t)dat, 0, len, 16};
        uint64_t kp[4] = {(uint64_t)key_blob, 0, 0, 32};
        
        main_decryption_logic(ctx, ip, kp, 0x807060504030201, 0xCAFEBABE);
        
        uint8_t *res = (uint8_t *)(*(uint64_t *)ctx);
        if (res) { 
            printf("%s --> ", enc[i]); 
            for (size_t k = 0; k < len; k++) {
                putchar(res[k]);
            }
            puts(""); 
            free(res); 
        }
        
        free(dat); 
        free((void*)ctx);
    }
    
    return 0;
}
