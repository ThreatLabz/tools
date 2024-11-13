def adc(value_1: int, value_2: int):
    out = value_1 + value_2
    first_checksum_32bit = out & 0xffffffff
    carry_out = 1 if out > 0xffffffff else 0
    return first_checksum_32bit, carry_out

def processing(input_data: bytes, is_lowercase_applied: bool):
    skip_iteration_list = [1, 4, 5, 7, 8, 40]
    counter = len(input_data)
    data_index = 0
    first_result = 0xA9858C82
    second_result = 0x63538140   
    carry_start = 0
    while counter:
        character = input_data[data_index];
        data_index += 1
        if is_lowercase_applied and 0x41 <= character <= 0x5A:
            lowercase_value = 32;
        else:
            lowercase_value = 0;
        adder = first_result ^ ((lowercase_value + character) & 0xffffffff)
        first_result = 0;
        prev_result = second_first_result;
        internal_iteration = 0;
        second_result = 0;
        carry_start = 0
        while internal_iteration <= 0x28 :
            if not internal_iteration or internal_iteration in skip_iteration_list:        
                first_result, carry_start = adc(first_result, adder)
                second_result += prev_result + carry_start
                second_result &= 0xffffffff
            internal_iteration += 1
            is_negative = adder >> 31;
            adder *= 2;
            adder &= 0xffffffff
            prev_result = is_negative | (( 2 * prev_result) & 0xffffffff);
            prev_result &= 0xffffffff
        counter -= 1
 return first_result, second_result

