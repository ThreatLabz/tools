#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Blog reference: https://www.zscaler.com/blogs/security-research/technical-analysis-xloaders-code-obfuscation-version-43
# Description: This is a Python reimplementation of Xloader's custom buffer decryption algorithm
# Follow us on Twitter: @ThreatLabz

def custom_buffer_decryption_algorithm_1(code, end):

    tbl1 = {
        0 : (2, 4, 6),  10 : (2, 4, 6),  20 : (1, 1, 2),  32 : (2, 4, 6),  40 : (2, 4, 6),  50 : (2, 4, 6),  60 : (1, 1, 2),  102: (0, 0, 1),  128: (2, 1, 3),
        1 : (2, 4, 6),  11 : (2, 4, 6),  21 : (1, 4, 5),  33 : (2, 4, 6),  41 : (2, 4, 6),  51 : (2, 4, 6),  61 : (1, 4, 5),  104: (1, 4, 5),  129: (2, 4, 6),
        2 : (2, 4, 6),  12 : (1, 1, 2),  24 : (2, 4, 6),  34 : (2, 4, 6),  42 : (2, 4, 6),  52 : (1, 1, 2),                   105: (2, 6, 10),
        3 : (2, 4, 6),  13 : (1, 4, 5),  25 : (2, 4, 6),  35 : (2, 4, 6),  43 : (2, 4, 6),  53 : (1, 4, 5),                   107: (2, 6, 7),
        4 : (1, 1, 2),  15 : (0, 0, 6),  26 : (2, 4, 6),  36 : (1, 1, 2),  44 : (1, 1, 2),  56 : (2, 4, 6),
        5 : (1, 4, 5),  16 : (2, 4, 6),  27 : (2, 4, 6),  37 : (1, 4, 5),  45 : (1, 4, 5),  57 : (2, 4, 6),
        8 : (2, 4, 6),  17 : (2, 4, 6),  28 : (1, 1, 2),                   48 : (2, 4, 6),  58 : (2, 4, 6),
        9 : (2, 4, 6),  18 : (2, 4, 6),  29 : (1, 4, 5),                   49 : (2, 4, 6),  59 : (2, 4, 6),
                        19 : (2, 4, 6),

        160 : (1, 4, 5),  170 : (0, 1, 1),  180 : (1, 1, 2),  190 : (1, 4, 5),  132 : (2, 4, 6),  141 : (2, 4, 6),  168 : (1, 1, 2),
        161 : (1, 4, 5),  171 : (0, 1, 1),  181 : (1, 1, 2),  191 : (1, 4, 5),  133 : (2, 4, 6),  143 : (2, 4, 6),  169 : (1, 4, 5),
        162 : (1, 4, 5),  172 : (0, 1, 1),  182 : (1, 1, 2),                    134 : (2, 4, 6),  144 : (0, 1, 1),
        163 : (1, 4, 5),  173 : (0, 1, 1),  183 : (1, 1, 2),                    135 : (2, 4, 6),
        164 : (0, 1, 1),  174 : (0, 1, 1),  184 : (1, 4, 5),                    136 : (2, 4, 6),
        165 : (0, 1, 1),  175 : (0, 1, 1),  185 : (1, 4, 5),                    137 : (2, 4, 6),
        166 : (0, 1, 1),  176 : (1, 1, 2),  186 : (1, 4, 5),                    138 : (2, 4, 6),
        167 : (0, 1, 1),  177 : (1, 1, 2),  187 : (1, 4, 5),                    139 : (2, 4, 6),
                          178 : (1, 1, 2),  188 : (1, 4, 5),
                          179 : (1, 1, 2),  189 : (1, 4, 5),

        192 : (2, 4, 7),  208 : (2, 4, 6),  232 : (0, 0, 5),  242 : (0, 1, 1),
        193 : (2, 4, 7),  209 : (2, 4, 6),  233 : (0, 0, 5),  246 : (2, 1, 3),
        194 : (1, 2, 3),                    235 : (0, 0, 2),  247 : (2, 4, 6),
        195 : (0, 1, 1),
    }

    tbl2 = {
        102: {
            104: (2, 2, 4),
            106: (1, 2, 3),
            184: (2, 2, 4),
        },
        128: {
            5: (2, 4, 7),
        },
        255: {
            53: (2, 4, 6),
        }
    }

    dec = b""
    i = 0
    while True:
        if code[i] == 106:
            j = code[i+1]
            dec += code[j:j+4]
            i += 2
        elif code[i] == 131:
            j = code[i+2]
            dec += code[j:j+4]
            i += 3
        elif ((code[i]-64)&0xff) > 31 and ((code[i]-112)&0xff) > 15 and code[i] in tbl2.keys() and code[i+1] in tbl2[code[i]].keys():
            op = tbl2[code[i]][code[i+1]]
            dec += code[i+op[0]:i+op[0]+op[1]]
            i += op[2]
        elif ((code[i]-64)&0xff) > 31 and ((code[i]-112)&0xff) > 15 and code[i] in tbl1.keys():
            op = tbl1[code[i]]
            dec += code[i+op[0]:i+op[0]+op[1]]
            i += op[2]
        elif ((code[i]-64)&0xff) > 31:
            i += 2
        else:
            dec += code[i:i+1]
            i += 1
        if len(dec) >= end:
            return dec