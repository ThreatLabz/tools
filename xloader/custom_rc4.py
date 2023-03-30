#!/usr/bin/env python3

# Author: Zscaler ThreatLabz
# Blog reference: https://www.zscaler.com/blogs/security-research/technical-analysis-xloaders-code-obfuscation-version-43
# Description: This is a Python reimplementation of Xloader's custom RC4 algorithm
# Follow us on Twitter: @ThreatLabz

def rc4(data, key):
    s = list(range(256))
    j = 0
    out = []
    # KSA Phase
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    # PRGA Phase
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(char ^ s[(s[i] + s[j]) % 256])
    return bytes(out)

def custom_rc4_backward_forward_sub_layers(encdata):
    encdata = list(encdata)
    lencdata = len(encdata)
    # backward sub
    p1 = lencdata - 2
    counter = lencdata - 1
    while True:
        encdata[p1] = 0xff & (encdata[p1] - encdata[p1 + 1])
        p1 -= 1
        counter -= 1
        if not counter:
            break
    # forward sub
    p1 = 0
    counter = lencdata - 1
    while True:
        encdata[p1] = 0xff & (encdata[p1] - encdata[p1 + 1])
        p1 += 1
        counter -= 1
        if not counter:
            break
    return bytes(encdata)

def custom_rc4(encdata, key):
    # backward / forward sub layer 1
    encdata = custom_rc4_backward_forward_sub_layers(encdata)
    # rc4
    encdata = rc4(list(encdata), list(key))
    # backward / forward sub layer 2
    encdata = custom_rc4_backward_forward_sub_layers(encdata)
    return encdata
