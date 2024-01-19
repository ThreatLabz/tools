def str_deobfuscate(enc_bin, enc_key):
  res = ''
  for i, element in enumerate(enc_bin):
    res += chr( ((element ^ 0xff) & (enc_key[i % len(enc_key)])) | (~(enc_key[i % len(enc_key)]) & element))
  return res

