# Example Python script to decode subdomains in DNS MX queries and responses

def decode(table:str, encoded:str) -> bytearray:
    table_len = len(table)

    decoded = bytearray()

    # Data is split into 60 byte "subdomains". These don't represent
    # data so we discard them
    chars = list(encoded.replace(".", ""))

    # Two alphanumeric characters make one byte
    for i in range(0, len(chars), 2):
        char1 = chars[i]
        char2 = chars[i+1]

        lo_byte = lookup(table, char1) - ((i // 2) % table_len)
        hi_byte = lookup(table, char2) - ((i // 2) % table_len)

        # Prevent negative values
        if lo_byte < 0:
            lo_byte += table_len
        if hi_byte < 0:
            hi_byte += table_len

        decoded_byte = ((hi_byte & 0xf) << 4) + (lo_byte & 0xf)
        decoded.append(decoded_byte)

    return decoded

def lookup(table:str, char:str) -> int:
    chars = list(table)
    for i, c in enumerate(chars):
        if char == c:
            return i
    return None

if __name__ == "__main__":
    table = "3qogr7dx8j60v4yzbe9wumthcpl12an5kfis"
    c2_domain = "litterbolo.com"

    dns_mx_resp = "33qqooggxr77mdxx88jj6600ev44yyzz9bee99wwuu.litterbolo.com"
    encoded = dns_mx_resp.removesuffix(c2_domain)
    decoded = decode(table, encoded)
    print(decoded)

