import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import ChaCha20

def decrypt_blackbyte_v2_go(private_key_bytes, data):
    priv_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    pub_bytes = data[-32:]
    peer_public_key = X25519PublicKey.from_public_bytes(pub_bytes)
    shared_key = priv_key.exchange(peer_public_key)
    chacha_key = hashlib.sha256(shared_key).digest()
    nonce_hash = hashlib.sha256(chacha_key).digest()
    nonce = nonce_hash[10:22]
    cc = cc = ChaCha20.new(key=chacha_key, nonce=nonce)
    return cc.decrypt(data[:-32])
    
def decrypt_blackbyte_v2_go_filename(filename):
    filename = base64.decodebytes(filename)
    out = bytearray()
    xor_key = b"fuckyou123"
    for j,i in enumerate(filename):
        out.append( xor_key[j%len(xor_key)] ^ i)
    return out

