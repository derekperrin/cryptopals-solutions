from cryptopals import block
from cryptopals import basic
from Crypto import Random
import base64

def bitflipping_oracle_encrypt(plaintext, aes_key, iv: bytes) -> bytes:
    prepend = b'comment1=cooking%20MCs;userdata='
    append = b';comment2=%20like%20a%20pound%20of%20bacon'
    plaintext = plaintext.replace(b'=',b'"="')
    plaintext = plaintext.replace(b';',b'";"')
    return block.aes_cbc_encrypt(prepend + plaintext + append, key, iv)

# This just returns True or False to see if the data is an admin.
def bitflipping_oracle_decrypt(ciphertext, aes_key, iv: bytes) -> bool:
    plaintext = block.aes_cbc_decrypt(ciphertext, aes_key, iv)
    print(plaintext)
    return b';admin=true;' in plaintext

if __name__ == '__main__':
    key = block.gen_random_aes_key()
    iv = Random.get_random_bytes(16)
    ciphertext = bitflipping_oracle_encrypt(b'YELLOW SUBMARINE',key,iv)
    differing_bits = basic.fixed_xor(b'YELLOW SUBMARINE', b';admin=true;4444') # pad so it's the same length.
    new_block = basic.fixed_xor(differing_bits, ciphertext[16:32])
    ciphertext = ciphertext[0:16] + new_block + ciphertext[32:]
    bitflipping_oracle_decrypt(ciphertext, key, iv)
    base64.b64decode('MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==')
