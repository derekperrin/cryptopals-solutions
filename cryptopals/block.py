import base64
import binascii
import string
import cryptopals.basic as basic
from Crypto.Cipher import AES

# Default block size for AES-ECB is 16 bytes.
def is_ecb(ciphertext: bytes, blocksize: int=16) -> bool:
    if len(ciphertext) % blocksize != 0:
        raise ValueError('Ciphertext length is not a multiple of the blocksize.')
    num_blocks = len(ciphertext) // blocksize
    blocks = [ciphertext[i*blocksize:(i+1)*blocksize] for i in range(num_blocks)]
    # If there are all blocks are unique, this likely isn't AES-ECB. If there are any non-unique blocks, then
    # this has probably been encrypted under AES-ECB.
    return len(set(blocks)) != num_blocks

# Padding function.
def pkcs7(plaintext: bytes, blocksize: int=16) -> bytes:
    padding_length = blocksize - len(plaintext) % blocksize
    if padding_length == blocksize:
        return plaintext
    return plaintext + bytes([padding_length])*padding_length

# def ecb_encrypt(plaintext,key: bytes) -> bytes:
#     cipher = AES.new(key, AES.MODE_ECB)
#     return cipher.encrypt(plaintext)
# 
# def ecb_decrypt(ciphertext,key: bytes) -> bytes:
#     cipher = AES.new(key, AES.MODE_ECB)
#     return cipher.decrypt(ciphertext)

def aes_cbc_encrypt(plaintext, key, iv: bytes, blocksize: int=16) -> bytes:
    # This is a helper function that just encrypts one 128 bit block 
    def aes_cbc_encrypt_block(plaintext, chain, key: bytes) -> bytes:
        x = basic.fixed_xor(plaintext, chain)
        return aes_ecb_encrypt(x,key)
    padded = pkcs7(plaintext)
    num_blocks = len(padded) // blocksize
    prev_ciphertext = iv
    c = b''
    for i in range(num_blocks):
        c += aes_cbc_encrypt_block(padded[i*blocksize:(i+1)*blocksize],prev_ciphertext, key)
        prev_ciphertext = c[i*blocksize:(i+1)*blocksize]
    return c
    
# TODO: Remove the padding after decryption. Should probably write a function for this.
def aes_cbc_decrypt(ciphertext, key, iv: bytes, blocksize: int=16) -> bytes:
    def aes_cbc_decrypt_block(ciphertext, chain, key: bytes) -> bytes:
        x = aes_ecb_decrypt(ciphertext,key)
        return basic.fixed_xor(x, chain)
    prev_ciphertext = iv
    num_blocks = len(ciphertext) // blocksize
    p = b''
    for i in range(num_blocks):
        p += aes_cbc_decrypt_block(ciphertext[i*blocksize:(i+1)*blocksize],prev_ciphertext,key)
        prev_ciphertext = ciphertext[i*blocksize:(i+1)*blocksize]
    return p     

# These are just functions so ECB can encrypt irregular sized data.
def aes_ecb_encrypt(plaintext, key: bytes, blocksize: int=16) -> bytes:
    padded = pkcs7(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(padded)

def aes_ecb_decrypt(ciphertext, key: bytes) -> bytes:
     cipher = AES.new(key, AES.MODE_ECB)
     return cipher.decrypt(ciphertext)
