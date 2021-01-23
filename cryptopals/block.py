import base64
import binascii
import string
import cryptopals.basic as basic
from Crypto.Cipher import AES
from Crypto import Random

class Oracle:
    def __init__(self, secret, pre=b''):
        self.key = gen_random_aes_key()
        self.secret = secret
        self.prepend = pre
    def encrypt(self, plaintext: bytes) -> bytes:
        return aes_ecb_encrypt(self.prepend + plaintext + self.secret, self.key)

def gen_random_aes_key(keysize: int=16) -> bytes:
    return Random.get_random_bytes(keysize)

# Default block size for AES-ECB is 16 bytes.
def is_ecb(ciphertext: bytes, blocksize: int=16) -> bool:
    if len(ciphertext) % blocksize != 0:
        raise ValueError('Ciphertext length is not a multiple of the blocksize.')
    num_blocks = len(ciphertext) // blocksize
    blocks = [ciphertext[i*blocksize:(i+1)*blocksize] for i in range(num_blocks)]
    # If there are all blocks are unique, this likely isn't AES-ECB. If there are any non-unique blocks, then
    # this has probably been encrypted under AES-ECB.
    return len(set(blocks)) != num_blocks

def ecb_find_block_size(oracle: Oracle) -> int:
    # Just keep adding bytes until we jump into another block. Take the difference in ciphertext lengths.
    plaintext = b''
    old_ctext = oracle.encrypt(plaintext)
    for i in range(40):
        plaintext += b'A'
        new_ctext = oracle.encrypt(plaintext)
        if len(new_ctext) != len(old_ctext):
            return len(new_ctext) - len(old_ctext)
    return -1 # couldn't find the block size

# Padding function.
def pkcs7_pad(plaintext: bytes, blocksize: int=16) -> bytes:
    padding_length = blocksize - len(plaintext) % blocksize
    return plaintext + bytes([padding_length])*padding_length

def pkcs7_unpad(plaintext: bytes, blocksize: int=16) -> bytes:
    padding_char = plaintext[-1]
    # If the value of the last character is greater than the blocksize, then it's not a padding character.
    if padding_char > blocksize:
        return plaintext
    for i in range(padding_char):
        if plaintext[-i-1] != padding_char:
            raise ValueError('Plaintext has invalid padding')
    return plaintext[:-padding_char]

def find_padding_length(oracle: Oracle, blocksize: int=16) -> int:
    padding = b''
    starting_length = len(oracle.encrypt(padding))
    for i in range(blocksize):
        padding += b'A'
        if len(oracle.encrypt(padding)) != starting_length:
            return i

def aes_cbc_encrypt(plaintext, key, iv: bytes, blocksize: int=16) -> bytes:
    # This is a helper function that just encrypts one 128 bit block 
    if len(iv) != len(key):
        raise ValueError('Length of key and IV need to match otherwise\
        encryption will not work correctly.')
    def aes_cbc_encrypt_block(plaintext, chain, key: bytes) -> bytes:
        x = basic.fixed_xor(plaintext, chain)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(x)
    padded = pkcs7_pad(plaintext)
    num_blocks = len(padded) // blocksize
    prev_ciphertext = iv
    c = b''
    for i in range(num_blocks):
        c += aes_cbc_encrypt_block(padded[i*blocksize:(i+1)*blocksize],prev_ciphertext, key)
        prev_ciphertext = c[i*blocksize:(i+1)*blocksize]
    return c
    
def aes_cbc_decrypt(ciphertext, key, iv: bytes, blocksize: int=16, remove_padding: bool=False) -> bytes:
    def aes_cbc_decrypt_block(ciphertext, chain, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        x = cipher.decrypt(ciphertext)
        return basic.fixed_xor(x, chain)
    prev_ciphertext = iv
    num_blocks = len(ciphertext) // blocksize
    p = b''
    for i in range(num_blocks+1):
        p += aes_cbc_decrypt_block(ciphertext[i*blocksize:(i+1)*blocksize],prev_ciphertext,key)
        prev_ciphertext = ciphertext[i*blocksize:(i+1)*blocksize]
    if remove_padding:
        p = pkcs7_unpad(p)
    return p

# These are just functions so ECB can encrypt irregular sized data.
def aes_ecb_encrypt(plaintext, key: bytes, blocksize: int=16) -> bytes:
    padded = pkcs7_pad(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(padded)

def aes_ecb_decrypt(ciphertext, key: bytes, remove_padding=True) -> bytes:
     cipher = AES.new(key, AES.MODE_ECB)
     return cipher.decrypt(ciphertext)
     p = cipher.decrypt(ciphertext)
     if remove_padding:
         return pkcs7_unpad(p)
     else:
        return p
