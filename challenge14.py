from cryptopals import block
from cryptopals.block import Oracle as Oracle
from Crypto import Random
from Crypto.Random import random
import base64

def find_starting_block(oracle: Oracle, blocksize: int=16) -> int:
    attacker = b'A'
    original_ciphertext = oracle.encrypt(b'')
    new_ciphertext = oracle.encrypt(attacker)
    for i in range(len(original_ciphertext)):
        if original_ciphertext[i] != new_ciphertext[i]:
            # Found the block!
            return i // blocksize

def find_filling_number(oracle: Oracle, start_block: int, blocksize: int=16) -> int:
    attacker = b''
    target_slice = slice(start_block*blocksize,(start_block+1)*blocksize)
    previous_block = oracle.encrypt(attacker)[target_slice]
    for i in range(blocksize + 1):
        attacker += b'A'
        current_block = oracle.encrypt(attacker)[target_slice]
        if current_block == previous_block:
            return i % blocksize # We do this in case we actually started at the beginning of a block.
        previous_block = current_block

def recover_one_byte_hard(oracle: Oracle, known_plaintext: bytes,
                          blocksize, filling_number, offset: int) -> bytes:
    prepend_plaintext_length = (len(known_plaintext) % blocksize)
    prepend = b'A' * (filling_number + blocksize - 1 - prepend_plaintext_length)
    target = oracle.encrypt(prepend)
    target_block_number = offset + len(known_plaintext) // blocksize
    target_slice = slice(target_block_number*blocksize, (target_block_number + 1)*blocksize)
    target_block = target[target_slice]
    for i in range(256):
        if oracle.encrypt(prepend + known_plaintext + bytes([i]))[target_slice] == target_block:
            return bytes([i])
    return b'0'

def byte_at_a_time_ecb_hard(oracle: Oracle, filling_number, offset: int) -> bytes:
    if not block.is_ecb(oracle.encrypt(b'A'*64)):
        raise ValueError('Oracle needs to be in ECB mode.')
    blocksize = block.ecb_find_block_size(oracle)
    known_plaintext = b''
    ciphertext = oracle.encrypt(known_plaintext)
    # This is just to advance the starting point after the first block is filled.
    offset += (filling_number + 15) // 16
    padding_length = block.find_padding_length(oracle) + (offset*blocksize - filling_number)
    for _ in range(len(ciphertext) - padding_length):
        known_plaintext += recover_one_byte_hard(oracle, known_plaintext, blocksize, filling_number, offset)
    return known_plaintext

if __name__ == '__main__':
    unknown_string = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    # We'll randomly prepend up to 100 bytes. Doesn't matter what they are. We'll also generate a key and oracle
    prepend = Random.get_random_bytes(random.randint(1,100))
    key = block.gen_random_aes_key()
    oracle = Oracle(unknown_string,prepend)

    offset = find_starting_block(oracle)
    x = find_filling_number(oracle, offset)

    print(byte_at_a_time_ecb_hard(oracle, x, offset).decode())
