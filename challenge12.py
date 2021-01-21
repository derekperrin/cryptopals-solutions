from cryptopals import block
from cryptopals.block import Oracle as Oracle
import base64

# This will recover one more byte from our plaintext.
def recover_one_byte(oracle: Oracle, known_plaintext: bytes, blocksize: int=16) -> bytes:
    prepend_plaintext_length = (len(known_plaintext) % blocksize)
    prepend = b'A'*(blocksize - 1 - prepend_plaintext_length)
    target = oracle.encrypt(prepend)
    target_block_number = len(known_plaintext) // blocksize
    target_slice = slice(target_block_number*blocksize,(target_block_number + 1)*blocksize)
    target_block = target[target_slice]
    for i in range(256):        
        if oracle.encrypt(prepend + known_plaintext + bytes([i]))[target_slice] == target_block:
            return bytes([i])
    return b'ERROR'

def byte_at_a_time_ecb(oracle: Oracle) -> bytes:
    # We need to confirm this is indeed ECB.
    if not block.is_ecb(oracle.encrypt(b'A'*64)):
        raise ValueError('Oracle needs to be in ECB mode.')
    blocksize = block.ecb_find_block_size(oracle)
    known_plaintext = b''
    ciphertext = oracle.encrypt(known_plaintext)
    padding_length = block.find_padding_length(oracle)
    for i in range(len(ciphertext) - padding_length):
        known_plaintext += recover_one_byte(oracle, known_plaintext, blocksize)
    return known_plaintext    

if __name__ == '__main__':
    unknown_string = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    # Verify we can find the proper block size
    oracle = Oracle(unknown_string)
    if block.ecb_find_block_size(oracle) == 16:
        print('Able to find correct block size of 16 bytes.')
    else:
        print('Unable to find the correct block size of 16 bytes.')

    # Verify we can test if it is indeed in ECB
    if block.is_ecb(oracle.encrypt(b'A'*64)):
        print('is_ecb test succeeded')
    else:
        print('is_ecb test failed.')

    oracle = Oracle(unknown_string)
    ptext = byte_at_a_time_ecb(oracle)
    print(ptext.decode())
