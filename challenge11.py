from cryptopals import block
import base64

from Crypto import Random
from Crypto.Random import random as random

def encryption_oracle(msg: bytes, a: int=5, b: int=10, keysize: int=16) -> tuple:
    pre = Random.get_random_bytes(random.randint(a,b))
    post = Random.get_random_bytes(random.randint(a,b))
    key = block.gen_random_aes_key()
    iv = Random.get_random_bytes(keysize)
    msg = pre + msg + post
    if random.randint(0,1) > 0:
        return block.aes_ecb_encrypt(msg, key), 'ECB'
    else:
        return block.aes_cbc_encrypt(msg, key, iv), 'CBC'

if __name__ == '__main__':
    detection = True
    for i in range(100):
        c, mode = encryption_oracle(b'A'*64)
        guess = block.is_ecb(c)
        if (guess and mode == 'ECB') or (not guess and mode == 'CBC'):
            continue
        else:
            detection = False
            break
    print('Able to detect ECB/CBC mode 100% of the time? ', detection)    

