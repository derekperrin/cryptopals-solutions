from cryptopals import block
from typing import Tuple
from Crypto import Random
from Crypto.Random import random
import base64

class PaddingOracle:
    def __init__(self,stringfile: str):
        self.key = block.gen_random_aes_key()
        with open(stringfile) as f:
            self.choices = [base64.b64decode(s) for s in f]
    
    def encrypt(self) -> bytes:
        iv = Random.get_random_bytes(len(self.key))
        s = self.choices[random.randint(0,len(self.choices)-1)]
        return block.aes_cbc_encrypt(s, self.key, iv), iv
    
    def decrypt(self, ciphertext, iv, blocksize=16) -> bool:
        plaintext = block.aes_cbc_decrypt(ciphertext, self.key, iv, remove_padding=False)
        padding_char = plaintext[-1]
        if padding_char > blocksize or padding_char < 1:
            return False
        for i in range(padding_char):
            if plaintext[-i-1] != padding_char:
                return False
        return True

# Takes in two ciphertext blocks and recovers the nth byte from the right. c1 needs to have already recovered 
# the previous bytes and had its bytes updated so they XOR to the corresponding n.
# Return the recovered plaintext byte along with D_K(n+1).
def recover_nth_byte(c1, c2: bytes, n: int, oracle: PaddingOracle) -> Tuple[bytes,bytes]:
    bs = len(c1)
    candidates = []
    for i in range(256):
        c1_modified = c1[:bs-n] + bytes([i]) + c1[bs-n+1:]
        if oracle.decrypt(c2, c1_modified):
            candidates.append(c1_modified)
    # If we have more than one candidate, modify the previous byte and see if padding is still correct.
    if len(candidates) > 1 and n < 16:
        for candidate in candidates:
            c1_modified = candidate[:bs-n-1] + bytes([random.randint(0,255)]) + candidate[bs-n:]
            if oracle.decrypt(c2,c1_modified):
                # There is a very high probability this is what we want.
                break
    else:
        c1_modified = candidates[0]

    return bytes([c1_modified[-n] ^ n])

# recovers all bytes in block c2
def recover_block(c1, c2: bytes, oracle: PaddingOracle) -> bytes:
    plaintext = b''
    bs = len(c1)
    d_k = b''
    for i in range(1, bs + 1): 
        cprime = c1[:bs - i + 1] + bytes([x^i for x in d_k])
        d = recover_nth_byte(cprime, c2, i, oracle)
        # P = D_K XOR C_1 = (C_1' XOR n) XOR C_1
        p = bytes([d[0]^c1[-i]])
        plaintext = p + plaintext
        d_k = d + d_k
    return plaintext

def break_cbc(ciphertext, iv: bytes, oracle: PaddingOracle) -> bytes:
    bs = len(iv)
    num_blocks = len(ciphertext)//bs
    plaintext = b''
    for i in range(num_blocks):
        cblock = ciphertext[(i)*bs:(i+1)*bs]
        plaintext += recover_block(iv, cblock, oracle)
        iv = cblock
    return plaintext

if __name__ == '__main__':
    for _ in range(10):
        paddingOracle = PaddingOracle('17.txt')
        c, iv = paddingOracle.encrypt()
        print(break_cbc(c, iv, paddingOracle))
        
