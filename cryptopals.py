import base64
import binascii
import string
from Crypto.Cipher import AES

def hex_to_b64(hexBytes: bytes) -> bytes:
    return base64.b64encode(hexBytes)

def fixed_xor(a,b: bytes) -> bytes:
    return bytes([x^y for x,y in zip(a,b)])

# Frequencies of letters in English text.
# https://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
char_freqs = {
        'a': 0.0812, 'b': 0.0149, 'c': 0.0271, 'd': 0.0432,
        'e': 0.1202, 'f': 0.0230, 'g': 0.0203, 'h': 0.0592,
        'i': 0.0731, 'j': 0.0010, 'k': 0.0069, 'l': 0.0398,
        'm': 0.0261, 'n': 0.0695, 'o': 0.0768, 'p': 0.0182,
        'q': 0.0011, 'r': 0.0602, 's': 0.0628, 't': 0.0910,
        'u': 0.0288, 'v': 0.0111, 'w': 0.0209,'x': 0.0017,
        'y': 0.0211,'z': 0.0007
         }

english_index = sum([char_freqs[letter] for letter in char_freqs])
char_set = string.ascii_letters + ' ' # used to determine if something is text or not

def single_char_xor(c,s: bytes) -> bytes:
    c *= len(s)
    return fixed_xor(c,s)

def is_text(candidate: bytes) -> bool:
    try:
        s = candidate.decode()
    except UnicodeDecodeError:
        return False
    num_chars = sum([c in char_set for c in s])
    return num_chars/len(s) > 0.8 # changing this from 0.7 to 0.8 got rid of a lot of garbage.
    
def break_single_byte_xor(s: bytes) -> list:
    
    # try some character c and assign it a score. Return the XOR of c,s as well as the numerical score.
    # A lower score corresponds to a higher likelihood of being the English plaintext we want.
    def score_trial(c, s: bytes) -> tuple:
        pt_candidate = single_char_xor(c,s)
        I = 0
        # If it doesn't look like text, assign it a high score and return it. Don't bother checking.
        if not is_text(pt_candidate):
            return pt_candidate,c,100
        for b in pt_candidate:
            if chr(b) not in string.ascii_letters:
                continue
            char = chr(b)
            occurrences = pt_candidate.count(ord(char.lower())) + pt_candidate.count(ord(char.upper()))
            I += char_freqs[char.lower()]*(occurrences/len(pt_candidate))
        return pt_candidate,c,abs(I-english_index)
    
    trials = []
    for i in range(0x20,0x7F):
        key_candidate = chr(i).encode('ascii')
        score = score_trial(key_candidate, s)
        if score[2] > 5:
            continue
        trials.append(score)
    return sorted(trials,key=lambda x:x[-1])


def repeating_key_xor(pt, k: bytes) -> bytes:
    key = k*(len(pt)//len(k) + 1) # our fixed xor of two strings works as long as key is greater than pt.
    return fixed_xor(pt,key)

# Hamming distance between two strings just counts the number of differing bits. We can xor the two strings
# together, and any of the differing bits are revealed as 1s in the xor product. So we count those and
# output their sum.
def hamming_distance(a,b: bytes) -> int:
    res = fixed_xor(a,b)
    return sum(bin(x).count('1') for x in res)

# First, find the likely size of the key the plaintext was encrypted with. Cryptopals recommends
# using a block size of 2
def find_keysize(ciphertext: bytes, length_range: tuple) -> int:
    min_ham = 100 # just set to some large number.
    likely_keysize = 0
    for keysize in range(length_range[0],length_range[1]):
        num_blocks = len(ciphertext)//keysize + 1
        hams = 0
        for i in range(num_blocks):
            hams += hamming_distance(ciphertext[i*keysize:(i+1)*keysize],ciphertext[(i+1)*keysize:(i+2)*keysize])
        hams = hams / keysize / num_blocks
        if hams < min_ham:
            min_ham = hams
            likely_keysize = keysize
    return likely_keysize

def break_vigenere(ciphertext):
    keysize = find_keysize(ciphertext,(2,40))
    num_blocks = len(ciphertext)//keysize
    transposed_blocks = []
    guessed_key = []
    for i in range(keysize):
        j = 0
        block = []
        while i + 29*j < len(ciphertext):
            block.append(ciphertext[i + 29*j])
            j += 1
        guessed_key.append(break_single_byte_xor(bytes(block))[0][1])
    return b''.join(guessed_key)

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

def ecb_encrypt(plaintext,key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def ecb_decrypt(ciphertext,key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)
