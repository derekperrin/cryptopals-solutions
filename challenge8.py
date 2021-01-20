from Crypto.Cipher import AES
import cryptopals
import binascii
import base64

if __name__ == '__main__':
    with open('./8.txt') as f:
        encoded_strings = [binascii.unhexlify(s.strip()) for s in f]
    ecb_candidates = []
    for s in encoded_strings:
        if cryptopals.is_ecb(s):
            ecb_candidates.append(s)
    print("Number of ECB ciphertexts detected: ", len(ecb_candidates))
    print("ECB candidates:")
    for candidate in ecb_candidates:
        print(candidate)
