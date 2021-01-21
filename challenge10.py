from cryptopals import block
import base64

BLOCK_SIZE=16

if __name__ == '__main__':
    with open('./10.txt') as f:
        ciphertext = base64.b64decode(f.read())
    key = b'YELLOW SUBMARINE'
    iv = b'\x00'*BLOCK_SIZE
    plaintext = block.aes_cbc_decrypt(ciphertext,key,iv)
    print(plaintext.decode())

    # We'll silently test to make sure encryption works correctly too.
    candidate_ciphertext = block.aes_cbc_encrypt(plaintext, key, iv)
    if candidate_ciphertext != ciphertext:
        print('Encryption is not working correctly.')
