from cryptopals import basic
import binascii
import base64

if __name__ == '__main__':
    # First, make sure the hamming distance code works correctly. This is very important.
    h1, h2 = 'this is a test'.encode(), 'wokka wokka!!!'.encode()
    if basic.hamming_distance(h1,h2) != 37:
        print('Hamming distance code is incorrect! Exiting.')
        exit()

    with open('./6.txt') as f:
        ciphertext = base64.b64decode(f.read())   
    keysize = basic.find_keysize(ciphertext,(2,40))
    key = basic.break_vigenere(ciphertext)
    plaintext = basic.repeating_key_xor(ciphertext,key)
    print('Key: ', key.decode())
    print('')
    print('Decrypted Message:')
    print('')
    print(plaintext.decode())
    print(key.decode())
