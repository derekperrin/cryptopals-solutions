from Crypto.Cipher import AES
import binascii
import base64

if __name__ == '__main__':
    key = b'YELLOW SUBMARINE'
    with open('./7.txt') as f:
        ciphertext = base64.b64decode(f.read())
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext.decode())
