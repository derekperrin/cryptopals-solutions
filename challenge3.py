import cryptopals
import binascii

if __name__ == '__main__':
    s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    plaintext, key, score = cryptopals.break_single_byte_xor(binascii.unhexlify(s))[0]
    print('Plaintext: ', plaintext)
    print('Key: ', key)
