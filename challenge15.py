from cryptopals import block

if __name__ == '__main__':
    rint(block.pkcs7_unpad(b'ICE ICE BABY\x04\x04\x04\x04'))
