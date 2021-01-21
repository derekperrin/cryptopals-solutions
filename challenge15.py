from cryptopals import block

if __name__ == '__main__':
    print(block.padding_validation(b'ICE ICE BABY\x04\x04\x04\x04'))
