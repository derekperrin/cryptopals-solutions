from cryptopals import block

if __name__ == '__main__':
    test_string = 'YELLOW SUBMARINE'
    print(block.pkcs7_pad(test_string.encode(), 20))
