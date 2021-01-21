from cryptopals import basic
import binascii

if __name__ == '__main__':
    s = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    correctOutput = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    # Need to call unhexlify on s to convert the hex string s into raw bytes.
    print('Expected output: ', correctOutput)
    print('Actual output: ', basic.hex_to_b64(binascii.unhexlify(s)).decode())
    basic.hex_to_b64(binascii.unhexlify(s)).decode() == correctOutput
