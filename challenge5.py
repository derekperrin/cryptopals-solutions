from cryptopals import basic
import binascii

if __name__ == '__main__':
    # Repeating-key XOR is just XOR'ing each byte of the key with each byte of
    # the plaintext. We concatenate the key with itself until it is the same
    # length as the plaintext.
    s = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
    k = 'ICE'
    expected_output = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    result = basic.repeating_key_xor(s.encode(),k.encode())
    print("Result: ", binascii.hexlify(result).decode())
    if binascii.hexlify(result).decode() == expected_output:
        print('This is the expected output.')
    else:
        print('Not expected output. Something went wrong.')
