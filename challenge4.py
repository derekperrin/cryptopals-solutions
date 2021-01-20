import cryptopals
import binascii
# Given an input file, find out which one of the lines was XOR'd
# against a single character. Our strategy will be to run the previous code from
# challenge 3 on every line in the file and just output the highest scoring
# texts we get.

if __name__ == '__main__':
    # We need to strip the newline characters from the end of each line, otherwise unhexlify fails.
    with open('4.txt') as f:
        ciphertexts = [binascii.unhexlify(line.strip()) for line in f]
    plaintexts = []
    for c in ciphertexts:
        plaintexts += cryptopals.break_single_byte_xor(c)
    plaintext, key, score = sorted(plaintexts,key=lambda x:x[-1])[0]
    print('Plaintext: ', plaintext)
    print('Key: ', key)
