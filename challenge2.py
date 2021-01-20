import cryptopals
import binascii

if __name__ == '__main__':
    s = '1c0111001f010100061a024b53535009181c'
    x = '686974207468652062756c6c277320657965'
    correctOutput = '746865206b696420646f6e277420706c6179'
    # unhexlify/hexlify converts raw bytes into hex or a hex string into raw bytes
    # str.decode() takes encoded bytes and returns a string object (gets rid of the leading 'b')


    output = cryptopals.fixed_xor(binascii.unhexlify(s),binascii.unhexlify(x))
    print('Decoded output: ', output.decode())
    print('Expected output: ', binascii.unhexlify(correctOutput).decode())
    if binascii.hexlify(output).decode() == correctOutput:
        print("Output is correct!")
    else:
        print("Output is incorrect!")
