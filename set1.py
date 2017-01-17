#! /usr/bin/python3

import base64
import binascii

def prettyOut(setNum, chalNum, out):
    print("Set {}, Challenge {},: {}".format(setNum, chalNum, out.decode('ascii')))

def hextobase64(hex_str):
    # Convert the hex (binary) string to bytes, unhexlify, encode as base64, and then decode to ascii
    return base64.b64encode(binascii.unhexlify(hex_str))

def base64tohex(b64_str):
    # Decode the b64 encoded string, then hexlify, then decode the hex encoding to ascii
    return binascii.hexlify(base64.b64decode(b64_str))

def q1():
    hex_str = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    b64_str = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    out = hextobase64(hex_str)
    if out == b64_str:
        prettyOut(1, 1, out)
        return

def xor(buf1, buf2):
    if len(buf1) != len(buf2):
        return None
    else:
        barr = bytearray(b'')
        for i,j in zip(binascii.unhexlify(buf1), binascii.unhexlify(buf2)):
            barr.append(i ^ j)
        
        return binascii.hexlify(barr)

def q2():
    buf1 = b'1c0111001f010100061a024b53535009181c'
    buf2 = b'686974207468652062756c6c277320657965'
    buf3 = b'746865206b696420646f6e277420706c6179'
    
    out = xor(buf1, buf2)
    if out == buf3:
        prettyOut(1, 2, out)

    return

def xorCipher(hex_str):
    outputArray = []
    for char in range(0,256):
        out = xorWithChar(char, hex_str)
        outputArray.append(out)

    return scoreOutput(outputArray)

def xorWithChar(key, hex_str):
    out = bytearray(b'')
    for b in binascii.unhexlify(hex_str):
        out.append(key ^ b)
    return out

def scoreOutput(outputArray):
    out = []
    for msg in outputArray:
        illegalChar = False
        for char in msg:
            illegalChar = isIllegalChar(char)
            if illegalChar == True:
                break
        if illegalChar == False:
            out.append(msg)
        illegalChar = False
   
    return out[0]

def isIllegalChar(char):
    if char < 32:
        return True
    if char > 122:
        return True
    if char > 90 and char < 97:
        return True
    if char >57 and char < 6:
        return True

    return False

def q3():
    hex_str = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    out = xorCipher(hex_str)
    prettyOut(1, 3, out)
    return

if __name__ == "__main__":
       q1()
       q2()
       q3()

