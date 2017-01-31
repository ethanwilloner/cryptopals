#! /usr/bin/python3

import base64
import binascii
from itertools import cycle

def prettyOut(setNum, chalNum, out):
    print("Set {}, Challenge {}: {}".format(setNum, chalNum, out.decode('ascii')).strip())

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

    return outputArray

def xorWithChar(key, hex_str):
    out = bytearray(b'')
    for b in binascii.unhexlify(hex_str):
        out.append(key ^ b)
    return out

# We use a very naive filtering system
# If the string contains characters outside
# alphanumerics and some punctuation, dont bother with it
def simpleFilter(inputArray):
    outputArray = []
    for msg in inputArray:
        illegalChar = False
        for char in msg:
            illegalChar = isIllegalChar(char)
            if illegalChar == True:
                break
        if illegalChar == False:
            outputArray.append(msg)
        illegalChar = False
   
    return outputArray

def isIllegalChar(char):
    if char < 32:
        return True
    if char > 122:
        return True

    return False

def q3():
    hex_str = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    out = simpleFilter(xorCipher(hex_str))
    prettyOut(1, 3, out[0])
    return

def generateXorSet(inputArray):
    tmpArray = []
    for i in inputArray:
        # Store each byte string with the number of spaces present in it
        # as there is a good chance only a proper sentence will have a lot of them
        tmpArray.append([i,commonWordCount(i)])
    return tmpArray

# return occurrences of common words
def commonWordCount(message):
    commonWords = ["the", "a", "if", "is", "of", " "]
    wordCount = 0
    for w in commonWords:
        if bytes(w, 'ascii') in message:
            wordCount += 1
    return wordCount

def q4():
    with open('4.txt') as f:
        outputArray = []
        for line in f:
            out = xorCipher(bytes(line.strip(), 'ascii'))
            for i in out:
                outputArray.append(i)
        tmpArray = generateXorSet(outputArray)
        prettyOut(1, 4, sorted(tmpArray, key = lambda x: x[1], reverse=True)[0][0])
    return 

def repeatingKeyXor(key, text):
    bytestring = bytes(x ^ y for x,y in zip(cycle(bytes(key, 'ascii')), bytes(text, 'ascii')))
    return binascii.hexlify(bytestring) 

def q5():
    key = 'ICE'
    plaintext = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
    ciphertext = repeatingKeyXor(key, plaintext)
    prettyOut(1, 5, ciphertext)
    return

def hammingDistance(str1, str2):
    differingBits = 0
    if len(str1) != len(str2):
        return None
    else:
        if type(str1) is str and type(str2) is str:
            for i,j in zip(str1, str2):
                differingBits += bin(ord(i) ^ ord(j)).count('1')
        elif type(str1) is bytes and type(str2) is bytes:
             for i,j in zip(str1, str2):
                differingBits += bin(i ^ j).count('1')
        else:
            # type mismatch
            return None
    return differingBits

def breakRepeatingKeyXor(fileName):
    bytesFile = None
    with open(fileName, 'rb') as f:
        bytesFile = base64.b64decode(f.read())
   
    hamDistTable = []
    for KEYSIZE in range(2, 51):
        hamDistTable.append([KEYSIZE, hammingDistance(bytesFile[:KEYSIZE], bytesFile[KEYSIZE:KEYSIZE*2])//KEYSIZE]) 
    
    keysizeGuess = sorted((x for x in hamDistTable), key =  lambda x: x[1])[:2]

    print(keysizeGuess)
    return None

def q6():
    if hammingDistance('this is a test', 'wokka wokka!!!') != 37:
        prettyOut(1, 6, b'Hamming Distance calculation is broken!')
        return
   
    if hammingDistance(b'this is a test', b'wokka wokka!!!') != 37:
        prettyOut(1, 6, b'Hamming Distance 2 calculation is broken!')
        return

    output = breakRepeatingKeyXor('6.txt')

    prettyOut(1, 6, b'')
    return

if __name__ == "__main__":
       q1()
       q2()
       q3()
       q4()
       q5()
       q6()
