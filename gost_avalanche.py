#!/usr/bin/env python3

DEBUG = False
# DEBUG=True


# We are going to use the following keys and plaintexts.
# program will be tested on different keys and plaintext

plaintext0 = 0x02468ACEECA86420
plaintext1 = 0x12468ACEECA86420
key0 = 0x08C73A08514436F2E150A865EB75443F904396E66638E182170C1CA1CB6C1062
key1 = 0x18C73A08514436F2E150A865EB75443F904396E66638E182170C1CA1CB6C1062

# 	GOST R 34.12-2015 S-Box
sboxes = [[0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1],
          [0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF],
          [0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0],
          [0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB],
          [0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC],
          [0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0],
          [0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7],
          [0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2]]


# meausure the avalanche effect in GOST,
# both for changes in the plaintext and in the key. it can be seen,
# that two plaintexts and the two keys differ in 1 bit, respectively.
#
# In order to measure the avalanche effect for differences in the
# plaintext, you encrypt both plaintext0 and plaintext1 with
# key0. After each round of encryption, you measure how many bits of
# the intermediate ciphertexts differ.
#
# In order to measure the avalanche effect for difference in the key,
# you encrypt plaintext0 both with key0 and with key1. Again, you
# measure how many bits of the intermediate ciphertexts differ.
#
#
# to check the implementation testGost() can be used

def functionAndSBox(left, right, key):
    modNum = 2 ** 32
    outLeft = right

    temp = (right + key) % modNum
    out = 0
    for i in range(8):
        out = out | ((sboxes[i][(temp >> (4 * i)) & 0b1111]) << (4 * i))
    out = ((out >> (21)) | (out << 11)) & 0xFFFFFFFF
    outRight = left ^ out

    return outLeft, outRight


def encryption(pText, key):
    pTextShift = 32
    ascendingKeys = 24
    decendingKeys = 8
    txtLeft = pText >> pTextShift
    txtRight = pText & 0xFFFFFFFF

    for i in range(ascendingKeys):
        txtLeft, txtRight = functionAndSBox(
            txtLeft, txtRight, key[i % 8])
    for i in range(decendingKeys):
        txtLeft, txtRight = functionAndSBox(
            txtLeft, txtRight, key[7 - i])
    toReturn =  txtRight << 32 | txtLeft

    return toReturn

def functionAndSBoxforDecrypt(left, right, key):
    modNum = 2 ** 32
    outRight = left

    temp = (left + key) % modNum
    out = 0
    for i in range(8):
        out = out | ((sboxes[i][(temp >> (4 * i)) & 0b1111]) << (4 * i))
    out = ((out >> (21)) | (out << 11)) & 0xFFFFFFFF
    outLeft = right ^ out
    return outLeft, outRight

def decryption(pText, key):
    pTextShift = 32
    ascendingKeys = 24
    decendingKeys = 8
    txtLeft = pText >> pTextShift
    txtRight = pText & 0xFFFFFFFF

    for i in range(decendingKeys):
        txtLeft, txtRight = functionAndSBoxforDecrypt(
            txtLeft, txtRight, key[i])
    for i in range(ascendingKeys):
        txtLeft, txtRight = functionAndSBoxforDecrypt(
            txtLeft, txtRight, key[(7 - i) % 8])

    toReturn =  txtLeft << 32 | txtRight

    return toReturn


def gost(text, key, encrypt=True, rounds=32):
    listKey = [None] * 8
    keyX = key
    for i in range(8):
        listKey[i] = keyX & 0xFFFFFFFF
        keyX = keyX >> 32
        print(hex(listKey[i]))
    keys = [None] * 8
    # invert all the keys
    for i in range(8):
        keys[i] = listKey[7 - i]

    if encrypt:
        return encryption(text, keys)
    else:
        return decryption(text, keys)

    ##################
    # YOUR CODE HERE #
    ##################
    return (ciphertext)



def bitDifference(a, b):
    """Return number of bits different between a and b."""
    pass


def testGost():
    ciphertext = gost(text=plaintext0, key=key0, encrypt=True)
    assert (ciphertext == 0xB3196C3940160B06)
    deciphered = gost(text=ciphertext,
                      key=key0, encrypt=False)
    assert (plaintext0 == deciphered)

    # Since it is notoriously hard to get bit ordering in crypto
    # algorithms right, here are the temporary values for the first
    # four rounds of encryption. You can also find a complete
    # example in appendix A.4 of RFC 89891, available at
    # https://tools.ietf.org/html/rfc8891
    #
    # Round:             1
    # Left:              0x02468ACE
    # Right:             0xECA86420
    # Round Key:         0x08C73A08
    # R + Round Key:     0xF56F9E28
    # S-Box Application: 0x29CC062E
    # Shift Left:        0x6031714E
    # Round:             2
    # Left:              0xECA86420
    # Right:             0x6277FB80
    # Round Key:         0x514436F2
    # R + Round Key:     0xB3BC3272
    # S-Box Application: 0x651B15C6
    # Shift Left:        0xD8AE3328
    # Round:             3
    # Left:              0x6277FB80
    # Right:             0x34065708
    # Round Key:         0xE150A865
    # R + Round Key:     0x1556FF6D
    # S-Box Application: 0x7926B053
    # Shift Left:        0x35829BC9
    # Round:             4
    # Left:              0x34065708
    # Right:             0x57F56049
    # Round Key:         0xEB75443F
    # R + Round Key:     0x436AA488
    # S-Box Application: 0x05C3A21E
    # Shift Left:        0x1D10F02E


def plaintextAvalanche():
    print('\nAvalanche effect for changes in plaintext.')
    print('Original difference: %d' %
          bitDifference(plaintext0, plaintext1))
    for rounds in range(32 + 1):
        c0 = gost(text=plaintext0, key=key0, rounds=rounds, encrypt=True)
        c1 = gost(text=plaintext1, key=key0, rounds=rounds, encrypt=True)
        print('Round: %02d Delta: %d' % (rounds, bitDifference(c0, c1)))


def keyAvalanche():
    print('\nAvalanche effect for changes in key.')
    print('Original difference: %d' %
          bitDifference(plaintext0, plaintext0))
    for rounds in range(32 + 1):
        c0 = gost(text=plaintext0, key=key0, rounds=rounds, encrypt=True)
        c1 = gost(text=plaintext0, key=key1, rounds=rounds, encrypt=True)
        print('Round: %02d Delta: %d' % (rounds, bitDifference(c0, c1)))


if __name__ == '__main__':
    # testGost()
    # plaintextAvalanche()
    # keyAvalanche()


