

"""
Given a message of length n:

1. Extend the message so its length is congruent to 0 modulo 16.
   Now the message has a length that is a multiple of 16.

2. Append Checksum. 16 byte checksum is appended to the previous result.
   /* Clear checksum. */
    For i = 0 to 15 do:
        Set C[i] to 0.
    end /* of loop on i */

    Set L to 0.

    /* Process each 16-byte block. */
    For i = 0 to N/16-1 do
        /* Checksum block i. */
        For j = 0 to 15 do
            Set c to M[i*16+j].
            Set C[j] to C[j] xor S[c xor L].
            Set L to C[j].
        end /* of loop on j */
    end /* of loop on i */

   The 16-byte checksum C[0 ... 15] is appended to the (padded)
   message.
   Let M[0..N'-1] be the message with padding and checksum appended,
   where N' = N + 16.

3. Initialise MD Buffer.
   A 48-byte buffer X is used to compute the message digest. The buffer
   is initialized to zero.


4. Process Message in 16-Byte Blocks.

    /* Process each 16-byte block. */
    For i = 0 to N'/16-1 do

        /* Copy block i into X. */
        For j = 0 to 15 do
            Set X[16+j] to M[i*16+j].
            Set X[32+j] to (X[16+j] xor X[j]).
        end /* of loop on j */

        Set t to 0.

        /* Do 18 rounds. */
        For j = 0 to 17 do
            /* Round j. */
            For k = 0 to 47 do
                Set t and X[k] to (X[k] xor S[t]).
            end /* of loop on k */
            Set t to (t+j) modulo 256.
        end /* of loop on j */

    end /* of loop on i */

5. Output.
   The message digest produced as output is X[0 ... 15]. That is, we
   begin with X[0], and end with X[15].


"""


import binascii
from typing import List

MD2Tests = {"": '8350e5a3e24c153df2275c9f80692773',
            "a": "32ec01ec4a6dac72c0ab96fb34c0b5d1",
            "abc": "da853b0d3f88d99b30283a69e6ded6bb",
            "message digest": "ab4f496bfb2a530b219ff33031fe06b0",
            "abcdefghijklmnopqrstuvwxyz": "4e8ddff3650292ab5a4108c3aa47940b",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "da33def2a42df13975352846c30338cd",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890": "d5976f79d83d3a0dc9806c3c66f3efd8"
            }

# Sample of numbers taken from the decimals of Pi.


###############################################################################################
###############################################################################################
################################        CLASS DEFINITION       ################################
###############################################################################################
###############################################################################################

class MD2(object):
    """
    This class gives utility as an MD2 encoder. It can be used to encode messages. 
    It has the three main methods of the MD2 algorithm, and a pipeline which executes 
    all the three steps for you and outputs the encoded string.

    Example: 
        md2 = MD2()
        message = 'abc'
        encodedMessage = md2.encodeMessage(message)
        # prints 'da853b0d3f88d99b30283a69e6ded6bb'  
    """

    S = [41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
         19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
         76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
         138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
         245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
         148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
         39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
         181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
         150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
         112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
         96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
         85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
         234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
         129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
         8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
         203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
         166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
         31, 26, 219, 153, 141, 51, 159, 17, 131, 20]

    def __init__(self):
        pass

    def extendMessage(self, message: bytearray) -> bytearray:
        """
        Extends the given message to have a total length being
        a multiple of 16. If the input message already has a length that
        is multiple of 16, it appends 16 0's anyway.
        """
        initLength: int = len(message)
        appendLength: int = 16 - initLength % 16
        message = message + \
            bytearray([appendLength for _ in range(appendLength)])
        return message

    def appendCheckSum(self, message: bytearray) -> bytearray:
        """
        This method 
        """
        checkSum: bytearray = bytearray([0]*16)
        L: int = 0
        N: int = len(message)

        for i in range(int(N//16)):
            for j in range(0, 16):
                c = message[i*16+j]
                checkSum[j] = checkSum[j] ^ self.S[c ^ L]
                L = checkSum[j]

        return message + checkSum

    def processMessage(self, message: bytearray) -> bytearray:
        N: int = len(message)
        X: bytearray = bytearray([0]*48)
        for i in range(N//16):
            for j in range(16):
                X[16+j] = message[i*16+j]
                X[32+j] = X[16+j] ^ X[j]
            t = 0
            for j in range(18):
                for k in range(48):
                    t = X[k] ^ self.S[t]
                    X[k] = t

                t = (t + j) % len(self.S)
        return X

    def encodeMessage(self, message: str) -> str:
        return binascii.hexlify(self.processMessage(self.appendCheckSum(self.extendMessage(bytearray(message, 'utf-8'))))[0:16]).decode('utf-8')


###############################################################################################
###############################################################################################
############################             TEST SECTION              ############################
###############################################################################################
###############################################################################################

def testVoid():
    md2Encoder = MD2()
    message = ""
    assert md2Encoder.encodeMessage(message) == MD2Tests.get("")


def testA():
    md2Encoder = MD2()
    message = "a"
    assert md2Encoder.encodeMessage(message) == MD2Tests.get('a')


def testABC():
    md2Encoder = MD2()
    message = "abc"
    assert md2Encoder.encodeMessage(message) == MD2Tests.get('abc')


def testMessageDigest():
    md2Encoder = MD2()
    message = "message digest"
    assert md2Encoder.encodeMessage(message) == MD2Tests.get('message digest')


def testAbecedary():
    md2Encoder = MD2()
    message = "abcdefghijklmnopqrstuvwxyz"
    assert md2Encoder.encodeMessage(message) == MD2Tests.get(
        'abcdefghijklmnopqrstuvwxyz')


def testAlphaNumeric():
    md2Encoder = MD2()
    message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    assert md2Encoder.encodeMessage(message) == MD2Tests.get(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')


def testNumbers():
    md2Encoder = MD2()
    message = "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    assert md2Encoder.encodeMessage(message) == MD2Tests.get(
        '12345678901234567890123456789012345678901234567890123456789012345678901234567890')


###############################################################################################
###############################################################################################


if(__name__ == '__main__'):
    string = "abc"
    message = bytearray(string, 'utf-8')
    md2Encoder = MD2()
    extendedMessage = md2Encoder.extendMessage(message)
    print('Extended message', binascii.hexlify(
        extendedMessage).decode('utf-8'))
    messageCheckSum = md2Encoder.appendCheckSum(extendedMessage)
    print('Message with checksum', binascii.hexlify(
        messageCheckSum).decode('utf-8'))
    messageProcessed = md2Encoder.processMessage(messageCheckSum)
    print('Message processed', binascii.hexlify(
        messageProcessed).decode('utf-8'))
    finalMessage = messageProcessed[0:16]
    print(
        f"Final message is: {binascii.hexlify(finalMessage[:16]).decode('utf-8')}")
    print('Run pipeline: ', md2Encoder.encodeMessage(message))
