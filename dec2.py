import struct
from typing import List



def rotr32(x, n):
    return (x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)


def rotl32(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def bytesToWords(data: bytes) -> List[int]:
    assert len(data) % 4 == 0

    words = []
    for i in range(len(data)//4):
        words.append(struct.pack("<I", data[i*4:i*4+4])[0])
    return words

def wordsToBytes(words: List[int]) -> bytes:
    buf = bytearray()
    for word in words:
        buf.extend(struct.unpack("<I", word))
    return bytes(buf)

def decrypt(words: List[int]):
    assert len(words) == 16

    for _ in range(8):
        words[2] = rotl32(words[2], 1) & 0xffffffff
        words[3] = rotr32(words[3] & 0xffffffff, 1)
        words[0] = rotl32(words[0], 1) & 0xffffffff
        words[1] = rotr32(words[1] & 0xffffffff, 1)        
    return words

def xor(a, b):
    w = [0 for _ in range(len(a))]
    for i in range(len(a)):
        w[i] = a[i] ^ b[i]
    return bytes(w)

iv = bytes.fromhex("A0 47 E9 3D 23 0A 4C 62 A7 44 B1 A4 EE 85 7F BA")
data = bytes.fromhex('76 84 91 97 BA DC 85 7F 72 DF 0D 91 54 12 3E 7D') # info.json에 있던 key decode한 값

data_words = bytesToWords(data)
print(wordsToBytes(decrypt(data_words)))
