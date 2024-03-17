import struct
from typing import List


def xor_block(a, b):
    return bytes(map(lambda v: v[0] ^ v[1], zip(a, b)))


def cbc_process(iv, data, dec_func, block_size=16):
    assert len(data) % block_size == 0

    last_block = iv
    for i in range(0, len(data), block_size):
        ct = data[i : i + block_size]
        pt = xor_block(dec_func(ct), last_block)
        last_block = ct
        yield pt


def derive_key(data: bytes, key: bytes):
    key = list(key)
    i = 0
    h = len(data) - data[3] - 4
    while h > 0:
        t = (h ^ key[i]) & 0xFF
        key[i] = 1 if t < 1 else t
        h //= 256
        i += 1
    return bytes(key)


def rotr32(x, n):
    return (x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)


def rotl32(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def bytesToWords(data: bytes) -> List[int]:
    assert len(data) % 4 == 0

    words_len = len(data) // 4
    return list(struct.unpack(f"<{words_len}I", data))


def wordsToBytes(words: List[int]) -> bytes:
    return bytes(struct.pack(f"<{len(words)}I", *words))
