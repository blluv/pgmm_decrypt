from typing import List

from pgmm_decrypt.utils import rotl32, rotr32


def weak_twofish_block_decrypt(words: List[int]):
    """
    Python code to simulate a strange key schedule.
    In PGMM, if you try to use a key that is less than the key size of twofish, the key schedule will not work properly.
    """

    assert len(words) == 4  # 16bytes

    for _ in range(8):
        words[2] = rotl32(words[2], 1) & 0xFFFFFFFF
        words[3] = rotr32(words[3] & 0xFFFFFFFF, 1)
        words[0] = rotl32(words[0], 1) & 0xFFFFFFFF
        words[1] = rotr32(words[1] & 0xFFFFFFFF, 1)

    [words[0], words[2]] = [words[2], words[0]]
    [words[1], words[3]] = [words[3], words[1]]

    return words
