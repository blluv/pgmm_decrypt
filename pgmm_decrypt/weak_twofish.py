from pgmm_decrypt.utils import rol_nbytes, ror_nbytes


def weak_twofish_block_decrypt(block: bytes) -> bytes:
    """
    Python code to simulate a strange key schedule.
    In PGMM, if you try to use a key that is less than the key size of twofish, the key schedule will not work properly.
    """

    assert len(block) == 16 # 16bytes

    block = ror_nbytes(block[:4], 1) + rol_nbytes(block[4:8], 1) + ror_nbytes(block[8:12], 1) + rol_nbytes(block[12:], 1)
    block = ror_nbytes(block, 8)

    return block
