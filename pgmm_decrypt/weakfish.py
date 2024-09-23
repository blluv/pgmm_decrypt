from .utils import rol_nbytes, ror_nbytes


class Weakfish():
    """
    Python code to simulate a strange key schedule.
    In PGMM, if you try to use a key that is less than the key size of twofish, the key schedule will not work properly.
    """

    def encrypt(self, block: bytes) -> bytes:
        if not len(block) == 16:
            raise ValueError("invalid block size")

        block = rol_nbytes(block[:4], 1) + ror_nbytes(block[4:8], 1) + rol_nbytes(block[8:12], 1) + ror_nbytes(block[12:], 1)
        block = rol_nbytes(block, 8)

        return block

    def decrypt(self, block: bytes) -> bytes:
        if not len(block) == 16:
            raise ValueError("invalid block size")

        block = ror_nbytes(block[:4], 1) + rol_nbytes(block[4:8], 1) + ror_nbytes(block[8:12], 1) + rol_nbytes(block[12:], 1)
        block = ror_nbytes(block, 8)

        return block
