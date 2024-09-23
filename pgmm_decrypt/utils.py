def xor_block(a: bytes, b: bytes) -> bytes:
    return bytes(va ^ vb for va, vb in zip(a, b))


def rol_nbytes(bs: bytes, n: int) -> bytes:
    return bs[n:] + bs[:n]


def ror_nbytes(bs: bytes, n: int) -> bytes:
    return bs[-n:] + bs[:-n]
