def xor_block(a: bytes, b: bytes) -> bytes:
    return bytes(va ^ vb for va, vb in zip(a, b))


def rol_nbytes(bs: bytes, n: int) -> bytes:
    return bs[n:] + bs[:n]


def ror_nbytes(bs: bytes, n: int) -> bytes:
    return bs[-n:] + bs[:-n]


def pad(block: bytes, block_size: int) -> bytes:
    return block + b"\0" * ((-len(block)) % block_size)
