def xor_block(a: bytes, b: bytes) -> bytes:
    return bytes(va ^ vb for va, vb in zip(a, b))


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


def rol_nbytes(bs: bytes, n: int) -> bytes:
    return bs[n:] + bs[:n]


def ror_nbytes(bs: bytes, n: int) -> bytes:
    return bs[-n:] + bs[:-n]
