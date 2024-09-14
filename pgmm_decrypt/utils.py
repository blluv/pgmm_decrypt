def xor_block(a: bytes, b: bytes) -> bytes:
    return bytes(va ^ vb for va, vb in zip(a, b))


def cbc_decrypt_wrapper(block_decrypt_func, iv):
    last_ciphertext_block = iv

    def decrypt_one_block(ciphertext_block):
        nonlocal last_ciphertext_block
        plaintext_block = xor_block(block_decrypt_func(ciphertext_block), last_ciphertext_block)
        last_ciphertext_block = ciphertext_block
        return plaintext_block

    return decrypt_one_block


def derive_subkey(key: bytes, plaintext_len: int) -> bytes:
    ptl_bytes = plaintext_len.to_bytes(8, 'little').rstrip(b'\0')   # 8 bytes for length value should be enough
    xor_key = xor_block(ptl_bytes, key).replace(b'\0', b'\1')   # this stops at the end of the shorter one

    return xor_key + key[len(xor_key):] # append the rest unchanged bytes, assume `key` is alwalys longer


def rol_nbytes(bs: bytes, n: int) -> bytes:
    return bs[n:] + bs[:n]


def ror_nbytes(bs: bytes, n: int) -> bytes:
    return bs[-n:] + bs[:-n]
