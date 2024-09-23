from typing import Callable, Generator

from .utils import xor_block


def derive_subkey(key: bytes, plaintext_len: int) -> bytes:
    ptl_bytes = plaintext_len.to_bytes(8, "little").rstrip(b"\0")   # 8 bytes for length value should be enough
    xor_key = xor_block(ptl_bytes, key).replace(b"\0", b"\1")   # this stops at the end of the shorter one

    return xor_key + key[len(xor_key):] # append the rest unchanged bytes, assume `key` is alwalys longer


def cbc_decrypt_wrapper(block_decrypt_func: Callable[[bytes], bytes], iv: bytes) -> Callable[[bytes], bytes]:
    last_ciphertext_block = iv

    def decrypt_one_block(ciphertext_block: bytes) -> bytes:
        nonlocal last_ciphertext_block
        plaintext_block = xor_block(block_decrypt_func(ciphertext_block), last_ciphertext_block)
        last_ciphertext_block = ciphertext_block
        return plaintext_block

    return decrypt_one_block


def decrypt(decrypt_func: Callable[[bytes], bytes], ciphertext: bytes, block_size: int = 16) -> bytes:
    if not len(ciphertext) % block_size == 0:
        raise ValueError("length of ciphertext must be divisible by block size")

    def sequential_decrypt() -> Generator[bytes, None, None]:
        for offset in range(0, len(ciphertext), block_size):
            yield decrypt_func(ciphertext[offset : offset + block_size])

    return b"".join(sequential_decrypt())
