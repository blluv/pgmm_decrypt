from twofish import Twofish

from pgmm_decrypt.utils import cbc_decrypt_wrapper
from pgmm_decrypt.weak_twofish import Weakfish

IV = bytes.fromhex("A047E93D230A4C62A744B1A4EE857FBA")

# TODO: calc weak from key
def decrypt(data: bytes, key: bytes | None, weak: bool):
    assert len(data) % 16 == 0

    cipher = Weakfish() if weak else Twofish(key)
    block_dec_with_cbc = cbc_decrypt_wrapper(cipher.decrypt, IV)

    return b"".join(
        block_dec_with_cbc(data[offset : offset + 16])
            for offset in range(0, len(data), 16)
        )
