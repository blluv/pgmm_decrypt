from .decrypt import cbc_decrypt_wrapper, decrypt, derive_subkey
from .twofish import Twofish
from .weakfish import Weakfish

PGMM_IV = bytes.fromhex("A047E93D230A4C62A744B1A4EE857FBA")


def decrypt_pgmm_key(encrypted_key: bytes) -> bytes:
    # The key for encrypted_key is "key". However, since it's too short (3 bytes),
    # we decrypt it using weakfish.

    cipher = Weakfish()
    cbc_dec_func = cbc_decrypt_wrapper(cipher.decrypt, PGMM_IV)

    return decrypt(cbc_dec_func, encrypted_key)


def decrypt_pgmm_resource(
    file_bytes: bytes, decrypted_key: bytes | None = None
) -> bytes:
    if not file_bytes[:3] == b"enc":  # resource file is not encrypted
        return file_bytes

    is_weakfish = decrypted_key is None or len(decrypted_key) <= 8
    pt_len = len(file_bytes) - 4 - file_bytes[3]

    cipher = (
        Weakfish() if is_weakfish else Twofish(derive_subkey(decrypted_key, pt_len))
    )
    cbc_dec_func = cbc_decrypt_wrapper(cipher.decrypt, PGMM_IV)

    return decrypt(cbc_dec_func, file_bytes[4:])[:pt_len]
