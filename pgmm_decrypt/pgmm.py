from .twofish import Twofish
from .decrypt import cbc_decrypt_wrapper, decrypt, derive_subkey
from .weakfish import Weakfish

PGMM_IV = bytes.fromhex("A047E93D230A4C62A744B1A4EE857FBA")


def decrypt_pgmm_key(encrypted_key: bytes) -> bytes:
    cipher = Weakfish()
    cbc_dec_func = cbc_decrypt_wrapper(cipher.decrypt, PGMM_IV)

    return decrypt(cbc_dec_func, encrypted_key)


# TODO: calc weak from key
def decrypt_pgmm_resource(file_bytes: bytes, decrypted_key: bytes | None = None, *, weak: bool = False) -> bytes:
    if not file_bytes[:3] == b"enc":    # resource file is not encrypted
        return file_bytes

    if decrypted_key is None:   # make sure the key is always available
        decrypted_key = bytes()
    decrypted_key += b"\0" * (16 - len(decrypted_key))  # extend key to at least 16 bytes long
    pt_len = len(file_bytes) - 4 - file_bytes[3]

    cipher = Weakfish() if weak else Twofish(derive_subkey(decrypted_key, pt_len))
    cbc_dec_func = cbc_decrypt_wrapper(cipher.decrypt, PGMM_IV)

    return decrypt(cbc_dec_func, file_bytes[4:])[:pt_len]
