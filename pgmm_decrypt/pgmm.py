from pgmm_decrypt.decrypt import decrypt
from pgmm_decrypt.utils import derive_subkey


def decrypt_pgmm_key(encrypted_key: bytes):
    return decrypt(encrypted_key, None, True)


# TODO: calc weak from key
def decrypt_pgmm_resource(decrypted_key: bytes | None, data: bytes, weak: bool):
    pt_len = len(data) - 4 - data[3]
    if weak:
        return decrypt(data[4:], None, True)[:pt_len]
    else:
        new_key = derive_subkey(decrypted_key, pt_len)
        return decrypt(data[4:], new_key, False)[:pt_len]
