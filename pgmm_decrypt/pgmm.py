from pgmm_decrypt.decrypt import decrypt
from pgmm_decrypt.utils import derive_key


def decrypt_pgmm_key(encrypted_key: bytes):
    return decrypt(encrypted_key, None, True)


# TODO: calc weak from key
def decrypt_pgmm_resource(decrypted_key: bytes | None, data: bytes, weak: bool):
    if weak:
        return decrypt(data[4:], None, True)
    else:
        new_key = derive_key(data[:4], decrypted_key)
        return decrypt(data[4:], new_key, False)
