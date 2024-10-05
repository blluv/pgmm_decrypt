def prepare_key(key: bytes):
    """
    Prepare the Twofish key.

    Key must be between 0 and 32 bytes.
    """
    ...

def encrypt(prepared_key, plaintext: bytes) -> bytes:
    """
    Encrypt a block with Twofish.

    Plaintext must be exactly 16 bytes.
    """
    ...

def decrypt(prepared_key, ciphertext: bytes) -> bytes:
    """
    Decrypt a block with Twofish.

    Ciphertext must be exactly 16 bytes.
    """
    ...
