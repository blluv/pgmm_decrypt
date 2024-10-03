from . import _twofish


class Twofish:
    def __init__(self, key: bytes):
        self.key = _twofish.prepare_key(key)

    def decrypt(self, ciphertext: bytes):
        return _twofish.decrypt(self.key, ciphertext)

    def encrypt(self, plaintext: bytes):
        return _twofish.encrypt(self.key, plaintext)
