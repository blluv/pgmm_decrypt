import os
from pgmm_decrypt.twofish import Twofish

# Test vectors: (key, plaintext, ciphertext)
TEST_VECTORS = [
    (
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "9F589F5CF6122C32B6BFEC2F2AE8C35A",
    ),
    (
        "0123456789ABCDEFFEDCBA98765432100011223344556677",
        "00000000000000000000000000000000",
        "CFD1D2E5A9BE9CDF501F13B892BD2248",
    ),
    (
        "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF",
        "00000000000000000000000000000000",
        "37527BE0052334B89F0CFCCAE87CFA20",
    ),
]


def test_twofish_with_test_vectors():
    for key, plaintext, expected_ciphertext in TEST_VECTORS:
        key_bytes = bytes.fromhex(key)
        plaintext_bytes = bytes.fromhex(plaintext)
        expected_ciphertext_bytes = bytes.fromhex(expected_ciphertext)

        twofish = Twofish(key_bytes)
        ciphertext = twofish.encrypt(plaintext_bytes)

        assert ciphertext == expected_ciphertext_bytes


def test_twofish_with_urandom():
    for key_len in range(0, 32 + 1):
        twofish = Twofish(os.urandom(key_len))

        for _ in range(1000):
            original = os.urandom(16)

            ciphertext = twofish.encrypt(original)
            plaintext = twofish.decrypt(ciphertext)

            assert plaintext == original
