from twofish import Twofish

from pgmm_decrypt.utils import cbc_process, bytesToWords, wordsToBytes
from pgmm_decrypt.weak_twofish import weak_twofish_block_decrypt

IV = bytes.fromhex("A047E93D230A4C62A744B1A4EE857FBA")

# TODO: calc weak from key
def decrypt(data: bytes, key: bytes | None, weak: bool):
    if weak:

        def block_dec(block):
            return wordsToBytes(weak_twofish_block_decrypt(bytesToWords(block)))

    else:
        twofish = Twofish(key)

        def block_dec(block):
            return twofish.decrypt(block)

    return b"".join(cbc_process(IV, data, block_dec))
