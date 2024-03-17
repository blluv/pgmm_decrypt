# pgmm_decrypt

Pixel Game Maker MV Decrypt

```py
# pip install git+https://github.com/blluv/pgmm_decrypt.git

from pgmm_decrypt import decrypt_pgmm_key, decrypt_pgmm_resource

# decrypt encrypted_key(in info.json)
decrypt_pgmm_key(encrypted_key: bytes)

# decrypt resource(if weak, no key is needed)
decrypt_pgmm_resource(decrypted_key: bytes | None, data: bytes, weak: bool)
```

## weak?

In PGMM, if you try to use a key that is less than the key size of twofish, the key schedule will not work properly.

I'm going to implement a way to check the length in the library and check weak automatically.

Increasing the key length in info.json and debugging it to see if it decrypt correctly, to figure out what length PGMM's weird key schedule works at.
