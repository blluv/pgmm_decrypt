# pgmm_decrypt

Pixel Game Maker MV Decrypt

```py
# pip install git+https://github.com/blluv/pgmm_decrypt.git

from pgmm_decrypt import decrypt_pgmm_key, decrypt_pgmm_resource


# signature

decrypt_pgmm_key(encrypted_key: bytes) -> bytes
decrypt_pgmm_resource(file_bytes: bytes, decrypted_key: bytes | None = None) -> bytes


# decrypt key (in info.json)

with open("info.json", "r", encoding="utf-8") as f:
    import base64, json
    encrypted_key = base64.b64decode(json.load(f)["key"])
decrypted_key = decrypt_pgmm_key(encrypted_key)


# decrypt resource

with open("encrypted_resource_file", "rb") as f:
    file_bytes = f.read()
decrypted_bytes = decrypt_pgmm_resource(file_bytes, decrypted_key)
with open("decrypted_resource_file", "wb") as f:
    f.write(decrypted_bytes)
```

## twofish
from [twofish](https://packages.debian.org/source/buster/twofish)