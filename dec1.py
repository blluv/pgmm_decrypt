from twofish import Twofish

def xor(a, b):
    w = [0 for _ in range(len(a))]
    for i in range(len(a)):
        w[i] = a[i] ^ b[i]
    return bytes(w)

def kc(data: bytes, key: bytes):
    key = list(key)
    i = 0
    h = len(data) - data[3] - 4
    while h > 0:
        t = (h ^ key[i]) & 0xff
        key[i] = 1 if t < 1 else t
        h //= 256
        i += 1
    return bytes(key)
    

decrypted_key = b"" # 게임 메모리에서 가져온 키
iv = bytes.fromhex("A0 47 E9 3D 23 0A 4C 62 A7 44 B1 A4 EE 85 7F BA")

data = open("./project.json", "rb").read()
twofish = Twofish(kc(data, decrypted_key))


file = open("./project.dec.json", "wb")
xora = iv

cnt = (len(data)-4) // 16
for i in range(cnt):
    ct = data[i*16+4:i*16+20]
    pt = twofish.decrypt(ct)
    file.write(xor(xora, pt))
    xora = ct
file.close()
