import hashlib
from Crypto.Cipher import AES
from urllib.request import urlopen
with open("words","r") as file:
    words = [word.strip() for line in file for word in line.split()]


cipher = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"

def decrypt(ciphertext, key):
    ciphertext = bytes.fromhex(ciphertext)
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return decrypted

for word in words:
    hash = hashlib.md5(word.encode()).digest()
    if b"crypto{" in decrypt(cipher, hash):
        print(decrypt(cipher, hash))
        break