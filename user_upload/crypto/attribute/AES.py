from Crypto import Random
from Crypto.Cipher import AES
from charm.toolbox.pairinggroup import PairingGroup


pairing_group = PairingGroup('SS512')
BS = 16
def pad(s): return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
def unpad(s): return s[:-ord(s[len(s)-1:])]


def aes_encrypt(key, raw):
    assert len(key) == 32
    raw = pad(raw.decode("ISO-8859-1"))  # bytes to string

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(raw.encode("ISO-8859-1")))  # string to bytes


def aes_decrypt(key, enc):
    enc = (enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))
