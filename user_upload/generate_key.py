from Crypto.PublicKey import RSA
from crypto.attribute.att_encrypt import out_key

def key_streamcipher_gen():
    filename = "./config/streamcipher.keys"
    key_streamcipher = open(filename, 'rb').read()
    return key_streamcipher

def rsa_keygen():
    with open('./rsa_key/PK.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())
    return public_key

def attribute_keygen():
    return out_key()