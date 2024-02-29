from Crypto.Cipher import PKCS1_OAEP

def rsa_encipher(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext
