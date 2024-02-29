from Crypto.Cipher import AES
import os
import base64
import pickle

def generateAESCBCIV():
    num_digits = 32
    key = os.urandom(int(num_digits / 2))
    f = open("./config/AESCBCIV.keys","wb+")
    f.write( pickle.dumps(key)  )
    f.close()
    return key

def generateAESCBCkey(num_totalnodes):
    session_keysAESCBC = []
    for i in range(num_totalnodes):
            num_digits = 64
            key = (os.urandom(int(num_digits / 2)))
            session_keysAESCBC.append(key)
    f = open("./config/AESsession%d.keys"%num_totalnodes,"wb+")
    f.write( pickle.dumps(session_keysAESCBC)  )
    f.close()
    return session_keysAESCBC

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AESCipher:
    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw, iv ):
        
        raw = pad(raw)
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( cipher.encrypt( raw.encode("ISO-8859-1") ) )

    def decrypt( self, enc, iv ):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc ))