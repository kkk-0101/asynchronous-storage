from Crypto.Cipher import AES

from charm.toolbox.pairinggroup import PairingGroup
import pickle

from crypto.attribute.ac17 import AC17CPABE

BS = 16
def pad(s): return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
def unpad(s): return s[:-ord(s[len(s)-1:])]


def element_to_bytes(element):
    group = PairingGroup('SS512')
    serialized_bytes = group.serialize(element)

    return serialized_bytes


def bytes_to_element(element_bytes):
    group = PairingGroup('SS512')
    element = group.deserialize(element_bytes)

    return element


def out_key():
    filename = "./attribute_key/pk.keys"
    with open(filename, 'rb') as f:
        pk_list = pickle.load(f)
    # print("pk_list---",pk_list,"---",type(pk_list))
    filename = "./attribute_key/msk.keys"
    with open(filename, 'rb') as f:
        msk_list = pickle.load(f)
    # print("msk_list---",msk_list,"---",type(msk_list))

    h_A = []
    e_gh_kA = []
    j = 1
    h_A_str = pk_list[j]
    j += 1
    for i in range(pk_list[j]):
        j += 1
        e = bytes_to_element(pk_list[j])
        h_A.append(e)
    j += 1
    e_gh_kA_str = pk_list[j]
    j += 1
    for i in range(pk_list[j]):
        j += 1
        e = bytes_to_element(pk_list[j])
        e_gh_kA.append(e)
    pk = {'h_A': h_A, 'e_gh_kA': e_gh_kA}

    j = 0
    g_str = msk_list[j]
    j += 1
    g = bytes_to_element(msk_list[j])
    j += 1
    h_str = msk_list[j]
    j += 1
    h = bytes_to_element(msk_list[j])
    j += 1
    g_k = []
    A = []
    B = []
    g_k_str = msk_list[j]
    j += 1
    for i in range(msk_list[j]):
        j += 1
        e = bytes_to_element(msk_list[j])
        g_k.append(e)
    j += 1
    A_str = msk_list[j]
    j += 1
    for i in range(msk_list[j]):
        j += 1
        e = bytes_to_element(msk_list[j])
        A.append(e)
    j += 1
    B_str = msk_list[j]
    j += 1
    for i in range(msk_list[j]):
        j += 1
        e = bytes_to_element(msk_list[j])
        B.append(e)
    msk = {'g': g, 'h': h, 'g_k': g_k, 'A': A, 'B': B}

    return (pk, msk)


def aes_decrypt(key, enc):
    enc = (enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


def decrypt(pk, msk, attr_list, m):
    ctxt = m[0]
    encryption = m[1]
    pairing_group = PairingGroup('SS512')
    cpabe = AC17CPABE(pairing_group, 2)
    key = cpabe.keygen(pk, msk, attr_list)
    rec_msg = cpabe.decrypt(pk, ctxt, key)
    aesKey_bytes = element_to_bytes(rec_msg)
    aesKey_bytes32 = aesKey_bytes[0:32]
    decryption = aes_decrypt(aesKey_bytes32, encryption)
    return decryption
