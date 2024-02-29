import pickle
from crypto.attribute.att_encrypt import out_key


def broadcast_keygen(sec_ACL):
    filename = "./config/broadenckeys/%d.keys" % sec_ACL
    secret_information_list = pickle.loads(open(filename, 'rb').read())
    open(filename, 'r').close()
    filename = "config/AESCBCIV.keys"
    IV = pickle.loads(open(filename, 'rb').read())
    open(filename, 'r').close()
    return secret_information_list, IV


def attribute_keygen():
    return out_key()