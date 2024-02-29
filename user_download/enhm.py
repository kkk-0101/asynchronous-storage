from crypto.attribute.att_decrypt import decrypt
from crypto.broadcast.generateBroadcastkeys import Broadcast_decryption
from generate_key import broadcast_keygen, attribute_keygen
from pack import _pack
from sgx import sgx
from uppack import broadcast_uppack, attribute_unpack


def hm_encrypt(tyke, chm_b, cACL):
    if tyke == 2:
        sec_ACL = 3
        f = sgx(tyke, sec_ACL, cACL)
        if f:
            chm = broadcast_uppack(chm_b)
            secret_information_list, IV = broadcast_keygen(sec_ACL)
            hm = Broadcast_decryption(secret_information_list, IV, chm)
            buf = _pack(tyke, "".encode(), hm, "".encode())
            return buf
        else:
            return ""
    elif tyke == 4:
        sec_ACL = ['ONE', 'TWO', 'THREE']
        f = sgx(tyke, sec_ACL, cACL)
        if f:
            chm = attribute_unpack(chm_b)
            (pk, msk) = attribute_keygen()
            hm = decrypt(pk, msk, sec_ACL, chm)
            buf = _pack(tyke, "".encode(), hm, "".encode())
            return buf
        else:
            return ""
    elif tyke == 6:
        sec_ACL = 'label'
        f = sgx(tyke, sec_ACL, cACL)
        if f:
            chm = chm_b
            hm = chm
            buf = _pack(tyke, "".encode(), hm, "".encode())
            return buf
        else:
            return ""
    else:
        return ""