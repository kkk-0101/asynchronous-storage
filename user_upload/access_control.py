from crypto.attribute.att_encrypt import encrypt
from crypto.broadcast.generateBroadcastkeys import Broadcast_encryption
from crypto.rsa.rsa_main import rsa_encipher
from crypto.threshold._threshold import Threshold_encryption
from generate_key import rsa_keygen, key_streamcipher_gen, attribute_keygen
from hashup import _hash
from pack import broadcast_pack, _pack_chain, _pack, attribute_pack


def _Broadcast(id, m):
    key_chain = str(id)
    print("key_chain---", key_chain)
    nodes_deleted = [4]
    public_key = rsa_keygen()
    key_streamcipher = key_streamcipher_gen()
    ACL = [3, 5, 6]
    ACL = ', '.join(map(str, ACL))
    ccACL = rsa_encipher(public_key, ACL.encode(
        "ISO-8859-1")).decode("ISO-8859-1")
    hm = _hash(m)
    cm = Broadcast_encryption(4, nodes_deleted, key_streamcipher, m)
    chm = Broadcast_encryption(4, nodes_deleted, key_streamcipher, hm)
    chm_str = broadcast_pack(chm).decode("ISO-8859-1")
    tyke = 1
    fields = _pack_chain(tyke, key_chain, chm_str, ccACL)
    buf = _pack(tyke, fields, hm, cm)
    return buf


def _Attribute(id, m):
    key_chain = str(id)
    print("key_chain---", key_chain)
    (pk, msk) = attribute_keygen()
    policy_str = '((ONE and THREE) and (TWO OR FOUR))'
    ACL = policy_str
    public_key = rsa_keygen()
    ccACL = rsa_encipher(public_key, ACL.encode(
        "ISO-8859-1")).decode("ISO-8859-1")
    hm = _hash(m)
    cm = encrypt(pk, msk, policy_str, m)
    chm = encrypt(pk, msk, policy_str, hm)
    chm_str = attribute_pack(chm).decode("ISO-8859-1")
    tyke = 3
    fields = _pack_chain(tyke, key_chain, chm_str, ccACL)
    buf = _pack(tyke, fields, hm, cm)
    return buf


def _Threshold(id, m):
    key_chain = str(id)
    print("key_chain---", key_chain)
    hm = _hash(m)
    chm = hm.decode("ISO-8859-1")
    ACL = 'label'
    public_key = rsa_keygen()
    ccACL = rsa_encipher(public_key, ACL.encode(
        "ISO-8859-1")).decode("ISO-8859-1")
    cm = Threshold_encryption(m, ACL)
    tyke = 5
    fields = _pack_chain(tyke, key_chain, chm, ccACL)
    buf = _pack(tyke, fields, hm, cm)
    return buf