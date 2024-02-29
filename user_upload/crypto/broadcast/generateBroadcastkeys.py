from crypto.broadcast.fullbinarytree import deleteleaves, combinecorrectleaves, generatesecretinformation, generateciphertext, locatesameelement
from crypto.broadcast.AESCBC import AESCipher, generateAESCBCkey, generateAESCBCIV
from crypto.broadcast.Streamcipher import xor_crypt_string, generateStreamkey

def Generate_broadcast_key(num_receivers):
    num_totalnodes = 2 * num_receivers - 1
    generateAESCBCkey(num_totalnodes)
    generateAESCBCIV()
    generatesecretinformation(num_receivers, num_totalnodes)
    generateStreamkey()

def Broadcast_encryption(num_leaf, nodes_deleted, key_streamcipher, m):
    mm = xor_crypt_string(m, key_streamcipher, encode=True)
    
    num_nodes = 2*num_leaf - 1
    flag = [True for i in range(num_nodes)]
    label = []
    flag = deleteleaves(flag,nodes_deleted)

    label = combinecorrectleaves(flag, label, num_leaf, num_nodes)
    
    list_content = generateciphertext(label, mm, 7)
    return list_content

def Broadcast_decryption(secret_information_list, IV, list_content):

    location_A, location_B = locatesameelement(list_content,secret_information_list)

    session_key = secret_information_list[location_B]
    stream_key = AESCipher(session_key).decrypt(list_content[location_A], IV)

    plaintext = xor_crypt_string(list_content[len(list_content) - 1], stream_key, decode = True)
    return plaintext