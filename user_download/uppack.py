from io import BytesIO
import struct

from ABE.msp import MSP
from charm.toolbox.pairinggroup import PairingGroup


def broadcast_uppack(b):
    buf = BytesIO(b)
    list_content = []
    list_1_len_bytes = buf.read(4)
    list_1_len, = struct.unpack("<i", list_1_len_bytes)
    list_1 = []
    for i in range(list_1_len):
        s_bytes = buf.read(4)
        s, = struct.unpack("<i", s_bytes)
        list_1.append(s)
    list_content.append(list_1)

    for i in range(list_1_len):
        va_len_bytes = buf.read(4)
        va_len, = struct.unpack("<i", va_len_bytes)
        va_bytes = buf.read(va_len)
        list_content.append(va_bytes)

    fx_len_bytes = buf.read(4)
    fx_len, = struct.unpack("<i", fx_len_bytes)
    fx_bytes = buf.read(fx_len)
    list_content.append(fx_bytes)
    return list_content


def element_to_bytes(element):
    group = PairingGroup('SS512')
    serialized_bytes = group.serialize(element)

    return serialized_bytes


def bytes_to_element(element_bytes):
    group = PairingGroup('SS512')
    element = group.deserialize(element_bytes)

    return element


def attribute_unpack(b):
    buf = BytesIO(b)

    policy_len_bytes = buf.read(4)
    policy_len, = struct.unpack("<i", policy_len_bytes)
    policy_bytes = buf.read(policy_len)
    policy_string = policy_bytes.decode()
    verbose = False
    pairing_group = PairingGroup('SS512')
    util = MSP(pairing_group, verbose)
    policy = util.createPolicy(policy_string)

    C_0 = []
    C_0_len_bytes = buf.read(4)
    C_0_len, = struct.unpack("<i", C_0_len_bytes)
    for i in range(C_0_len):
        x_len_bytes = buf.read(4)
        x_len, = struct.unpack("<i", x_len_bytes)
        x_bytes = buf.read(x_len)
        x = bytes_to_element(x_bytes)
        C_0.append(x)

    C = {}
    C_len_bytes = buf.read(4)
    C_len, = struct.unpack("<i", C_len_bytes)
    for i in range(C_len):
        x_len_bytes = buf.read(4)
        x_len, = struct.unpack("<i", x_len_bytes)
        x_bytes = buf.read(x_len)
        x = x_bytes.decode()

        y = []
        y_len_bytes = buf.read(4)
        y_len, = struct.unpack("<i", y_len_bytes)
        for j in range(y_len):
            z_len_bytes = buf.read(4)
            z_len, = struct.unpack("<i", z_len_bytes)
            z_bytes = buf.read(z_len)
            z = bytes_to_element(z_bytes)
            y.append(z)
        C[x] = y

    Cp_len_bytes = buf.read(4)
    Cp_len, = struct.unpack("<i", Cp_len_bytes)
    Cp_bytes = buf.read(Cp_len)
    Cp = bytes_to_element(Cp_bytes)

    ctxt = {'policy': policy, 'C_0': C_0, 'C': C, 'Cp': Cp}

    msg_len_bytes = buf.read(4)
    msg_len, = struct.unpack("<i", msg_len_bytes)
    msg_bytes = buf.read(msg_len)

    return [ctxt, msg_bytes]