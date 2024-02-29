import time
import socket
import threading
from access_control import _Attribute, _Broadcast, _Threshold
from data_generation import tx_generator
from log import write_time_log
from pack import get_len

n = 1
txs = [None] * (n + 10)

def Client_send(host, port, tx):
    try:
        sk = socket.socket()
        sk.connect((host, port))
        _tx = get_len(tx)
        sk.sendall(_tx)
        # data = sk.recv(1024)
        # print("tx---",len(_tx))
        sk.close()
    except:
        print("NO")


def main():
    N = 4
    mes_addresses = [None] * N
    with open('../user_client/hosts_message.config', 'r') as hosts:
        for line in hosts:
            params = line.split()
            pid = int(params[0])
            priv_ip = params[1]
            pub_ip = params[2]
            port = int(params[3])
            # print(pid, priv_ip ,pub_ip ,port)
            if pid not in range(N):
                continue
            mes_addresses[pid] = (pub_ip, port)
    assert all([node is not None for node in mes_addresses])

    threads = []

    id = 2
    k = 3
    b = [None] * (n + 10)

    for i in range(n):
        b[i] = tx_generator(250)

    timelog = write_time_log()
    i_time = time.time()
    if k == 1:
        # Attribute encryption
        for i in range(n):
            m = b[i].encode()
            txs[i] = _Attribute(id, m)
            id += 1
    elif k == 2:
        # Broadcast encryption
        for i in range(n):
            m = b[i].encode()
            txs[i] = _Broadcast(id, m)
            id += 1
    else:
        # Threshold encryption
        for i in range(n):
            m = b[i].encode()
            txs[i] = _Threshold(id, m)
            id += 1

    for thread in threads:
        thread.join()

    e_time = time.time()
    timelog.info('The encryption time of ' + str(n) +
                 ' data is ' + str((e_time - i_time)))
    print(str((e_time - i_time)))
    input("按 Enter 键继续...")
    threads = []
    i_time = time.time()

    for i in range(n):
        j = i % N
        addresse = mes_addresses[j]
        host = addresse[0]
        port = addresse[1]
        # Client_send(host, port, txs[i])
        thread = threading.Thread(
            target=Client_send, args=(host, port, txs[i], ))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    e_time = time.time()
    timelog.info(str(n) + ' pieces of data are sent in ' +
                 str(e_time - i_time))
    print(str(e_time - i_time))


if __name__ == '__main__':
    main()
