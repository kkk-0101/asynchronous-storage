import socket
import time
import threading
from pack import get_len
from log import inquire_time_log
from chain import query_chain
from enhm import hm_encrypt

id = 2
n = 10

txs = [None] * (n + 10)
bufs = [None] * (n + 10)

def Client_send(host, port, tx):
    try:
        sk = socket.socket()
        sk.connect((host, port))
        _tx = get_len(tx)
        sk.sendall(_tx)
        # data = sk.recv(1024)
        print("YES")
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

    timelog = inquire_time_log()
    i_time = time.time()
    cn = 0
    for i in range(n):
        txs[i]=query_chain(id, i)
        cn += 1

    for thread in threads:
        thread.join()

    for i in range(n):
        if txs[i] is None or txs[i] == "":
            cn -= 1
            print(i, " Unable to access")

    e_time = time.time()
    print("chain--- ", str(cn), " --- ", str(e_time - i_time))
    timelog.info('chain--- ' + str(cn) + ' --- ' + str(e_time - i_time))

    i_time = time.time()

    for i in range(n):
        if txs[i] is None or txs[i] == "":
            bufs[i] = ""
        else:
            tx = txs[i]
            tyke = tx["tyke"]
            cACL = tx["cACL"]
            chm_b = tx["chm_b"]
            bufs[i] = hm_encrypt(tyke, chm_b, cACL)

    e_time = time.time()
    print('sgx ', str(cn), ' --- ', str(e_time - i_time))
    timelog.info('sgx ' + str(cn) + ' --- ' + str(e_time - i_time))

    input("按 Enter 键继续...")

    threads = []
    i_time = time.time()

    cn = 0
    for i in range(n):
        j = i % N
        addresse = mes_addresses[j]
        host = addresse[0]
        port = addresse[1]
        if bufs[i] != '':
            thread = threading.Thread(target=Client_send, args=(host, port, bufs[i],))
            threads.append(thread)
            thread.start()
            cn += 1

    for thread in threads:
        thread.join()

    e_time = time.time()
    print("--- ", str(e_time - i_time))
    timelog.info('The time for a user to inquire ' + str(n) + ' data is ' + str(e_time - i_time))


if __name__ == '__main__':
    main()
