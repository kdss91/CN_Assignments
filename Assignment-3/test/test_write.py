from client.httpObject import HTTPObject
from client.httpConnection import HTTPConnection as client_HTTPConnection
from threading import Thread
import random
from datetime import datetime
from random import randint
from server.serverParam import ServerParam
from server.httpConnection import HTTPConnection as server_HTTPConnection
from time import sleep

t1 = [41830, 41831, 41832, 41833]
t2 = [8007, 8008, 8009, 8010]
gen = []


def test_write2(p1, p2):
    server_HTTPConnection(ServerParam("httpfs -v -p " + str(p2) + " -d foo"), p1).start_server()


def test_write(p1, p2, val):
    my_http_obj = HTTPObject("httpc post -v -h Content-type:text/plain -h Content-Disposition:inline " +
                             "-d 'This line has been added by thread" + val + "' " + "'localhost:" + str(p2)
                             + "/bar/test.txt'")
    http_con = client_HTTPConnection(my_http_obj, p2)
    http_con.send_request(p1)


for k in range(0, 4):
    random.seed(datetime.now())
    tmp = 0
    while True:
        tmp = randint(0, 3)
        if tmp not in gen:
            gen.append(tmp)
            break
    Thread(target=test_write2, args=(t1[tmp], t2[tmp])).start()

for k in gen:
    sleep(0.5)
    Thread(target=test_write, args=(t1[k], t2[k], str(k))).start()

