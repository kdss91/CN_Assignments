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


def test_read(p1, p2):
    my_http_obj = HTTPObject("httpc get -v -h Content-Disposition:inline 'localhost:" + str(p2) + "/bar/test.txt'")
    http_con = client_HTTPConnection(my_http_obj, p2)
    http_con.send_request(p1)


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
    sleep(0.2)

for k in (gen[0], gen[1]):
    Thread(target=test_write, args=(t1[k], t2[k], str(k))).start()

for k in (gen[2], gen[3]):
    Thread(target=test_read, args=(t1[k], t2[k])).start()
