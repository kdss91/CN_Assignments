from client.httpObject import HTTPObject
from client.httpConnection import HTTPConnection
from threading import Thread


def test_read():
    HTTPConnection.send_request(HTTPObject("httpc get -v -h Content-Disposition:inline '127.0.0.1:8080/bar/test.txt'"))


for k in range(0, 4):
    Thread(target=test_read, args=()).start()
