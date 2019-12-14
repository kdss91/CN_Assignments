from client.httpObject import HTTPObject
from client.httpConnection import HTTPConnection
from threading import Thread


def test_write(val):
    HTTPConnection.send_request(HTTPObject("httpc post -v -h Content-type:text/plain -h Content-Disposition:inline " +
                                           "-d 'This line has been added by thread" + val + "' " +
                                           "'127.0.0.1/bar/test.txt'"))


for k in range(0, 4):
    Thread(target=test_write, args=(str(k))).start()
