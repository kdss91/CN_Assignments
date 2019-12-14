import socket
from client.httpObject import HTTPObject
import time


class HTTPConnection:
    """Class to make HTTP connection to the server"""

    @staticmethod
    def send_request(http_object):
        if HTTPObject.get_req_type(http_object) == "GET":
            HTTPConnection.send_get_request(http_object)  # send GET request based on type
        else:
            HTTPConnection.send_post_request(http_object)  # send POST request based on type

    @staticmethod
    def send_post_request(http_object):
        # HTTPObject.convert_to_string(http_object)  # print request object
        socket_object = socket.socket()  # create socket object
        try:
            socket_object.connect(
                (HTTPObject.get_host(http_object), HTTPObject.get_port(http_object)))  # connect to server
            socket_object.settimeout(2);  # set timeout to 2sec
            if socket.gethostbyaddr(socket_object.getpeername()[0])[0]:  # check remote server name
                print("Connected to server.....\n")
        except socket.error as msg:  # handle socket errors
            print("Cannot connect to server. Try again!!!")
            return
        message = "POST " + str(HTTPObject.get_path(http_object)) + " HTTP/1.1\r\n"
        message += "Host: " + str(HTTPObject.get_host(http_object)) + "\r\n"
        for keys in HTTPObject.get_headers(http_object):  # iterate over headers stored in dictionary
            message += keys + ": " + HTTPObject.get_headers(http_object)[keys] + "\r\n"
        if HTTPObject.get_inline(http_object) == "true":  # check if data is provided as inline
            if "Content-Type" not in HTTPObject.get_headers(http_object):
                message += "Content-Type: text/plain" + "\r\n"
            message += "Content-Length: " + str(len(HTTPObject.get_data(http_object))) + "\r\n\r\n"
            message += str(HTTPObject.get_data(http_object))
        elif HTTPObject.get_read_file(http_object) == "true":  # check if data is to be read from the file
            if "Content-Type" not in HTTPObject.get_headers(http_object):
                if str(HTTPObject.get_file1(http_object)).endswith(".txt"):
                    message += "Content-Type: text/plain" + "\r\n"
                elif str(HTTPObject.get_file1(http_object)).endswith(".html"):
                    message += "Content-Type: text/html" + "\r\n"
                elif str(HTTPObject.get_file1(http_object)).endswith(".xml"):
                    message += "Content-Type: text/xml" + "\r\n"
                elif str(HTTPObject.get_file1(http_object)).endswith(".json"):
                    message += "Content-Type: application/json" + "\r\n"
                else:
                    message += "Content-Type: text/plain" + "\r\n"
            message += "Content-Length: " + str(len(HTTPConnection.read_from_file(HTTPObject.get_file1(http_object)))) \
                       + "\r\n\r\n"
            message += HTTPConnection.read_from_file(HTTPObject.get_file1(http_object))
        print("Sending message:\n")
        print(message)
        socket_object.sendall(bytes(message, 'utf-8'))  # send message to remote server
        HTTPConnection.receive_response(http_object, socket_object)  # receive response from the server

    @staticmethod
    def send_get_request(http_object):
        # HTTPObject.convert_to_string(http_object)
        socket_object = socket.socket()  # create socket object
        try:
            socket_object.connect(
                (HTTPObject.get_host(http_object), HTTPObject.get_port(http_object)))  # connect to server
            socket_object.settimeout(2)  # set timeout to 5sec
            if socket.gethostbyaddr(socket_object.getpeername()[0])[0]:  # check remote server name
                print("Connected to server.....")
        except socket.error as msg:  # handle socket errors
            print("Cannot connect to server. Try again!!!")
            return
        message = "GET " + str(HTTPObject.get_path(http_object)) + " HTTP/1.1\r\n"
        message += "Host: " + str(HTTPObject.get_host(http_object)) + "\r\n"
        for keys in HTTPObject.get_headers(http_object):  # iterate over headers stored in dictionary
            message += keys + ": " + HTTPObject.get_headers(http_object)[keys] + "\r\n"
        if "Content-Type" not in HTTPObject.get_headers(http_object):
            if str(HTTPObject.get_path(http_object)).endswith(".txt"):
                message += "Content-Type: text/plain" + "\r\n"
            elif str(HTTPObject.get_path(http_object)).endswith(".html"):
                message += "Content-Type: text/html" + "\r\n"
            elif str(HTTPObject.get_path(http_object)).endswith(".xml"):
                message += "Content-Type: text/xml" + "\r\n"
            elif str(HTTPObject.get_path(http_object)).endswith(".json"):
                message += "Content-Type: application/json" + "\r\n"
            else:
                message += "Content-Type: text/plain" + "\r\n"
        message += "\r\n"
        print("Sending message:\n")
        print(message + "\n")
        socket_object.sendall(bytes(message, 'utf-8'))  # send message to remote server
        HTTPConnection.receive_response(http_object, socket_object)  # receive response from the server

    @staticmethod
    def read_from_file(file):
        fr = open(file, "r")  # open file in read mode
        return fr.read()  # read the contents of the file till eof

    @staticmethod
    def write_to_file(file, data):
        fw = open(file, "w")  # open file in write mode
        fw.write(data)  # write data to the file

    @staticmethod
    def find_url(body):  # find the url contained in the body
        tmp = body.split("\n")
        for line in tmp:
            if line.find("url") != -1:  # check if word url is contained in the body
                my_url = line.split("\"")
                for word in my_url:
                    if word.startswith("http"):  # check if url starts with http
                        return word
        return ""

    @staticmethod
    def receive_response(http_object, socket_object):
        # print("Inside receive response")
        _receive_data = []
        begin = time.time()  # stores current time
        while 1:
            if _receive_data and time.time() - begin > socket_object.gettimeout():  # break if time elapsed since \
                # last receive is greater than the timeout
                break
            elif time.time() - begin > socket_object.gettimeout() * 2:
                break
            try:
                _tmp = socket_object.recv(2048)  # receive 2048 bytes at a time
                if _tmp:
                    _tmp = _tmp.decode("utf-8")  # convert to text string
                    _receive_data.append(_tmp)  # append to receive array
                    begin = time.time()  # set begin to current time
            except:
                pass
        str_received_data = ''
        for data in _receive_data:
            str_received_data += data  # convert received array to string
        print("Received data:\n")
        # print(str_received_data)
        header_body = str_received_data.split("\r\n\r\n")  # split header and body
        print_data = ''
        if HTTPObject.get_is_verbose(http_object) == "true":  # check if verbose option is enabled
            print_data += header_body[0] + "\n"
        if len(header_body) == 2:  # check if body is contained in received data
            print_data += "\n" + header_body[1] + "\n"
        my_header = header_body[0].split(" ")
        if my_header[1].startswith("3") and 300 <= int(my_header[1]) <= 304:  # check if body contains redirection code
            socket_object.close()
            loc_index = header_body[0].replace("location:", "Location:").find("Location:")  # find location of new url
            start = header_body[0].find(":", loc_index) + 2;  # get start index of new url, +2 for // in http://
            end = header_body[0].find("\r\n", start);  # get end index of new url
            --end  # move to one previous location
            HTTPObject.set_path(http_object, header_body[0][start:end].strip())  # set new path
            HTTPObject.set_url(http_object, HTTPConnection.find_url(header_body[1]))  # set new url
            HTTPConnection.send_request(http_object)  # send new request to redirected url
            return
        headers = {}
        count = 0
        for line in header_body[0].split("\r\n"):
            if count != 0:
                headers[line.split(":")[0].strip()] = line.split(":")[1].strip()
            else:
                count = count + 1
        if "Content-Disposition" in headers:
            if headers["Content-Disposition"].startswith("attachment"):
                pos = (headers["Content-Disposition"]).find("/")
                file = (headers["Content-Disposition"])[pos + 1:]
                if headers["Content-Type"] == "text/plain":
                    file += ".txt"
                elif headers["Content-Type"] == "text/html":
                    file += ".html"
                elif headers["Content-Type"] == "text/xml":
                    file += ".xml"
                elif headers["Content-Type"] == "application/json":
                    file += ".json"
                else:
                    file += ".txt"
                if len(header_body) > 1:
                    HTTPConnection.write_to_file(file, header_body[1])
        if HTTPObject.get_write_file(http_object) == "true":  # check if data is to be written to a file
            HTTPConnection.write_to_file(HTTPObject.get_file2(http_object), print_data)  # write data to the file
        else:
            print(print_data)  # print data to console
