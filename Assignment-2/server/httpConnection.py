import threading
import os
import socket
import time
from filelock import FileLock
from server.httpObject import HTTPObject
from server.serverParam import ServerParam
from email.utils import formatdate
import pathlib


class HTTPConnection(threading.Thread):
    """class to make connection from server"""

    def __init__(self, server_obj):
        self._server_name = '127.0.0.1'
        self._server_obj = server_obj
        self._socket = socket.socket()
        self._response = ''

    def print_debug(self, message):
        if getattr(self._server_obj, '_is_verbose') == "true":
            print(message)

    def start_server(self):
        print("Server Name: ", self._server_name)
        ServerParam.convert_to_string(self._server_obj)
        try:
            self._socket.bind((self._server_name, getattr(self._server_obj, '_port')))
            self._socket.listen(10)
            print("Server started listening on port: ", getattr(self._server_obj, '_port'))
            while True:
                conn, addr = self._socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()
        except socket.error as msg:
            print("Server not started. Try again!!!")
        finally:
            self._socket.close()

    def handle_client(self, conn, addr):
        """receive request from the client and send response"""
        self.print_debug("Connection established with client " + addr[0] + ":" + str(addr[1]) + " at " +
                         time.strftime("%a, %d %b %Y %I:%M:%S %p %Z", time.gmtime()))
        try:
            while True:
                _receive_data = []
                _tmp = conn.recv(2048)
                if _tmp:
                    _tmp = _tmp.decode("utf-8")  # convert to text string
                    _receive_data.append(_tmp)  # append to receive array
                else:
                    break
                str_received_data = ''
                for data in _receive_data:
                    str_received_data += data  # convert received array to string
                print(str_received_data)
                first_line = str_received_data.split("\r\n", 1)
                req_type = first_line[0].split(" ")[0]
                uri = first_line[0].split(" ")[1]
                headers = {}
                header_body = str_received_data.split("\r\n\r\n")
                count = 0
                for line in header_body[0].split("\r\n"):
                    if count != 0:
                        headers[line.split(":")[0].strip()] = line.split(":")[1].strip()
                    else:
                        count = count + 1
                count = -1
                body = ''
                if len(header_body) > 1:
                    if header_body[0].find("Content-Length:") > -1:
                        last = header_body[0].find("\r\n", header_body[0].find("Content-Length:"))
                        --last
                        count = int(header_body[0][header_body[0].find("Content-Length:") + 16:last])
                        body = ''
                        for line in header_body[1]:
                            if count > 0:
                                body += line
                            --count
                http_object = HTTPObject(req_type, uri, headers, body)
                # Sending code
                message = 'HTTP/1.1 '
                if ".." in uri:
                    self.print_debug("Access Denied " + uri)
                    message += "403 Forbidden" + "\r\n"
                    message += "Content-type: text/plain" + "\r\n"
                    message += "Content-Disposition: inline" + "\r\n\r\n"
                else:
                    if HTTPObject.get_req_type(http_object).lower() == "get":
                        try:
                            if HTTPObject.get_uri(http_object) == "/":
                                message += "200 OK" + "\r\n"
                                message += "Date: " + formatdate(timeval=None, localtime=False, usegmt=True) + "\r\n"
                                message += "Server:" + socket.gethostname() + "\r\n"
                                self.print_debug("GET DIR " + os.getcwd().replace("\\", "/") + "/" +
                                                 getattr(self._server_obj, '_path') + HTTPObject.get_uri(http_object))
                                working_dir = os.getcwd().replace("\\", "/") + "/" + getattr(self._server_obj, '_path') \
                                              + HTTPObject.get_uri(http_object)
                                list_files = os.listdir(working_dir)
                                str_files = ''
                                for file in list_files:
                                    str_files += file + "\r\n"
                                message += "Content-Length: " + str(len("{\r\n" + str_files + "}")) + "\r\n"
                                message += "Content-Type: text/directory" + "\r\n"
                                if "Content-Disposition" in HTTPObject.get_headers(http_object):
                                    if HTTPObject.get_headers(http_object)["Content-Disposition"] == "attachment":
                                        message += "Content-Disposition: attachment/output" + "\r\n"
                                    else:
                                        message += "Content-Disposition: " + HTTPObject.get_headers(http_object) \
                                                    ["Content-Disposition"] + "\r\n"
                                elif "inline" in HTTPObject.get_uri(http_object):
                                    message += "Content-Disposition: inline" + "\r\n"
                                else:
                                    message += "Content-Disposition: attachment/output" + "\r\n"
                                message += "\r\n"
                                message += "{\r\n" + str_files + "}"
                            else:
                                working_file = os.getcwd().replace("\\", "/") + "/" + getattr(self._server_obj, '_path') \
                                               + HTTPObject.get_uri(http_object)
                                if "Content-Type" in HTTPObject.get_headers(http_object):
                                    if HTTPObject.get_headers(http_object)["Content-Type"] == "text/plain":
                                        if not working_file.endswith(".txt"):
                                            working_file += ".txt"
                                    elif HTTPObject.get_headers(http_object)["Content-Type"] == "text/html":
                                        if not working_file.endswith(".html"):
                                            working_file += ".html"
                                    elif HTTPObject.get_headers(http_object)["Content-Type"] == "text/html":
                                        if not working_file.endswith(".html"):
                                            working_file += ".html"
                                    elif HTTPObject.get_headers(http_object)["Content-Type"] == "text/xml":
                                        if not working_file.endswith(".xml"):
                                            working_file += ".xml"
                                    elif HTTPObject.get_headers(http_object)["Content-Type"] == "application/json":
                                        if not working_file.endswith(".json"):
                                            working_file += ".json"
                                self.print_debug("GET File " + working_file)
                                if not os.path.isfile(working_file):
                                    message += "404 Not Found" + "\r\n"
                                    message += "Date: " + formatdate(timeval=None, localtime=False,
                                                                     usegmt=True) + "\r\n"
                                    message += "Server: " + socket.gethostname() + "\r\n"
                                    if "Content-Disposition" in HTTPObject.get_headers(http_object):
                                        if HTTPObject.get_headers(http_object)["Content-Disposition"] == "attachment":
                                            message += "Content-Disposition: attachment/output" + "\r\n"
                                        else:
                                            message += "Content-Disposition: " + HTTPObject.get_headers(http_object) \
                                                        ["Content-Disposition"] + "\r\n"
                                    elif "inline" in HTTPObject.get_uri(http_object):
                                        message += "Content-Disposition: inline" + "\r\n"
                                    else:
                                        message += "Content-Disposition: inline" + "\r\n"
                                    message += "\r\n"
                                else:
                                    message += "200 OK" + "\r\n"
                                    message += "Date: " + formatdate(timeval=None, localtime=False,
                                                                     usegmt=True) + "\r\n"
                                    message += "Server: " + socket.gethostname() + "\r\n"
                                    fr = open(working_file, 'r')
                                    file_data = fr.read()
                                    if "Content-Type" in HTTPObject.get_headers(http_object):
                                        message += "Content-Type: " + HTTPObject.get_headers(http_object)[
                                                    "Content-Type"] + "\r\n"
                                    else:
                                        if working_file.endswith(".txt"):
                                            message += "Content-Type: text/plain" + "\r\n"
                                        elif working_file.endswith(".html"):
                                            message += "Content-Type: text/html" + "\r\n"
                                        elif working_file.endswith(".xml"):
                                            message += "Content-Type: text/xml" + "\r\n"
                                        elif working_file.endswith(".json"):
                                            message += "Content-Type: application/json" + "\r\n"
                                        else:
                                            message += "Content-Type: text/plain" + "\r\n"
                                    message += "Content-Length: " + str(len(file_data)) + "\r\n"
                                    if "Content-Disposition" in HTTPObject.get_headers(http_object):
                                        if HTTPObject.get_headers(http_object)["Content-Disposition"] == "attachment":
                                            message += "Content-Disposition: attachment/output" + "\r\n"
                                        else:
                                            message += "Content-Disposition: " + HTTPObject.get_headers(http_object) \
                                                        ["Content-Disposition"] + "\r\n"
                                    elif "inline" in HTTPObject.get_uri(http_object):
                                        message += "Content-Disposition: inline" + "\r\n"
                                    else:
                                        message += "Content-Disposition: inline" + "\r\n"
                                    message += "\r\n"
                                    message += file_data
                        except OSError as msg:
                            self.print_debug(msg)
                            message = "HTTP/1.1 400 Bad Request\r\n\r\n"
                            message += msg.strerror
                    elif HTTPObject.get_req_type(http_object).lower() == "post":
                        try:
                            if HTTPObject.get_uri(http_object) != "":
                                working_file = os.getcwd().replace("\\", "/") + "/" + getattr(self._server_obj, '_path') \
                                               + HTTPObject.get_uri(http_object)
                                if "Content-Type" in HTTPObject.get_headers(http_object):
                                    if HTTPObject.get_headers(http_object)["Content-Type"] == "text/plain":
                                        if not working_file.endswith(".txt"):
                                            working_file += ".txt"
                                    elif HTTPObject.get_headers(http_object)["Content-Type"] == "text/html":
                                        if not working_file.endswith(".html"):
                                            working_file += ".html"
                                    elif HTTPObject.get_headers(http_object)["Content-Type"] == "text/html":
                                        if not working_file.endswith(".html"):
                                            working_file += ".html"
                                    elif HTTPObject.get_headers(http_object)["Content-Type"] == "text/xml":
                                        if not working_file.endswith(".xml"):
                                            working_file += ".xml"
                                    elif HTTPObject.get_headers(http_object)["Content-Type"] == "application/json":
                                        if not working_file.endswith(".json"):
                                            working_file += ".json"
                                self.print_debug("POST File " + working_file)
                                path = pathlib.Path(working_file)
                                path.parent.mkdir(parents=True, exist_ok=True)
                                lock_path = working_file + ".lock"
                                my_lock = FileLock(lock_path, timeout=2)
                                my_lock.acquire()
                                try:
                                    open(working_file, "a").write(HTTPObject.get_data(http_object) + "\n")
                                finally:
                                    my_lock.release()
                                message += "200 OK" + "\r\n"
                                message += "Date: " + formatdate(timeval=None, localtime=False, usegmt=True) + "\r\n"
                                message += "Server: " + socket.gethostname() + "\r\n"
                                if "Content-Type" in HTTPObject.get_headers(http_object):
                                    message += "Content-Type: " + HTTPObject.get_headers(http_object)[
                                        "Content-Type"] + "\r\n"
                                else:
                                    if working_file.endswith(".txt"):
                                        message += "Content-Type: text/plain" + "\r\n"
                                    elif working_file.endswith(".html"):
                                        message += "Content-Type: text/html" + "\r\n"
                                    elif working_file.endswith(".json"):
                                        message += "Content-Type: application/json" + "\r\n"
                                    elif working_file.endswith(".xml"):
                                        message += "Content-Type: text/xml" + "\r\n"
                                    else:
                                        message += "Content-Type: text/plain" + "\r\n"
                                message += "Content-Length: " + str(len(HTTPObject.get_data(http_object))) + "\r\n"
                                if "Content-Disposition" in HTTPObject.get_headers(http_object):
                                    if HTTPObject.get_headers(http_object)["Content-Disposition"] == "attachment":
                                        message += "Content-Disposition: attachment/output" + "\r\n"
                                    else:
                                        message += "Content-Disposition: " + HTTPObject.get_headers(http_object) \
                                            ["Content-Disposition"] + "\r\n"
                                elif "inline" in HTTPObject.get_uri(http_object):
                                    message += "Content-Disposition: inline" + "\r\n"
                                else:
                                    message += "Content-Disposition: inline" + "\r\n"
                                message += "\r\n"
                                message += HTTPObject.get_data(http_object)
                        except OSError as msg:
                            self.print_debug(msg)
                            message = "HTTP/1.1 400 Bad Request\r\n\r\n"
                            message += msg.strerror
                print("Sending response message to client " + addr[0])
                print(message)
                conn.sendall(bytes(message, 'utf-8'))
                self.print_debug("Connection closed with client " + addr[0] + ":" + str(addr[1]) + " at " +
                                 time.strftime("%a, %d %b %Y %I:%M:%S %p %Z", time.gmtime()))
                break
        finally:
            conn.close()
