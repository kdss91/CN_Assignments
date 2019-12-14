import threading
import os
import socket
import time
from filelock import FileLock
from server.httpObject import HTTPObject
from email.utils import formatdate
import pathlib
from python.packet import Packet
import python.packet as packet
import ipaddress

from server.serverParam import ServerParam

client_ip = '127.0.0.1'
router_port = 3000
router_ip = "localhost"
router = (router_ip, router_port)


class HTTPConnection(threading.Thread):
    """class to make connection from server"""

    def __init__(self, server_obj, client_port):
        self._server_name = 'localhost'
        self._server_obj = server_obj
        self.socket_object = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.payload = {}
        self.fin_num = 0
        self.fin_packet_arrived = False  # I added
        self.fin_seq_num = 0  # I added
        self.received_pkt_list = []  # I Added this
        self._handshake_done = False
        self.window_size = 10
        self.num_windows = 0
        self.buffer = []
        self.pkt_sent_count = 0
        """Last Packet"""
        self.last_rc_pkt = 0
        self.ack_window = []
        self.sent_pkt_window = []
        self.ack_window_lock = threading.Lock()
        self.received_all_acks = False
        self.all_acks_list = []
        self.check_flag_aks = False  # for moving window of acks
        self.client_port = client_port

    # To reset configuration
    def res_configuration(self):
        self.buffer = []

    def res_conf2(self):
        self.received_all_acks = False
        self.sent_pkt_window = []
        self.ack_window_lock = threading.Lock()
        self.ack_window = []
        self.check_flag_aks = False

    def print_debug(self, message):
        if getattr(self._server_obj, '_is_verbose') == "true":
            print(message)

    # This will be called from server
    def start_server(self):
        # print("Server Name: ", self._server_name)
        # ServerParam.convert_to_string(self._server_obj)
        try:
            self.socket_object.bind((self._server_name, getattr(self._server_obj, '_port')))
            # print("Server started listening on port: ", getattr(self._server_obj, '_port'))
            # Will keep on listening
            while True:
                data, sender = self.socket_object.recvfrom(1024)
                # Continue to handle packet Start from here
                threading.Thread(target=self.handle_packet, args=(data, sender)).start()
        except socket.error as msg:
            print("Server not started. Try again!!!")
        finally:
            self.socket_object.close()

    # To check in buffer
    def check_in_buffer(self, pkt):
        for pkt2 in self.buffer:
            if pkt.seq_num == pkt2.seq_num:
                return True
        return False

    # Check buffer full  which if full should reset buffer and wait for next window
    def check_buffer_full(self, pkt):
        if not self.fin_packet_arrived:  # I added this variable # fin packed not arrived yet
            if pkt.packet_type == packet.FIN:  # if fin packet arrived
                self.fin_seq_num = pkt.seq_num
                self.fin_packet_arrived = True  # set arrived packet true
                if len(self.buffer) == pkt.seq_num - self.num_windows * self.window_size + 1:
                    for pkts in self.buffer:
                        self.payload[pkts.seq_num] = pkts.payload.decode('utf-8')

                    return True
            elif pkt.packet_type == packet.DATA:
                if len(self.buffer) == self.window_size:
                    for pkts in self.buffer:
                        self.payload[pkts.seq_num] = pkts.payload.decode('utf-8')

                    return True
        else:  # I added this code  # fin is already arrived
            if pkt.packet_type == packet.FIN:  # if fin packet arrived
                self.fin_seq_num = pkt.seq_num
                self.fin_packet_arrived = True
            if len(self.buffer) == self.fin_seq_num - self.num_windows * self.window_size + 1:  # I added fin_seq_num
                for pkts in self.buffer:
                    self.payload[pkts.seq_num] = pkts.payload.decode('utf-8')

                return True
            else:
                return False

    def add_to_buffer(self, pkt):
        if pkt.packet_type == packet.DATA:
            print("Adding to buffer")
        else:
            print("Ack is received")
        if pkt.packet_type == packet.FIN:
            self.last_rc_pkt = pkt.seq_num
            print("FIN received")
        #  So whatever Data Comes it Acks
        if pkt.packet_type == packet.DATA or pkt.packet_type == packet.FIN:
            self.send_ack(pkt)

        if self.fin_num + self.num_windows * self.window_size <= pkt.seq_num < self.fin_num + (
                self.num_windows + 1) * self.window_size:
            if pkt.packet_type == packet.DATA and pkt.seq_num not in self.received_pkt_list:
                if not self.check_in_buffer(pkt):
                    self.buffer.append(pkt)
                    self.received_pkt_list.append(pkt.seq_num)

                    if self.check_buffer_full(pkt):  # from here i removed buffer empty and increasing window number
                        print("Buffer:", self.buffer)
                        self.num_windows += 1
                        self.buffer = []
                        if self.fin_packet_arrived:
                            print("All packets have been received.")
                            # this is only to assemble data
                            self.handle_data(self.last_rc_pkt)
                            return

            if pkt.packet_type == packet.FIN and pkt.seq_num not in self.received_pkt_list:
                print("FIN packet received")
                self.fin_packet_arrived = True
                if not self.check_in_buffer(pkt):
                    self.buffer.append(pkt)
                    self.received_pkt_list.append(pkt.seq_num)
                    if self.check_buffer_full(pkt):  # from here i removed buffer empty and increasing window number
                        print("Buffer:", self.buffer)
                        self.num_windows += 1
                        self.buffer = []
                        if self.fin_packet_arrived:
                            print("All packets have been received.")
                            # this is only to assemble data
                            self.handle_data(self.last_rc_pkt)
                            return

    def send_ack(self, pkt):
        global client_ip
        global router
        new_ip = ipaddress.ip_address(socket.gethostbyname(client_ip))
        tmp_pkt = Packet(packet_type=packet.ACK,
                         seq_num=pkt.seq_num,
                         peer_ip_addr=new_ip,
                         peer_port=self.client_port,
                         payload=b'')
        print("Sending Ack#", str(pkt.seq_num))
        self.socket_object.sendto(tmp_pkt.to_bytes(), router)

    #  When packet Comes they come here
    def handle_packet(self, data, sender):
        """receive request from the client and send response"""
        self.print_debug("Connection established with router " + sender[0] + ":" + str(sender[1]) + " at " +
                         time.strftime("%a, %d %b %Y %I:%M:%S %p %Z", time.gmtime()))
        pkt = Packet.from_bytes(data)
        if pkt.packet_type == packet.SYN:
            self.print_debug("SYN packet received.")
            new_ip = ipaddress.ip_address(socket.gethostbyname(client_ip))
            new_pkt = Packet(packet.SYN_ACK, pkt.seq_num, new_ip, self.client_port, ''.encode('utf-8'))
            self.socket_object.sendto(new_pkt.to_bytes(), sender)
            print("Sending syn-ack")
            print("Handshaking is done from side of server")
            self._handshake_done = True

        # When data of ACK packet comes
        elif self._handshake_done:
            if pkt.packet_type == packet.DATA or pkt.packet_type == packet.FIN:
                print("Data#", str(pkt.seq_num))
                print(pkt.payload.decode('utf-8'))
                self.add_to_buffer(pkt)

    #  This is for handling acks after receiving
    def receive_ack(self, data):
        pkt = Packet.from_bytes(data)
        print("Started receiving ack#", str(pkt.seq_num))
        #  These are for ack window size
        start = self.sent_pkt_window[0].seq_num
        end = self.sent_pkt_window[len(self.sent_pkt_window) - 1].seq_num

        #  Check if fin is contained or not
        contains_fin = False
        for pkts in self.sent_pkt_window:
            if pkts.packet_type == packet.FIN:
                contains_fin = True

        #  getting only valid acks
        if pkt.packet_type == packet.ACK and start <= pkt.seq_num <= end:
            self.ack_window_lock.acquire()
            self.all_acks_list.append(pkt.seq_num)
            self.ack_window.append(pkt.seq_num)
            #  if all acks for window have been received
            if len(set(self.ack_window)) == len(self.sent_pkt_window):
                self.received_all_acks = True   # all acks are received
                self.check_flag_aks = True  # All acks are received for
                print("Current Window acks are received,:", self.ack_window)

                # this means every data packet has been sent and ack have been received
                if contains_fin:
                    print("Received ack#", str(pkt.seq_num))
                    self.received_acks_for_all_data = True
                    print("Received acks for all data, continue to receive response.")
                    if self.ack_window_lock.locked():
                        self.ack_window_lock.release()  # I added this
                    print("At last Program ends")
                    return
            else:
                # continue receiving acks
                print("Received ack#", pkt.seq_num)
            if self.ack_window_lock.locked():
                self.ack_window_lock.release()

    def look_ack(self):
        # We are continuously looking for acks
        while not self.received_all_acks:
            # What we are receiving
            data, sender = self.socket_object.recvfrom(1024)
            pkt = Packet.from_bytes(data)
            if pkt.packet_type == packet.ACK:
                self.receive_ack(data)
        # why we are calling this fxn
        self.received_all_acks = False

    # This is for particular packet
    def check_resend_pkt(self, pkt):
        global router
        time.sleep(1)
        if len(self.sent_pkt_window) == len(set(self.ack_window)):
            return

        while pkt.seq_num not in set(self.ack_window):
            if pkt.seq_num not in self.all_acks_list:
                time.sleep(0.5)
                print("Re-sending packet#", pkt.seq_num)
                self.socket_object.sendto(pkt.to_bytes(), router)
            else:
                break

    def create_payload_packets(self, payload, last_pkt):
        print("Creating packets started")
        global client_ip
        global router
        self.res_conf2()
        MAX_PAYLOAD = packet.MAX_LEN - packet.MIN_LEN
        current_byte = [0, 0]

        def num_bytes(n):
            current_byte[0], current_byte[1] = current_byte[1], current_byte[1] + n
            return payload[current_byte[0]: current_byte[1]]

        remaining_data = len(payload)  # initialize
        tmp = last_pkt
        print("Payload:", payload)
        self.all_acks_list = self.received_pkt_list
        while remaining_data > 0:
            self.res_conf2()
            while self.pkt_sent_count < self.window_size:
                print("sending packet %d", tmp)
                if remaining_data > MAX_PAYLOAD:
                    tmp = tmp + 1
                    new_ip = ipaddress.ip_address(socket.gethostbyname(client_ip))
                    p = Packet(packet_type=packet.DATA,
                               seq_num=tmp,
                               peer_ip_addr=new_ip,
                               peer_port=self.client_port,
                               payload=num_bytes(MAX_PAYLOAD))
                    self.socket_object.sendto(p.to_bytes(), router)
                    threading.Thread(target=self.look_ack, args=()).start()
                    self.sent_pkt_window.append(p)

                    # Increase Send window +1
                    self.pkt_sent_count += 1

                    # decreasing payload
                    remaining_data -= MAX_PAYLOAD
                    Packet.packet_num += 1
                    # For same packet we are threading for resend
                    threading.Thread(target=self.check_resend_pkt, args=(p,)).start()
                    print("not last packet")
                else:
                    tmp += 1
                    new_ip = ipaddress.ip_address(socket.gethostbyname(client_ip))
                    p = Packet(packet_type=packet.FIN,
                               seq_num=tmp,
                               peer_ip_addr=new_ip,
                               peer_port=self.client_port,
                               payload=num_bytes(remaining_data))
                    self.socket_object.sendto(p.to_bytes(), router)
                    """We have fin number also"""
                    self.fin_num = tmp
                    self.sent_pkt_window.append(p)
                    threading.Thread(target=self.look_ack, args=()).start()
                    self.pkt_sent_count += 1
                    remaining_data -= remaining_data
                    print("remaining data " + str(remaining_data))
                    print("is last packet")
                    threading.Thread(target=self.check_resend_pkt, args=(p,)).start()
                    break
            while not self.check_flag_aks:
                pass
            self.check_flag_aks = False  # I changed it from True to False
            self.pkt_sent_count = 0

    def handle_data(self, last_pkt):
        global client_ip
        global router
        str_received_data = ""
        for some_data in sorted(self.payload.items()):
            str_received_data += some_data[1]
        print("Received data")
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
        print("Sending response message to router " + router[0])
        print(message)
        self.create_payload_packets(message.encode('utf-8'), last_pkt)
