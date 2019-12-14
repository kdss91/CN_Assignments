import socket
from client.httpObject import HTTPObject
import time
from python.packet import Packet
import python.packet as packet
import ipaddress
import threading

router_ip = "localhost"
server_ip = '127.0.0.1'
router_port = 3000
router = (router_ip, router_port)


class HTTPConnection:
    """Class to make HTTP connection to the server"""

    def __init__(self, http_object, server_port):
        self.check_flag_aks = False  # for moving window of acks
        # self.seq = 0
        self.socket_object = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ack_window = []
        self.sent_pkt_window = []
        self.ack_window_lock = threading.Lock()
        self.window_size = 10
        self.pkt_sent_count = 0
        self.next_pkt_num = 0
        self.next_pkt_ack = 0
        self.received_all_acks = False
        self.received_acks_for_all_data = False
        self.num_windows = 0
        self.buffer = []
        self.payload = {}
        self.fin_num = 0
        self.http_object = http_object
        self.all_acks_list = []
        self.all_packet_received = []
        self.fin_packet_arrived = False
        self.fin_seq_num = 0
        self.last_window_seq_num = 0
        self.server_port = server_port

    def res_configuration(self):
        self.seq = 0
        self.ack_window = []
        self.sent_pkt_window = []
        self.ack_window_lock = threading.Lock()
        self.window_size = 10
        self.pkt_sent_count = 0
        self.received_all_acks = False
        self.next_pkt_num = 0  # should we reset this
        self.next_pkt_ack = 0
        self.check_flag_aks = False

    def res_conf2(self):
        pass

    def perform_handshaking(self, client_port):
        global server_ip
        global router
        new_ip = ipaddress.ip_address(socket.gethostbyname(server_ip))
        pkt = Packet(packet.SYN, Packet.packet_num, new_ip, self.server_port, ''.encode('utf-8'))
        self.socket_object.bind(('127.0.0.1', client_port))
        self.socket_object.sendto(pkt.to_bytes(), router)
        res, rout = self.socket_object.recvfrom(1024)
        pkt = Packet.from_bytes(res)
        if pkt.packet_type == packet.SYN_ACK:
            print("Received SYN-ACK packet.")
            new_pkt = Packet(packet.ACK, pkt.seq_num, new_ip, self.server_port, ''.encode('utf-8'))
            self.socket_object.sendto(new_pkt.to_bytes(), rout)
        else:
            print("Received an invalid packet during handshaking.")
            self.perform_handshaking(client_port)

    # this the first function called from client driver
    def send_request(self, client_port):
        print("Sending request")
        # Here before doing anything we are performing handshaking
        self.perform_handshaking(client_port)

        # from here we start things
        if HTTPObject.get_req_type(self.http_object) == "GET":
            self.send_get_request()  # send GET request based on type
        else:
            self.send_post_request()  # send POST request based on type

    def send_post_request(self):
        # HTTPObject.convert_to_string(self.http_object)  # print request object
        message = "POST " + str(HTTPObject.get_path(self.http_object)) + " HTTP/1.1\r\n"
        message += "Host: " + str(HTTPObject.get_host(self.http_object)) + "\r\n"
        for keys in HTTPObject.get_headers(self.http_object):  # iterate over headers stored in dictionary
            message += keys + ": " + HTTPObject.get_headers(self.http_object)[keys] + "\r\n"
        if HTTPObject.get_inline(self.http_object) == "true":  # check if data is provided as inline
            if "Content-Type" not in HTTPObject.get_headers(self.http_object):
                message += "Content-Type: text/plain" + "\r\n"
            message += "Content-Length: " + str(len(HTTPObject.get_data(self.http_object))) + "\r\n\r\n"
            message += str(HTTPObject.get_data(self.http_object))
        elif HTTPObject.get_read_file(self.http_object) == "true":  # check if data is to be read from the file
            if "Content-Type" not in HTTPObject.get_headers(self.http_object):
                if str(HTTPObject.get_file1(self.http_object)).endswith(".txt"):
                    message += "Content-Type: text/plain" + "\r\n"
                elif str(HTTPObject.get_file1(self.http_object)).endswith(".html"):
                    message += "Content-Type: text/html" + "\r\n"
                elif str(HTTPObject.get_file1(self.http_object)).endswith(".xml"):
                    message += "Content-Type: text/xml" + "\r\n"
                elif str(HTTPObject.get_file1(self.http_object)).endswith(".json"):
                    message += "Content-Type: application/json" + "\r\n"
                else:
                    message += "Content-Type: text/plain" + "\r\n"
            message += "Content-Length: " + str(
                len(HTTPConnection.read_from_file(HTTPObject.get_file1(self.http_object)))) \
                       + "\r\n\r\n"
            message += HTTPConnection.read_from_file(HTTPObject.get_file1(self.http_object))
        print("Sending message:\n")
        print(message)
        self.communicate_with_server(message.encode('utf-8'))
        print("Data Send Complete")
        # HTTPConnection.receive_response(self.http_object, socket_object)  # receive response from the server

    # this is called when get request is opted
    def send_get_request(self):
        # HTTPObject.convert_to_string(http_object)
        message = "GET " + str(HTTPObject.get_path(self.http_object)) + " HTTP/1.1\r\n"
        message += "Host: " + str(HTTPObject.get_host(self.http_object)) + "\r\n"
        for keys in HTTPObject.get_headers(self.http_object):  # iterate over headers stored in dictionary
            message += keys + ": " + HTTPObject.get_headers(self.http_object)[keys] + "\r\n"
        if "Content-Type" not in HTTPObject.get_headers(self.http_object):
            if str(HTTPObject.get_path(self.http_object)).endswith(".txt"):
                message += "Content-Type: text/plain" + "\r\n"
            elif str(HTTPObject.get_path(self.http_object)).endswith(".html"):
                message += "Content-Type: text/html" + "\r\n"
            elif str(HTTPObject.get_path(self.http_object)).endswith(".xml"):
                message += "Content-Type: text/xml" + "\r\n"
            elif str(HTTPObject.get_path(self.http_object)).endswith(".json"):
                message += "Content-Type: application/json" + "\r\n"
            else:
                message += "Content-Type: text/plain" + "\r\n"
        message += "\r\n"
        print("Sending message:\n")
        print(message + "\n")
        print("Starting to create packets of this message")
        # Here we start for the procedure so packect shoud be created and set and wait for acks
        self.communicate_with_server(message.encode('utf-8'))
        print("Data Send Complete")
        self.received_all_acks = False
        # self.receive_response()  # receive response from the server

    # starting creating packets and also see for acks
    def create_payload_packets(self, payload):
        print("Creating packets started")
        global server_ip
        global router
        self.res_configuration()
        MAX_PAYLOAD = packet.MAX_LEN - packet.MIN_LEN
        current_byte = [0, 0]

        def num_bytes(n):
            current_byte[0], current_byte[1] = current_byte[1], current_byte[1] + n
            return payload[current_byte[0]: current_byte[1]]

        remaining_data = len(payload)  # initialize

        while remaining_data > 0:
            # To reset configuration
            self.res_configuration()
            while self.pkt_sent_count < self.window_size:
                print("sending packet %d" % Packet.packet_num)
                # this is to create packet
                if remaining_data > MAX_PAYLOAD:
                    new_ip = ipaddress.ip_address(socket.gethostbyname(server_ip))
                    p = Packet(packet_type=packet.DATA,
                               seq_num=Packet.packet_num,
                               peer_ip_addr=new_ip,
                               peer_port=self.server_port,
                               payload=num_bytes(MAX_PAYLOAD))
                    # send created packed
                    self.socket_object.sendto(p.to_bytes(), router)
                    threading.Thread(target=self.look_ack, args=()).start()
                    # What ever you are sending append to sent window
                    self.sent_pkt_window.append(p)
                    # Increase Send window +1
                    self.pkt_sent_count += 1

                    # decreasing payload
                    remaining_data -= MAX_PAYLOAD
                    self.next_pkt_num += 1
                    Packet.packet_num += 1
                    # For same packet we are threading for resend
                    threading.Thread(target=self.check_resend_pkt, args=(p,)).start()
                    print("not last packet")
                else:
                    new_ip = ipaddress.ip_address(socket.gethostbyname(server_ip))
                    p = Packet(packet_type=packet.FIN,
                               seq_num=Packet.packet_num,
                               peer_ip_addr=new_ip,
                               peer_port=self.server_port,
                               payload=num_bytes(remaining_data))
                    self.socket_object.sendto(p.to_bytes(), router)
                    self.fin_num = Packet.packet_num  # To use in response
                    self.last_window_seq_num = self.fin_num
                    self.sent_pkt_window.append(p)
                    self.pkt_sent_count += 1
                    remaining_data -= remaining_data
                    threading.Thread(target=self.look_ack, args=()).start()
                    self.next_pkt_num += 1
                    print("remaining data " + str(remaining_data))
                    print("is last packet")
                    threading.Thread(target=self.check_resend_pkt, args=(p,)).start()
                    break
            while not self.check_flag_aks:
                pass
            self.check_flag_aks = False  # I changed it from True to False
            self.pkt_sent_count = 0  # I have done it

    # Here we start for the procedure so packet should be created and set and wait for acks
    def communicate_with_server(self, message):
        global router
        global server_ip
        # starting creating packets
        self.create_payload_packets(message)

    # This is for handling acks after receiving
    def receive_ack(self, data):
        pkt = Packet.from_bytes(data)
        print("Started receiving ack#", str(pkt.seq_num))
        # These are for ack window size
        start = self.sent_pkt_window[0].seq_num
        end = self.sent_pkt_window[len(self.sent_pkt_window) - 1].seq_num

        # Check if fin is contained or not
        contains_fin = False
        for pkts in self.sent_pkt_window:
            if pkts.packet_type == packet.FIN:
                contains_fin = True

        # getting only valid acks
        if pkt.packet_type == packet.ACK and start <= pkt.seq_num <= end:
            self.ack_window_lock.acquire()
            # add to ack_window
            self.all_acks_list.append(pkt.seq_num)
            self.ack_window.append(pkt.seq_num)
            # if all acks for window have been received
            if len(set(self.ack_window)) == len(self.sent_pkt_window):
                self.received_all_acks = True  # This will close the while loop for receving acks   # all acks are received
                self.check_flag_aks = True  # All acks are received for
                print("Current Window acks are receved,:", self.ack_window)

                # this means every data packet has been sent and ack have been received
                if contains_fin:
                    print("Received ack#", str(pkt.seq_num))
                    self.received_acks_for_all_data = True
                    print("Received acks for all data, continue to receive response.")
                    if self.ack_window_lock.locked():
                        self.ack_window_lock.release()  # I added this
                    threading.Thread(target=self.receive_response, args=()).start()
                    return
            else:
                # continue receiving acks
                print("Received ack#", pkt.seq_num)
            if self.ack_window_lock.locked():
                self.ack_window_lock.release()

    # this is looking for acks
    def look_ack(self):
        # We are continuously looking for acks
        while not self.received_all_acks:
            # What we are receiving
            data, sender = self.socket_object.recvfrom(1024)
            pkt = Packet.from_bytes(data)
            if pkt.packet_type == packet.ACK:
                self.receive_ack(data)
        self.received_all_acks = False

    # This is for particular packet
    def check_resend_pkt(self, pkt):
        global router
        time.sleep(1)
        # here we are also covering the case of last window
        if len(self.sent_pkt_window) == len(set(self.ack_window)):
            return
        # Will resend till we receive response
        print("All acks list:", self.all_acks_list)
        while pkt.seq_num not in set(self.ack_window):
            if pkt.seq_num not in self.all_acks_list:
                time.sleep(0.5)
                print("Re-sending packet#", pkt.seq_num)
                self.socket_object.sendto(pkt.to_bytes(), router)
            else:
                break

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

    def receive_response(self):
        print("Started receiving response.")
        while True:
            data, sender = self.socket_object.recvfrom(1024)
            pkt = Packet.from_bytes(data)
            if pkt.packet_type == packet.DATA or pkt.packet_type == packet.FIN:
                self.add_to_buffer(Packet.from_bytes(data))

    def check_in_buffer(self, pkt):
        for pkt2 in self.buffer:
            if pkt.seq_num == pkt2.seq_num:
                return True
        return False

    def check_buffer_full(self, pkt):
        print("ar:", self.fin_packet_arrived)
        if not self.fin_packet_arrived:  # I added this variable # fin packed not arrived yet
            if pkt.packet_type == packet.FIN:  # if fin packet arrived
                # length
                """Think about it"""
                self.fin_seq_num = pkt.seq_num
                self.fin_packet_arrived = True  # set arrived packet true
                # if fin arrived and buffer is full so whole data will be received
                # after it we should decode.and assemble and send response
                print("Buffer==>", self.buffer)
                if len(self.buffer) == pkt.seq_num - self.last_window_seq_num:
                    for pkts in self.buffer:
                        self.payload[pkts.seq_num] = pkts.payload.decode('utf-8')
                    return True

            elif pkt.packet_type == packet.DATA:
                if len(self.buffer) == self.window_size:
                    for pkts in self.buffer:
                        self.payload[pkts.seq_num] = pkts.payload.decode('utf-8')
                        self.last_window_seq_num += self.window_size

                    return True
        else:  # I added this code  # fin is already arrived
            if pkt.packet_type == packet.FIN:  # if fin packet arrived
                # length
                self.fin_seq_num = pkt.seq_num
                self.fin_packet_arrived = True
            if len(self.buffer) == self.fin_seq_num - self.last_window_seq_num:  # I added fin_seq_num
                for pkts in self.buffer:
                    self.payload[pkts.seq_num] = pkts.payload.decode('utf-8')

                return True
            else:
                return False

    def send_ack(self, pkt):
        global server_ip
        global router
        new_ip = ipaddress.ip_address(socket.gethostbyname(server_ip))
        tmp_pkt = Packet(packet_type=packet.ACK,
                         seq_num=pkt.seq_num,
                         peer_ip_addr=new_ip,
                         peer_port=self.server_port,
                         payload=b'')
        print("Sending Ack#", str(pkt.seq_num))
        self.socket_object.sendto(tmp_pkt.to_bytes(), router)

    def add_to_buffer(self, pkt):
        print("Adding to buffer pkt")
        if pkt.packet_type == packet.DATA or pkt.packet_type == packet.FIN:
            self.send_ack(pkt)

        if self.fin_num + self.num_windows * self.window_size < pkt.seq_num <= self.fin_num + (
                self.num_windows + 1) * self.window_size:
            if pkt.packet_type == packet.DATA and pkt.seq_num not in self.all_packet_received:

                if not self.check_in_buffer(pkt):
                    # self.fin_packet_arrived=True
                    print("Received data pkt#", pkt.seq_num)
                    self.buffer.append(pkt)
                    self.all_packet_received.append(pkt.seq_num)
                    print("Buffer after this", self.buffer)
                    x = self.check_buffer_full(pkt)
                    print(x)
                    if x:
                        print("Fin:", self.fin_packet_arrived)
                        self.num_windows += 1
                        self.buffer = []
                        if self.fin_packet_arrived:
                            print("All packet received")
                            self.convert_response()
                            return

            if pkt.packet_type == packet.FIN and pkt.seq_num not in self.all_packet_received:
                print("FIN packet received")
                if not self.check_in_buffer(pkt):
                    self.fin_packet_arrived = True
                    print("Received last data pkt#", pkt.seq_num)
                    self.buffer.append(pkt)
                    self.fin_seq_num = pkt.seq_num
                    self.all_packet_received.append(pkt.seq_num)
                    print("Buffer after last packet", self.buffer)
                    x = self.check_buffer_full(pkt)
                    print(x)
                    if x:
                        self.num_windows += 1
                        self.buffer = []
                        print("Fin:", self.fin_packet_arrived)
                        if self.fin_packet_arrived:
                            print("All packet received")
                            self.convert_response()
                            return

    def handle_packet(self, data, sender):
        pkt = Packet.from_bytes(data)
        if pkt.packet_type == packet.DATA or pkt.packet_type == packet.FIN:
            # send ack
            print("Received response-pkt#", str(pkt.seq_num))

    def convert_response(self):
        str_received_data = ''
        for some_data in sorted(self.payload.items()):
            str_received_data += some_data[1]  # convert received array to string
        print("Received data:\n")
        print(str_received_data)
        header_body = str_received_data.split("\r\n\r\n")  # split header and body
        print_data = ''
        if HTTPObject.get_is_verbose(self.http_object) == "true":  # check if verbose option is enabled
            print_data += header_body[0] + "\n"
        if len(header_body) == 2:  # check if body is contained in received data
            print_data += "\n" + header_body[1] + "\n"
        my_header = header_body[0].split(" ")
        if my_header[1].startswith("3") and 300 <= int(my_header[1]) <= 304:  # check if body contains redirection code
            # socket_object.close()
            loc_index = header_body[0].replace("location:", "Location:").find("Location:")  # find location of new url
            start = header_body[0].find(":", loc_index) + 2;  # get start index of new url, +2 for // in http://
            end = header_body[0].find("\r\n", start);  # get end index of new url
            --end  # move to one previous location
            HTTPObject.set_path(self.http_object, header_body[0][start:end].strip())  # set new path
            HTTPObject.set_url(self.http_object, HTTPConnection.find_url(header_body[1]))  # set new url
            HTTPConnection.send_request(self.http_object)  # send new request to redirected url
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
        if HTTPObject.get_write_file(self.http_object) == "true":  # check if data is to be written to a file
            HTTPConnection.write_to_file(HTTPObject.get_file2(self.http_object), print_data)  # write data to the file
        else:
            print(print_data)  # print data to console """
