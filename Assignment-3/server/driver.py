from server.serverParam import ServerParam
from server.httpConnection import HTTPConnection


def main():
    input_command = input("Please enter command to start the server:\n")
    try:
        server_obj = ServerParam(input_command)
        my_http_conn = HTTPConnection(server_obj, 41830)
        my_http_conn.start_server()
    except Exception:
        pass


main()
