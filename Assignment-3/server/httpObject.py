class HTTPObject:
    _req_type = ''
    _uri = ''
    _headers = {}
    _data = ''

    def get_req_type(self):
        return self._req_type

    def get_uri(self):
        return self._uri

    def get_headers(self):
        return self._headers

    def get_data(self):
        return self._data

    def __init__(self, req_type, uri, headers, data):
        self._req_type = req_type
        self._uri = uri
        self._headers = headers
        self._data = data

    def convert_to_string(self):
        tmp = ''
        count = 0
        if len(self._headers.keys()) > 0:
            for key, val in self._headers.items():
                ++count
                if count != len(self._headers):
                    tmp += key + ": " + val + ", "
                else:
                    tmp += key + ": " + val
        return "Request type: " + self._req_type + "\n" + \
               "URI: " + self._uri + "\n" + \
               "Headers : { " + tmp + " }\n" + \
               "Body: " + self._data + "\n"
