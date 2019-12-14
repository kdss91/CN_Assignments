class ServerParam:
    _port = 8007
    _is_verbose = "false"
    _path = ""

    def __init__(self, input_command):
        input_array = input_command.split()
        for index in range(len(input_array)):
            if index == 0:
                if input_array[index].lower() != "httpfs":
                    print("Check your command.")
                    raise Exception("Invalid Command")
            elif input_array[index] == "-p":
                self._port = int(input_array[index + 1])
            elif input_array[index] == "-v":
                self._is_verbose = "true"
            elif input_array[index] == "-d":
                self._path = input_array[index + 1].replace("'", "")
                #if not self._path.endswith("/"):
                    #self._path += "/"

    def convert_to_string(self):
        print("Port: ", self._port,"\nPrint Debugging Message: ", self._is_verbose,
              "\nPath to directory: ", self._path)
