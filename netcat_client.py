import socket
 
class Netcat:
    def __init__(self, ip, port):
        self.buff = b''
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((ip, port))
        
    def read(self, length = 1024):
        return self.socket.recv(length)
 
    def read_until(self, data):
        while not data in self.buff:
            self.buff += self.socket.recv(1024)
 
        pos = self.buff.find(data)
        rval = self.buff[:pos + len(data)]
        self.buff = self.buff[pos + len(data):]
        return rval

    def write(self, data):
        self.socket.send(data.encode())
    
    def close(self):
        self.socket.close()

nc = Netcat(1.1.1.1, 8080)
while(True:)
    output = nc.read_until(b'>')
    print(output)
    user_input = input(">")
    nc.write(user_input)