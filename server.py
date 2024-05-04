from ReliableUDPSocket import ReliableUDPSocket
from ReliableUDPSocket import FLAG_SYN, FLAG_SYNACK, FLAG_ACK, FLAG_FIN, FLAG_DATA
import struct

class Server:
    def __init__(self):
        self.socket = ReliableUDPSocket(("0.0.0.0", 5000))  # Listen on all interfaces

    def handle_client(self, client_address):
        while True:
            self.socket.handle_timeout()
            data, _ = self.socket.recvfrom(1024)
            if not data:
                break
            # Process HTTP request (parse data, generate response)
            response = "HTTP/1.0 200 OK\r\nContent-Length: 10\r\n\r\nHello World"
            self.socket.send_packet(response.encode(), FLAG_DATA)
            self.socket.handle_timeout()
            # Wait for FIN and send ACK
            data, _ = self.socket.recvfrom(1024)
            if data and struct.unpack("!I", data[:4])[0] & FLAG_FIN:
                self.socket.send_packet(b"", FLAG_ACK)
                break

if __name__ == "__main__":
    server = Server()
    while True:
        server.handle_client(None)
