from ReliableUDPSocket import ReliableUDPSocket
from ReliableUDPSocket import FLAG_SYN, FLAG_SYNACK, FLAG_ACK, FLAG_FIN, FLAG_DATA

class Client:
    def __init__(self, server_address):
        self.socket = ReliableUDPSocket(server_address)

    def send_http_request(self, method, url, headers={}, data=b""):
        request = f"{method} {url} HTTP/1.0\r\n"
        for header, value in headers.items():
            request += f"{header}: {value}\r\n"
        request += "\r\n"
        request += data.decode()
        packets = [request[i:i + 1024] for i in range(0, len(request), 1024)]
        for i, packet in enumerate(packets):
            self.socket.send_packet(packet.encode(), FLAG_DATA)
            self.socket.handle_timeout()

    def process_http_response(self, data):
        response_lines = data.decode().split("\r\n")
        status_code = response_lines[0].split()[1]
        headers = {}
        for line in response_lines[1:]:
            if line:
                key, value = line.split(": ")
                headers[key] = value
        # Process response data and headers

if __name__ == "__main__":
    server_address = ("127.0.0.1", 5000)  # Replace with server address and port
    client = Client(server_address)
    client.send_http_request("GET", "/index.html")
    data, _ = client.socket.recvfrom(1024)
    client.process_http_response(data)
