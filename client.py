import socket
import json
import time


class UDPTCP_Client:
    def __init__(self, server_address, server_port, client_address, client_port):
        self.server_address = server_address
        self.server_port = server_port
        self.client_address = client_address  # Client's IP address
        self.client_port = client_port  # Client's source port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.client_address, self.client_port))  # Bind to client's source IP address and port
        self.sequence_number = 0
        self.ack_number = 0

    def handshake(self):
        # Send SYN packet with client's IP address and source port
        syn_packet = {'type': 'SYN', 'sequence_number': self.sequence_number, 'client_ip': self.client_address, 'client_port': self.client_port}
        self.socket.sendto(json.dumps(syn_packet).encode(), (self.server_address, self.server_port))

        # Receive SYN-ACK packet
        syn_ack, _ = self.socket.recvfrom(1024)
        syn_ack_packet = json.loads(syn_ack.decode())
        if syn_ack_packet['type'] == 'SYN-ACK':
            self.sequence_number = syn_ack_packet['ack_number']
            self.ack_number = syn_ack_packet['sequence_number'] + 1
            print("client received SYN-ACK")

            # Send ACK packet
            ack_packet = {'type': 'ACK', 'sequence_number': self.sequence_number,'ack_number': self.ack_number, 'client_ip': self.client_address, 'client_port': self.client_port}
            self.socket.sendto(json.dumps(ack_packet).encode(), (self.server_address, self.server_port))
            print("Client sent ACK")
            return True
        else:
            return False

    def send_data(self, data):
        # Send data packet
        data_packet = {'type': 'DATA', 'sequence_number': self.sequence_number, 'data': data}
        self.socket.sendto(json.dumps(data_packet).encode(), (self.server_address, self.server_port))

        # Receive ACK packet
        ack, _ = self.socket.recvfrom(1024)
        ack_packet = json.loads(ack.decode())
        self.sequence_number = ack_packet['ack_number']
        self.ack_number += len(ack_packet)
        if ack_packet['type'] == 'ACK' :
            self.sequence_number += 1
            return True
        else:
            return False

    def stop(self):
        self.socket.close()

    def start(self):
        if self.handshake():
            # Send HTTP request
            http_request = {'method': 'GET', 'url': '/example'}
            self.send_data(json.dumps(http_request))
        else:
            print("Failed to establish connection")


if __name__ == "__main__":
    client = UDPTCP_Client('localhost', 8000, 'localhost', 50506)  # Pass client's IP address and source port as arguments
    client.start()
