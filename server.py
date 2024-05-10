import socket
import json

class UDPTCP_Server:
    def __init__(self, server_address, server_port):
        self.server_address = server_address
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.server_address, self.server_port))
        self.sequence_number = 0
        self.ack_number = 0

    def handshake(self):
        # Receive SYN packet
        syn, client_address = self.socket.recvfrom(1024)
        syn_packet = json.loads(syn.decode())
        if syn_packet['type'] == 'SYN':
            self.ack_number = syn_packet['sequence_number'] + 1
            print("server received SYN")

            # Send SYN-ACK packet with client's IP address and source port
            syn_ack_packet = {'type': 'SYN-ACK', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number, 'client_ip': syn_packet['client_ip'], 'client_port': syn_packet['client_port']}
            self.socket.sendto(json.dumps(syn_ack_packet).encode(), client_address)

            # Receive ACK packet
            #print("about to receive ACK")
            ack, _ = self.socket.recvfrom(1024)
            #print("received ACK packet (undecoded)")
            ack_packet = json.loads(ack.decode())
            print(ack_packet['sequence_number'])
            print(self.ack_number)
            if ack_packet['type'] == 'ACK' and ack_packet['sequence_number'] == self.ack_number:
                print("Server received ACK")
               # self.sequence_number += 1  # update the sequence number
                return True
            else:
                return False
        else:
            return False

    def receive_data(self):
        # Receive data packet
        data, _ = self.socket.recvfrom(1024)
        data_packet = json.loads(data.decode())
        self.ack_number += len(data_packet)
        # Send ACK packet
        ack_packet = {'type': 'ACK', 'sequence_number': self.sequence_number, 'ack_number':self.ack_number}
        self.socket.sendto(json.dumps(ack_packet).encode(), (data_packet['client_ip'], data_packet['client_port']))

        return data_packet['data']

    def handle_request(self, request):
        # Handle HTTP request
        print("Received HTTP request:", request)
        # For simplicity, just print the request for now

    def start(self):
        if self.handshake():
            while True:
                request = self.receive_data()
                self.handle_request(request)
        else:
            print("Failed to establish connection")

if __name__ == "__main__":
    server = UDPTCP_Server('localhost', 8000)
    server.start()
