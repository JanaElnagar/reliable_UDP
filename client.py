import socket
import json
import random
import binascii
import zlib


class UDPTCP_Client:
    def __init__(self, server_address, server_port, client_address, client_port):
        self.server_address = server_address
        self.server_port = server_port
        self.client_address = client_address  # Client's IP address
        self.client_port = client_port  # Client's source port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.client_address, self.client_port))  # Bind to client's source IP address and port
        self.sequence_number = random.randint(0, 1000)  # Random initial sequence number
        self.ack_number = 0
        self.flags = '00000000'  # Initialize flags

    def display(self, packet):
        print("type: " + packet['type'])
        print("seq_num: " + str(packet['sequence_number']))
        print("ack_num: " + str(packet['ack_number']))
        print("flags: " + packet['flags'])
        print("------------------------")

    def display_self(self):
        print("current state")
        print("seq_num: " + str(self.sequence_number))
        print("ack_num: " + str(self.ack_number))
        print("flags: " + self.flags)
        print("------------------------")

    def calculate_checksum(self, data):
        checksum = zlib.crc32(data.encode())
        return checksum

    def handshake(self):
        # Send SYN packet with client's IP address and source port
        self.flags = '00000010'  # Set SYN flag
        syn_packet = {'type': 'SYN', 'sequence_number': self.sequence_number, 'ack_number': None,
                      'client_ip': self.client_address, 'client_port': self.client_port, 'flags': self.flags}
        self.socket.sendto(json.dumps(syn_packet).encode(), (self.server_address, self.server_port))
        self.display(syn_packet)

        # Receive SYN-ACK packet
        syn_ack, _ = self.socket.recvfrom(1024)
        syn_ack_packet = json.loads(syn_ack.decode())
        if syn_ack_packet['type'] == 'SYN-ACK' and syn_ack_packet['flags'][6] == '1' and syn_ack_packet['flags'][
            3] == '1':
            self.display(syn_ack_packet)
            self.sequence_number = syn_ack_packet['ack_number']
            self.ack_number = syn_ack_packet['sequence_number'] + 1

            # Send ACK packet
            self.flags = '00010000'  # Set ACK flag
            ack_packet = {'type': 'ACK', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
                          'client_ip': self.client_address, 'client_port': self.client_port, 'flags': self.flags}

            # Calculate checksum and include it in the packet
            ack_packet['checksum'] = self.calculate_checksum(json.dumps(ack_packet))

            self.socket.sendto(json.dumps(ack_packet).encode(), (self.server_address, self.server_port))
            print("Client sent ACK")
            # self.ack_number += 1
            return True
        else:
            return False

    def send_data(self, data):
        # Send data packet
        self.flags = '00000000'  # Reset flags
        self.sequence_number += 1
        data_packet = {'type': 'DATA', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
                       'client_ip': self.client_address, 'client_port': self.client_port, 'data': data,
                       'flags': self.flags}

        # Calculate checksum and include it in the packet
        data_packet['checksum'] = self.calculate_checksum(json.dumps(data_packet))

        self.socket.sendto(json.dumps(data_packet).encode(), (self.server_address, self.server_port))

        # Receive ACK packet
        ack, _ = self.socket.recvfrom(1024)
        ack_packet = json.loads(ack.decode())
        self.display(ack_packet)
        if ack_packet['type'] == 'ACK' and ack_packet['flags'][3] == '1':
            self.sequence_number += len(data)  # Increment sequence number by length of data
            self.ack_number = data_packet['sequence_number'] + 1
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
    client = UDPTCP_Client('localhost', 8000, 'localhost',
                           50506)  # Pass client's IP address and source port as arguments
    client.start()
