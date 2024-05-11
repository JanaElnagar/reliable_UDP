import socket
import json
import random
import binascii
import zlib
import time


class UDPTCP_Server:
    def __init__(self, server_address, server_port):
        self.server_address = server_address
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.server_address, self.server_port))
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

    def verify_checksum(self, packet):
        received_checksum = packet.get('checksum')
        del packet['checksum']  # Remove checksum from the packet for checksum calculation
        calculated_checksum = self.calculate_checksum(json.dumps(packet))
        return received_checksum == calculated_checksum

    def simulate_false_checksum(self, packet):
        # Simulate a false checksum by modifying the received packet's checksum
        packet['checksum'] = random.randint(0, 2 ** 32 - 1)  # Generate a random checksum value
        return packet

    def handshake(self):
        # Receive SYN packet
        syn, client_address = self.socket.recvfrom(1024)
        syn_packet = json.loads(syn.decode())
        if syn_packet['type'] == 'SYN' and syn_packet['flags'][6] == '1':
            self.ack_number = syn_packet['sequence_number'] + 1
            self.display(syn_packet)

            # Send SYN-ACK packet with client's IP address and source port
            self.flags = '00010010'  # Set SYN and ACK flags
            syn_ack_packet = {'type': 'SYN-ACK', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
                              'client_ip': syn_packet['client_ip'], 'client_port': syn_packet['client_port'],
                              'flags': self.flags}

            # Calculate checksum and include it in the packet
            syn_ack_packet['checksum'] = self.calculate_checksum(json.dumps(syn_ack_packet))

            self.socket.sendto(json.dumps(syn_ack_packet).encode(), client_address)

            # Receive ACK packet
            ack, client_address = self.socket.recvfrom(1024)
            ack_packet = json.loads(ack.decode())
            self.display(ack_packet)
            if ack_packet['type'] == 'ACK' and ack_packet['sequence_number'] == self.ack_number and ack_packet['flags'][
                3] == '1':
                self.sequence_number = ack_packet['ack_number']
                self.ack_number = ack_packet['sequence_number'] + 1
                return True
            else:
                return False
        else:
            return False

    def receive_data(self):
        # Receive data packet
        data, client_address = self.socket.recvfrom(1024)
        data_packet = json.loads(data.decode())

        #data_packet = self.simulate_false_checksum(data_packet)    # for checksum testing

        # Verify checksum
        if self.verify_checksum(data_packet):
            # Check if the sequence number is as expected
            if data_packet['sequence_number'] == self.ack_number:
                self.display(data_packet)
                self.ack_number = data_packet['sequence_number'] + len(
                    data_packet['data'])  # Update acknowledgment number
                self.sequence_number = data_packet['ack_number']
                # Send ACK packet
                self.flags = '00010000'  # Set ACK flag
                ack_packet = {'type': 'ACK', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
                              'client_ip': data_packet['client_ip'], 'client_port': data_packet['client_port'],
                              'flags': self.flags}

                # Calculate checksum and include it in the ACK packet
                ack_packet['checksum'] = self.calculate_checksum(json.dumps(ack_packet))

                # Introduce a delay to test stop-and-wait
               # time.sleep(10)  # Delay for 2 seconds

                self.socket.sendto(json.dumps(ack_packet).encode(), client_address)
                return data_packet['data']
            else:
                # Handle out of order
                print("retry")
                return False
        else:
            print("Checksum verification failed. Dropping packet.")
            return False


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
