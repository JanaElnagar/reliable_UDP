import socket
import json
import random
import binascii
import zlib
import time
from collections import deque



class UDPTCP_Server:
    def __init__(self, server_address, server_port, window_size):
        self.server_address = server_address
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.server_address, self.server_port))
        self.sequence_number = random.randint(0, 1000)  # Random initial sequence number
        self.ack_number = 0
        self.flags = '00000000'  # Initialize flags
        self.window_size = window_size
        self.window = deque(maxlen=self.window_size)  # Sliding window

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

        # Verify checksum
        if self.verify_checksum(data_packet):
            # Check if the sequence number is within the window
            if self.ack_number <= data_packet['sequence_number'] < self.ack_number + self.window_size:
                self.display(data_packet)
                self.window.append(data_packet)  # Add packet to window

                # Process packets within the window
                while len(self.window) > 0 and self.window[0]['sequence_number'] == self.ack_number:
                    packet_to_process = self.window.popleft()
                    self.ack_number = packet_to_process['sequence_number'] + len(packet_to_process['data'])

                    # Send ACK packet
                    self.flags = '00010000'  # Set ACK flag
                    ack_packet = {'type': 'ACK', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
                                  'client_ip': packet_to_process['client_ip'], 'client_port': packet_to_process['client_port'],
                                  'flags': self.flags}

                    # Calculate checksum and include it in the ACK packet
                    ack_packet['checksum'] = self.calculate_checksum(json.dumps(ack_packet))
                    
                    # Introduce a delay to test stop-and-wait
                    # time.sleep(10)  # Delay for 2 seconds
                    
                    self.socket.sendto(json.dumps(ack_packet).encode(), client_address)
                    #self.display(ack_packet)

                return data_packet['data']
            else:
                # Handle out of order
                print("Packet out of order, dropping...")
                return False
        else:
            print("Checksum verification failed. Dropping packet.")
            return False


#    def handle_request(self, request):
#        # Handle HTTP request
#        print("Received HTTP request:", request)
#        # For simplicity, just print the request for now

    def handle_request(self, request):

        # Simulate handling of requests
        if request:
            status_message = 'OK'
            response_body = 'Welcome to the server!'
        else:
            status_message = 'NOT FOUND'
            response_body = 'Page not found.'

        print(status_message)
    
        # Construct HTTP response
        http_response = f"HTTP/1.0 {status_message}\r\nContent-Length: {len(response_body)}\r\n\r\n{response_body}"

        print(http_response)
    
        # Send HTTP response
#        self.send_response(http_response)

#   def send_response(self,response):
#       # Split response into packets if it's longer than 1024 bytes
#       while response:
#           packet, response = response[:1024], response[1024:]
#           # Prepare data packet
#           data_packet = {'type': 'DATA', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
#                          'client_ip': self.client_address, 'client_port': self.client_port, 'data': packet,
#                          'flags': self.flags}
#   
#           # Calculate checksum and include it in the packet
#           data_packet['checksum'] = self.calculate_checksum(json.dumps(data_packet))
#   
#           # Send data packet
#           self.socket.sendto(json.dumps(data_packet).encode(), (self.client_address, self.client_port))
#   
#           # Receive ACK packet
#           ack, _ = self.socket.recvfrom(1024)
#           ack_packet = json.loads(ack.decode())
#           self.display(ack_packet)
#           if ack_packet['type'] == 'ACK' and ack_packet['flags'][3] == '1':
#               self.sequence_number += len(packet)  # Increment sequence number by length of data
#               self.ack_number = data_packet['sequence_number'] + 1
#           else:
#               print("Failed to send packet.")  # Handle error
    
    
    
    def start(self):

        if self.handshake():
            while True:
                request = self.receive_data()
                self.handle_request(request)
        else:
            print("Failed to establish connection")


if __name__ == "__main__":
    server = UDPTCP_Server('localhost', 8000, window_size=5)  # Provide the window_size argument
    server.start()

