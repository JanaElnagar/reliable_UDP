import socket
import json
import random
import binascii
import zlib
import time
from collections import deque

class UDPTCP_Client:
    def __init__(self, server_address, server_port, client_address, client_port, window_size):
        self.server_address = server_address
        self.server_port = server_port
        self.client_address = client_address  # Client's IP address
        self.client_port = client_port  # Client's source port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.client_address, self.client_port))  # Bind to client's source IP address and port
        self.sequence_number = random.randint(0, 1000)  # Random initial sequence number
        self.ack_number = 0
        self.flags = '00000000'  # Initialize flags
        self.timeout = 1  # Timeout in seconds
        self.max_retries = 4  # Maximum number of retransmissions
        self.window_size = window_size
        self.window = deque(maxlen=self.window_size)  # Sliding window
        self.unacknowledged_packets = deque(maxlen=self.window_size)  # Packets waiting for acknowledgment
        self.last_sent_packet = None  # Track the last sent packet for retransmission

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

        # Receive SYN-ACK packet
        syn_ack, _ = self.socket.recvfrom(1024)
        syn_ack_packet = json.loads(syn_ack.decode())
        if syn_ack_packet['type'] == 'SYN-ACK' and syn_ack_packet['flags'][6] == '1' and syn_ack_packet['flags'][3] == '1':
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
            return True
        else:
            return False

    def send_data(self, data):
        # Send data packet
        self.flags = '00011000'  # Set ACK and PUSH flags
        self.sequence_number += 1
        data_packet = {'type': 'Request', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
                       'client_ip': self.client_address, 'client_port': self.client_port, 'data': data,
                       'flags': self.flags}

        # Calculate checksum and include it in the packet
        data_packet['checksum'] = self.calculate_checksum(json.dumps(data_packet))

        self.window.append(data_packet)  # Add packet to window
        self.unacknowledged_packets.append(data_packet)  # Add packet to unacknowledged list

        retries = 0
        while retries < self.max_retries:
            if len(self.unacknowledged_packets) > 0:
                # Send the next packet in the window
                packet_to_send = self.unacknowledged_packets[0]
                self.socket.sendto(json.dumps(packet_to_send).encode(), (self.server_address, self.server_port))
                print("Sent packet with sequence number:", packet_to_send['sequence_number'])

                start_time = time.time()
                # Receive ACK packet with timeout
                self.socket.settimeout(self.timeout)
                try:
                    ack, _ = self.socket.recvfrom(1024)
                    ack_packet = json.loads(ack.decode())
                    self.display(ack_packet)
                    if ack_packet['type'] == 'ACK' and ack_packet['flags'][3] == '1':
                        print("Received ACK for sequence number:", ack_packet['sequence_number'])
                        self.sequence_number += len(data)  # Increment sequence number by length of data
                        self.ack_number = ack_packet['sequence_number'] + 1
                        self.window.popleft()  # Slide window
                        self.unacknowledged_packets.popleft()  # Remove acknowledged packet
                        # self.display(ack_packet)
                        return True
                except socket.timeout:
                    print("Timeout occurred, retransmitting data packet...")
                    retries += 1
                finally:
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    if elapsed_time < self.timeout:
                        time.sleep(self.timeout - elapsed_time)

        print("Maximum retries reached, failed to send data.")
        return False

    def receive_http_response(self):
        received_packets = set()  # Keep track of received packets
        fin_received = False  # Flag to track if FIN packet is received

        while not fin_received:
            # Receive packet with timeout
            self.socket.settimeout(self.timeout)
            try:
                packet, _ = self.socket.recvfrom(1024)
                received_packet = json.loads(packet.decode())
                self.display(received_packet)

                # Check packet type
                if received_packet['type'] == 'HTTP/1.0':
                    print("Received HTTP response from server:", received_packet['data'])
                    received_packets.add('HTTP/1.0')
                elif received_packet['type'] == 'FIN-ACK' and received_packet['flags'][4] == '1':
                    print("Received FIN-ACK from server.")
                    fin_received = True
                    received_packets.add('FIN-ACK')

                # Send ACK for received packet
                ack_packet = {'type': 'ACK', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
                              'client_ip': self.client_address, 'client_port': self.client_port, 'flags': '00010000'}
                self.socket.sendto(json.dumps(ack_packet).encode(), (self.server_address, self.server_port))
                print("Sent ACK for packet with sequence number:", received_packet['sequence_number'])
                break
            except socket.timeout:
                print("Timeout occurred while waiting for packet from server.")

        # Once FIN-ACK is received, wait for a short period to ensure all packets are acknowledged
        time.sleep(1)
        print("All packets acknowledged. Connection closed.")

    def stop(self):
        self.socket.close()

    def start(self):
        if self.handshake():
            # Define HTTP headers
            headers = {
                'Host': 'example.com',
                'User-Agent': 'MyClient/1.0',
                'Accept': 'text/html',
                'Content-Type': 'application/json',
                # Add more headers as needed
            }

            # Define the HTTP request
            http_request = {
                'method': 'GET',
                'url': '/example',
                'headers': headers,  # Include the headers in the request
            }

            # Send HTTP GET request with headers
            if self.send_data(json.dumps(http_request)):  # if request sent successfully (and first ack received)
                self.receive_http_response()              # receive http response data

            # Define a sample POST request body
            post_body = '{"key": "value"}'
            # Send HTTP POST request with headers and body
            post_request = {
                'method': 'POST',
                'url': '/example',
                'headers': headers,  # Include the headers in the request
                'body': post_body   # Include the body in the request
            }
            if self.send_data(json.dumps(post_request)):  # if request sent successfully (and first ack received)
                self.receive_http_response()               # receive http response data
        else:
            print("Failed to establish connection")

if __name__ == "__main__":
    client = UDPTCP_Client('localhost', 8000, 'localhost', 50506, window_size=5)   # Pass client's IP address and source port as arguments
    client.start()
