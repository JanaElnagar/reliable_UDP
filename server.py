import socket
import json
import random
import binascii
import zlib
import time
from collections import deque
import server_test



class UDPTCP_Server:
    def __init__(self, server_address, server_port, window_size):
        self.server_address = server_address
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.server_address, self.server_port))
        self.sequence_number = random.randint(0, 1000)  # Random initial sequence number
        self.ack_number = 0
        self.expected_ack_number = 0
        self.flags = '00000000'  # Initialize flags
        self.window_size = window_size
        self.window = deque(maxlen=self.window_size)  # Sliding window

    def display(self, packet):
        print("type: " + packet['type'])
        print("seq_num: " + str(packet['sequence_number']))
        print("ack_num: " + str(packet['ack_number']))
        print("flags: " + packet['flags'])
        # if packet['data']:
        #     print("Length: "+ str(len(packet['data'])))
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
            self.ack_number = syn_packet['sequence_number'] + len(syn_packet)
            self.display(syn_packet)

            # Send SYN-ACK packet with client's IP address and source port
            self.flags = '00010010'  # Set SYN and ACK flags
            syn_ack_packet = {'type': 'SYN-ACK', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
                              'client_ip': syn_packet['client_ip'], 'client_port': syn_packet['client_port'],
                              'flags': self.flags}

            # Calculate checksum and include it in the packet
            syn_ack_packet['checksum'] = self.calculate_checksum(json.dumps(syn_ack_packet))

            self.socket.sendto(json.dumps(syn_ack_packet).encode(), client_address)
            self.expected_ack_number = self.sequence_number + len(syn_ack_packet)

            # Receive ACK packet
            ack, client_address = self.socket.recvfrom(1024)
            ack_packet = json.loads(ack.decode())
            if ack_packet['type'] == 'ACK' and ack_packet['ack_number'] == self.expected_ack_number and ack_packet['flags'][3] == '1':
                self.display(ack_packet)
                # self.sequence_number = ack_packet['ack_number']
                # self.ack_number = ack_packet['sequence_number'] + len(ack_packet)
                #self.display_self()
                return True
            else:
                return False
        else:
            return False

    def receive_data(self):
        try:
            # Receive data packet
            data, client_address = self.socket.recvfrom(1024)
            data_packet = json.loads(data.decode())

            # Rest of the code for processing the received packet...
            if data_packet:

                # data_packet = self.simulate_false_checksum(data_packet)    # for checksum testing

                # Verify packet integrity and process the packet
                if self.verify_checksum(data_packet):
                    # Check if the sequence number is within the window
                    if self.ack_number <= data_packet['sequence_number'] < self.ack_number + self.window_size:
                        self.display(data_packet)
                        self.window.append(data_packet)  # Add packet to window

                        # Process packets within the window
                        while len(self.window) > 0 and self.window[0]['ack_number'] == self.expected_ack_number:
                            packet_to_process = self.window.popleft()
                            self.ack_number = packet_to_process['sequence_number'] + len(packet_to_process)
                            self.sequence_number = packet_to_process['ack_number']
                            #self.display_self()

                            # Send ACK packet
                            self.flags = '00010000'  # Set ACK flag
                            ack_packet = {'type': 'ACK', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
                                        'client_ip': packet_to_process['client_ip'], 'client_port': packet_to_process['client_port'],
                                        'flags': self.flags}

                            # Calculate checksum and include it in the ACK packet
                            ack_packet['checksum'] = self.calculate_checksum(json.dumps(ack_packet))
                            
                            # Introduce a delay to test stop-and-wait
                            # time.sleep(10)  # Delay for 10 seconds

                            self.socket.sendto(json.dumps(ack_packet).encode(), client_address)
                            self.expected_ack_number = self.sequence_number + len(ack_packet)
                            print("EXPECTED ACK: " + str(self.expected_ack_number))
                        return data_packet['data'], (data_packet['client_ip'], data_packet['client_port'])
                    else:
                        print("Packet out of order, dropping...")
                else:
                    print("Checksum verification failed. Dropping packet.")
        except TimeoutError:
            print("Timeout occurred while waiting for data. Connection may have been lost.")
        return None, None


    def handle_http_request(self, http_request, client_address):
        method = http_request.get('method')
        url = http_request.get('url')
        headers = http_request.get('headers', {})
        body = http_request.get('body', '')

        # Handle HTTP request based on the method
        if method == 'GET':
            # Process GET request
            response_body = 'This is a GET response'
            status_code = 200  # OK
        elif method == 'POST':
            # Process POST request
            response_body = f'This is a POST response. Received data: {body}'
            status_code = 200  # OK
        else:
            # Unsupported method
            response_body = 'Unsupported HTTP method'
            status_code = 405  # Method Not Allowed

        # Construct HTTP response
        http_response = f'HTTP/1.0 {status_code}\r\nContent-Length: {len(response_body)}\r\n\r\n{response_body}'

        # Split the HTTP response into packets
        packets = [http_response[i:i + 100] for i in range(0, len(http_response), 100)]

        # Send HTTP response packets
        for packet_data in packets:

            # Send packet
            packet = {'type': 'HTTP/1.0', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
                      'client_ip': client_address[0], 'client_port': client_address[1], 'data': packet_data,
                      'flags': '00011000'}  # Set ACK and PUSH flags

            # Calculate checksum and include it in the packet
            packet['checksum'] = self.calculate_checksum(json.dumps(packet))

            acknowledged = False

            self.socket.settimeout(2)  # Set a timeout for acknowledgment
            while not acknowledged:
                try:
                    # Send packet
                    self.socket.sendto(json.dumps(packet).encode(), client_address)

                    print(f"Sent packet with sequence number: {packet['sequence_number']}")

                    # Receive acknowledgment
                    ack, _ = self.socket.recvfrom(1024)
                    ack_packet = json.loads(ack.decode())

                    if ack_packet['type'] == 'ACK' and ack_packet['ack_number'] == self.expected_ack_number:
                        self.display(ack_packet)
                        self.sequence_number = ack_packet['ack_number']
                        self.ack_number = ack_packet['sequence_number'] + len(ack_packet)
                        print(f"Received ACK for sequence number: {ack_packet['sequence_number']}")
                        acknowledged = True
                except socket.timeout:
                    print("Timeout occurred while waiting for acknowledgment. Retransmitting...")

        # Send FIN+ACK packet
        end_msg = 'FIN'

        # Send FIN+ACK response
        fin_ack_packet = {'type': 'FIN-ACK', 'sequence_number': self.sequence_number, 'ack_number': self.ack_number,
                          'client_ip': client_address[0], 'client_port': client_address[1], 'data': end_msg,
                          'flags': '00010001'}  # Set ACK and PUSH flags

        # Calculate checksum and include it in the response packet
        fin_ack_packet['checksum'] = self.calculate_checksum(json.dumps(fin_ack_packet))

        # Wait for acknowledgment of FIN+ACK packet
        acknowledged = False
        while not acknowledged:
            try:
                self.socket.sendto(json.dumps(fin_ack_packet).encode(), client_address)
                self.expected_ack_number = self.sequence_number + len(fin_ack_packet)
                ack, _ = self.socket.recvfrom(1024)
                ack_packet = json.loads(ack.decode())
                self.display(ack_packet)

                if ack_packet['type'] == 'ACK' and ack_packet['ack_number'] == self.expected_ack_number:
                    acknowledged = True
                    self.display(ack_packet)
                    print(f"Received ACK for FIN-ACK packet with sequence number: {ack_packet['sequence_number']}")
                    self.sequence_number = ack_packet['ack_number']
                    self.ack_number = ack_packet['sequence_number'] + len(ack_packet)
                    return
            except socket.timeout:
                print("Timeout occurred while waiting for acknowledgment of FIN-ACK packet. Retransmitting...")

    def start(self):
        if self.handshake():
            retries = 0
            max_retries = 5  # Maximum number of retries for receiving data
            total_timeout = 60  # Total timeout for the entire communication process in seconds

            start_time = time.time()

            while retries < max_retries and time.time() - start_time < total_timeout:
                request, client_address = self.receive_data()
                if request:
                    try:
                        http_request = json.loads(request)
                        self.handle_http_request(http_request, client_address)
                    except json.JSONDecodeError:
                        print("Invalid JSON data received. Dropping request.")
                    retries = 0  # Reset retry count since data was received successfully
                else:
                    retries += 1  # Increment retry count if no data received
                    print("No data received from client.")

            print("Communication finished. Closing connection.")
        else:
            print("Failed to establish connection")



if __name__ == "__main__":

    # Create a server instance
    server = UDPTCP_Server('localhost', 8000, window_size=5)  # Provide the window_size argument

    #Test case 1: Successful HTTP GET Request 
    #server_test.TestUDPTCPServer.simulate_multiple_responses
    
    server.start()
