import socket
import struct
import time
import random
from hashlib import crc32

FLAG_SYN = 1
FLAG_SYNACK = 2
FLAG_ACK = 4
FLAG_FIN = 8
FLAG_DATA = 16

class ReliableUDPSocket:
    def __init__(self, address):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.address = address
        self.sequence_number = 0
        self.expected_sequence_number = 0
        self.window_size = 1
        self.next_expected_ack = 0
        self.outstanding_packets = {}
        self.timeout = 1

    def send_packet(self, data, flags):
        checksum = crc32(struct.pack("!I", self.sequence_number) + data)
        packet = struct.pack("!IHHI", self.sequence_number, flags, checksum, len(data)) + data
        self.socket.sendto(packet, self.address)
        if flags & FLAG_DATA:
            self.outstanding_packets[self.sequence_number] = time.time()
        self.sequence_number += 1

    def receive_packet(self):
        data, address = self.socket.recvfrom(1024)
        sequence_number, flags, checksum, data_length = struct.unpack("!IHHI", data[:12])
        calculated_checksum = crc32(struct.pack("!I", sequence_number) + data[12:])
        if checksum != calculated_checksum:
            return  # Discard corrupted packet
        if flags & FLAG_SYN:
            self.send_packet(b"", FLAG_SYNACK)
        elif flags & FLAG_ACK:
            self.expected_sequence_number = sequence_number + 1
            del self.outstanding_packets[sequence_number - 1]
        elif flags & FLAG_FIN:
            self.send_packet(b"", FLAG_ACK)
            # Handle connection termination here
        elif sequence_number == self.expected_sequence_number:
            self.expected_sequence_number += 1
            # Process data according to HTTP protocol
            # Send ACK for received packet
        # Handle out-of-order packets silently (not shown)

    def handle_timeout(self):
        now = time.time()
        for sequence_number, send_time in self.outstanding_packets.items():
            if now - send_time > self.timeout:
                self.send_packet(self.outstanding_packets[sequence_number], FLAG_DATA)
