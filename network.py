import socket
import crypt
import packets
from struct import Struct

# format string reference
# https://docs.python.org/3/library/struct.html#format-characters
packet_layouts = {
    "init": Struct("< x i 4x 128s 16x 16s"),
}


class BaseConn:
    HEADER_SIZE = 2
    BUFFER_SIZE = 65535

    def __init__(self):
        self.buffer = bytearray(self.BUFFER_SIZE)
        mem_view = memoryview(self.buffer)
        self.packet_size = 0
        self.header = mem_view[:self.HEADER_SIZE]
        self.contents = mem_view[self.HEADER_SIZE:]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.session_id = None
        self.rsa_key = None

        self.cipher = crypt.Blowfish()


class LoginServer(BaseConn):
    def connect(self, ip, port):
        self.sock.connect((ip, port))
        self.recv_packet()
        self.session_id, self.rsa_key, new_blowfish_key = self.read_packet("init")
        self.cipher = crypt.Blowfish(new_blowfish_key)

        packet = packets.AuthGG(self.session_id)
        self.send_packet(packet)

    def recv_packet(self):
        # get size of the packet
        self.packet_size = int.from_bytes(self.sock.recv(2), byteorder="little") - self.HEADER_SIZE
        # get contents
        self.sock.recv_into(self.buffer, self.packet_size)

    def read_packet(self, packet_name):
        self.cipher.decrypt(self.buffer, self.packet_size)

        if packet_name == "init":
            crypt.dec_xor(self.buffer, self.packet_size)

        return packet_layouts[packet_name].unpack_from(self.buffer)

    def send_packet(self, packet):
        packet.write_to(self.contents)

        # add padding
        pad_start = packet.struct.size
        size = pad_start + (8 - (pad_start % 8))
        # add space for checksum
        size += 4
        self.clean_buffer(pad_start, size)

        crypt.append_checksum(self.contents, size)
        self.clean_buffer(size, size + 12)
        size += 12
        self.cipher.encrypt(self.contents, size)
        self.header[0] = 0x2A
        self.header[1] = 0x00
        self.sock.send(self.buffer[:size + 2])

    def clean_buffer(self, start, end):
        self.contents[start:end] = b"\x00" * (end - start)


class GameServer(BaseConn):
    def connect(self, ip, port):
        self.sock.connect((ip, port))
