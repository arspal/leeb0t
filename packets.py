from struct import Struct

# struct format string reference
# https://docs.python.org/3/library/struct.html#format-characters
init = {
    "name": "init",
    "struct": Struct("< x i 4x 128s 16x 16s")
}

req_auth = {
    "name": "req_auth",
    "fields": {
        "op_code": 0x00,
        "user_data": None,
        "session_id": None,
        "game_guard": b"\x00" * 16,
        "game_id": 8
    },
    "struct": Struct("< B 128s i 16s I")
}

auth_gg = {
    "name": "auth_gg",
    "fields": {
        "op_code": 0x07,
        "session_id": None,
        "game_guard": b"\x00" * 16,
    },
    "struct": Struct("< B i 16s")
}

HEADER_SIZE = 2
BUFFER_SIZE = 65535


class PacketContainer:
    def __init__(self, size=BUFFER_SIZE):
        self.buf = bytearray(size)
        self.size = 0

        # setup memory views
        mem_view = memoryview(self.buf)
        self.header = mem_view[:HEADER_SIZE]
        self.contents = mem_view[HEADER_SIZE:]

    def calc_size(self):
        self.size = int.from_bytes(self.header, byteorder="little") - HEADER_SIZE
        return self.size

    def write_packet(self, packet):
        packet["struct"].pack_into(self.contents, 0, *packet["fields"].values())
        self.size = packet["struct"].size

    def read_packet(self, packet):
        return packet["struct"].unpack_from(self.contents)
