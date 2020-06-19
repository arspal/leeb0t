from struct import Struct

# struct format string reference
# https://docs.python.org/3/library/struct.html#format-characters
init = {
    "name": "init",
    "fields": ("session_id", "scrambled_rsa_mod", "blowfish_key"),
    "struct": Struct("< x i 4x 128s 16x 16s")
}

login_ok = {
    "name": "login_ok",
    "fields": ("account_id", "auth_key", "forbidden_servers"),
    "struct": Struct("< x i i 24x 16s")
}

play_ok = {
    "name": "play_ok",
    "fields": ("gs_session_id", "gs_account_id", "gs_id"),
    "struct": Struct("< x i i B")
}

version_check = {
    "name": "version_check",
    # "fields": ("cipher_key",),
    "struct": Struct("< x x q")
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

send_protocol_ver = {
    "name": "send_protocol_ver",
    "fields": {
        "op_code": 0x0E,
        "protocol_ver": 0x111,
        # "rsa_mod": None
    },
    "struct": Struct("< B i")
}

gs_req_login = {
    "name": "gs_req_login",
    "fields": {
        "op_code": 0x2B,
        "account_name": b"\x74\x00\x65\x00\x73\x00\x74\x00\x00\x00",
        "gs_account_id": None,
        "gs_session_id": None,
        "ls_account_id": None,
        "ls_auth_key": None,
        "localization": 0x01
    },
    "struct": Struct("< B 10s i i i i i")
}

gs_req_game_start = {
    "name": "gs_req_game_start",
    "fields": {
        "op_code": 0x12,
        "char_index": 0,
    },
    "struct": Struct("< B i 2x 4x 4x 4x")
}

gs_req_enter_world = {
    "name": "gs_req_enter_world",
    "fields": {
        "op_code": 0x11,
        "game_guard1": b"\xC9\xBC\xF2\xA7\x66\x5A\x0B\x98\x36\xA5\xBD\x89\xED\x7F\xE4\xD7\x6B\x49\xE2\x9F\xEF\x76\xEB\xCE\xA3\xFA\xF4\xBF\x0C\x64\xA3\xB4\xA4\xCE\xDC\xC6\x08\x3E\x6E\xEA\x45\xCA\xD3\xFE\x88\x13\x87\xB8\x06\x2C\x96\xF0\x9B\x1E\x8E\xBC\xC6\x9B\x98\xC8\x63\x16\xCF\xD0",
        "game_guard2": 0x29
    },
    "struct": Struct("< B 4x 4x 4x 4x 64s i 4x 4x 4x 4x 4x")
}

gs_manor_list = {
    "name": "gs_manor_list",
    "fields": {
        "op_code": b"\xD0\x01\x00",
    },
    "struct": Struct("< 3s")
}

gs_keymap = {
    "name": "gs_keymap",
    "fields": {
        "op_code": b"\xD0\x3D\x00",
    },
    "struct": Struct("< 3s")
}

gs_fort_info = {
    "name": "gs_fort_info",
    "fields": {
        "op_code": b"\xD0\x21\x00",
    },
    "struct": Struct("< 3s")
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

req_server_list = {
    "name": "req_server_list",
    "fields": {
        "op_code": 0x05,
        "account_id": None,
        "auth_key": None,
        "list_type": 5,
    },
    "struct": Struct("< B i i B")
}

req_server_login = {
    "name": "req_server_login",
    "fields": {
        "op_code": 0x02,
        "account_id": None,
        "auth_key": None,
        "game_server": None
    },
    "struct": Struct("< B i i B")
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
