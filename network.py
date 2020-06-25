from socket import socket, AF_INET, SOCK_STREAM
import logging
import threading
import encrypt
import packets

logging.basicConfig(format="%(asctime)s: %(message)s", level=logging.INFO,
                    datefmt="%H:%M:%S")

packet_container = packets.PacketContainer()
USERNAME_MAX_LEN = 14
PASSWORD_MAX_LEN = 16


class Connection:
    def __init__(self, ip, login_port, game_port):
        self.config = {
            "ip": ip,
            "login_port": login_port,
            "game_port": game_port
        }

        self.login_conn = LoginConn()
        self.game_conn = GameConn()

    def connect(self, login: str, password: str):
        self.login_conn.connect(self.config["ip"], self.config["login_port"])
        self.login_conn.login(login, password)

        self.game_conn.connect(self.config["ip"], self.config["game_port"])


class LoginConn:
    def __init__(self):
        self.session_id = 0
        self.scrambled_rsa_mod = bytearray()
        self.account_id = 0
        self.auth_key = 0
        self.cipher = encrypt.Blowfish()
        self.sock = socket(AF_INET, SOCK_STREAM)

    def connect(self, ip, port):
        self.sock.connect((ip, port))
        self.recv_packet()
        self.session_id, self.scrambled_rsa_mod, new_blowfish_key = self.read_packet(packets.init)
        self.cipher = encrypt.Blowfish(new_blowfish_key)

        packets.auth_gg["fields"]["session_id"] = self.session_id

        self.send_packet(packets.auth_gg)
        self.recv_packet()

    def login(self, username: str, password: str):
        username_len = len(username)
        password_len = len(password)

        if username_len > USERNAME_MAX_LEN:
            raise ValueError(f"Username should be {USERNAME_MAX_LEN} characters or less")
        if password_len > PASSWORD_MAX_LEN:
            raise ValueError(f"Password should be {PASSWORD_MAX_LEN} characters or less")

        # cleanup space for rsa encoded data
        self.clean_buffer(0, 128)

        # specify some unknown bytes that client expects
        packet_container.contents[91] = 0x24

        # login/pw should start at exactly these bytes
        packet_container.contents[94:94 + username_len] = bytes(username, "utf-8")
        packet_container.contents[108:108 + password_len] = bytes(password, "utf-8")

        packets.req_auth["fields"]["user_data"] = encrypt.enc_rsa_no_pad(packet_container.contents[0:128],
                                                                         self.scrambled_rsa_mod)
        packets.req_auth["fields"]["session_id"] = self.session_id

        self.send_packet(packets.req_auth)

        # todo @cleanup: Maybe receive and read packet in one function call
        self.recv_packet()
        self.account_id, self.auth_key, _forbidden_servers = self.read_packet(packets.login_ok)

        packets.req_server_list["fields"]["account_id"] = self.account_id
        packets.req_server_list["fields"]["auth_key"] = self.auth_key

        self.send_packet(packets.req_server_list)
        self.recv_packet()

        packets.req_server_login["fields"]["account_id"] = self.account_id
        packets.req_server_login["fields"]["auth_key"] = self.auth_key

        # todo: server selection is hardcoded for now
        packets.req_server_login["fields"]["game_server"] = 0x02
        self.send_packet(packets.req_server_login)
        self.recv_packet()

        return self.read_packet(packets.play_ok)

    def recv_packet(self):
        # get size of the packet
        self.sock.recv_into(packet_container.header, 0)

        # get contents
        self.sock.recv_into(packet_container.contents, packet_container.calc_size())

    def read_packet(self, packet):
        self.cipher.decrypt(packet_container.contents, packet_container.size)

        if packet["name"] == "init":
            encrypt.dec_xor(packet_container.contents, packet_container.size)

        return packet_container.read_packet(packet)

    def send_packet(self, packet):
        packet_container.write_packet(packet)

        # add padding
        pad_start = packet_container.size
        size = pad_start + (8 - (pad_start % 8))
        # add space for checksum
        size += 4
        self.clean_buffer(pad_start, size)

        encrypt.append_checksum(packet_container.contents, size)
        self.clean_buffer(size, size + 12)
        size += 12
        self.cipher.encrypt(packet_container.contents, size)
        # todo: calculate packet size dynamically
        packet_container.header[0] = size + 2
        packet_container.header[1] = 0x00
        self.sock.send(packet_container.buf[:size + 2])

    @staticmethod
    def clean_buffer(start, end):
        packet_container.contents[start:end] = b"\x00" * (end - start)


class GameConn:
    def __init__(self):
        self.game_crypt = None
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.processed_packets = 0

    def connect(self, ip, port):
        self.sock.connect((ip, port))

    def start_loop(self, gs_session_id, gs_account_id, gs_id, ls_account_id, ls_auth_key):
        self.send_packet(packets.send_protocol_ver)
        self.recv_packet()

        (cipher_key,) = self.read_packet(packets.version_check)

        self.game_crypt = encrypt.GameCrypt(cipher_key)

        packets.gs_req_login["fields"]["gs_account_id"] = gs_account_id
        packets.gs_req_login["fields"]["gs_session_id"] = gs_session_id
        packets.gs_req_login["fields"]["ls_account_id"] = ls_account_id
        packets.gs_req_login["fields"]["ls_auth_key"] = ls_auth_key

        self.send_enc_packet(packets.gs_req_login)
        self.recv_packet()

        self.send_enc_packet(packets.gs_req_game_start)
        self.recv_packet()
        self.recv_packet()

        self.send_enc_packet(packets.gs_manor_list)
        self.recv_packet()

        self.send_enc_packet(packets.gs_fort_info)
        self.send_enc_packet(packets.gs_keymap)
        self.send_enc_packet(packets.gs_req_enter_world)

        loop_thread = threading.Thread(target=self.collect_packets, daemon=True)
        loop_thread.start()

    def collect_packets(self):
        while True:
            self.recv_packet()
            # self.read_enc_packet_debug()
            self.processed_packets += 1

    def recv_packet(self):
        # get size of the packet
        self.sock.recv_into(packet_container.header, 0)
        # get contents
        self.sock.recv_into(packet_container.contents, packet_container.calc_size())

    def read_packet(self, packet):
        return packet_container.read_packet(packet)

    def read_enc_packet_debug(self):
        self.game_crypt.decrypt(packet_container.contents, packet_container.size)
        logging.info(f"op: {packet_container.contents[0:1].hex().upper()}, size: {packet_container.size + 2}")

    def read_enc_packet(self, packet):
        self.game_crypt.decrypt(packet_container.contents, packet_container.size)
        return packet_container.read_packet(packet)

    def send_packet(self, packet):
        packet_container.write_packet(packet)

        size = packet_container.size

        packet_container.header[0] = size + 2
        packet_container.header[1] = 0x00

        self.sock.send(packet_container.buf[:size + 2])

    def send_enc_packet(self, packet):
        packet_container.write_packet(packet)
        self.game_crypt.encrypt(packet_container.contents, packet_container.size)

        size = packet_container.size

        packet_container.header[0] = size + 2
        packet_container.header[1] = 0x00

        self.sock.send(packet_container.buf[:size + 2])
