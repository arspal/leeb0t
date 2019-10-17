from struct import Struct

from dataclasses import dataclass


@dataclass
class AuthGG:
    session_id: int
    op_code: int = 0x07
    game_guard: bytes = b"\x00" * 16
    struct: Struct = Struct("< B i 16s")

    def write_to(self, buffer):
        self.struct.pack_into(buffer, 0, self.op_code, self.session_id, self.game_guard)
