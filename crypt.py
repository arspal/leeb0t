import blowfish

DEF_RSA_EXPONENT = 65537
STATIC_BLOWFISH_KEY = b"\x6b\x60\xcb\x5b\x82\xce\x90\xb1\xcc\x2b\x6c\x55\x6c\x6c\x6c\x6c"


class Blowfish:
    """
    Blowfish dec/enc utilities. Temporarily uses external lib.
    """

    def __init__(self, key: bytes = STATIC_BLOWFISH_KEY):
        self.cipher = blowfish.Cipher(key, byte_order="little")

    def encrypt(self, raw, size, offset=0):
        for i in range(offset, size, 8):
            raw[i:i + 8] = self.cipher.encrypt_block(raw[i:i + 8])

    def decrypt(self, raw, size, offset=0):
        for i in range(offset, size, 8):
            raw[i:i + 8] = self.cipher.decrypt_block(raw[i:i + 8])


def append_checksum(raw: bytearray, size: int, offset: int = 0):
    chksum = 0
    count = size - 4
    i = offset

    while i < count:
        ecx = raw[i] & 0xff
        ecx |= (raw[i + 1] << 8) & 0xff00
        ecx |= (raw[i + 2] << 0x10) & 0xff0000
        ecx |= (raw[i + 3] << 0x18) & 0xff000000

        chksum ^= ecx
        i += 4

    ecx = raw[i] & 0xff
    ecx |= (raw[i + 1] << 8) & 0xff00
    ecx |= (raw[i + 2] << 0x10) & 0xff0000
    ecx |= (raw[i + 3] << 0x18) & 0xff000000

    raw[i] = chksum & 0xff
    raw[i + 1] = (chksum >> 0x08) & 0xff
    raw[i + 2] = (chksum >> 0x10) & 0xff
    raw[i + 3] = (chksum >> 0x18) & 0xff


def dec_xor(raw: bytearray, size: int, offset: int = 0):
    key = int.from_bytes(raw[size - 8:size - 4], byteorder="little")
    stop = 4 + offset
    pos = size - 12
    ecx = key

    while stop <= pos:
        edx = (raw[pos] & 0xFF)
        edx |= (raw[pos + 1] & 0xFF) << 8
        edx |= (raw[pos + 2] & 0xFF) << 16
        edx |= (raw[pos + 3] & 0xFF) << 24

        edx ^= ecx
        ecx -= edx

        raw[pos] = (edx & 0xFF)
        raw[pos + 1] = (edx >> 8 & 0xFF)
        raw[pos + 2] = (edx >> 16 & 0xFF)
        raw[pos + 3] = (edx >> 24 & 0xFF)

        pos -= 4


def enc_rsa_no_pad(msg: bytearray, scrambled_mod: bytes, exp: int = DEF_RSA_EXPONENT) -> bytes:
    mod = unscramble_and_parse_rsa_mod(scrambled_mod)
    # should be 128 bytes 99.99% of the time
    key_len = mod.bit_length() // 8
    msg_as_int = int.from_bytes(msg, byteorder="big")

    return pow(msg_as_int, exp, mod).to_bytes(key_len, byteorder="big")


def unscramble_and_parse_rsa_mod(rsa_mod: bytes) -> int:
    rsa_mod = bytearray(rsa_mod)

    # step 1: xor last 64 bytes with first 64 bytes
    for i in range(0, 64):
        rsa_mod[64 + i] ^= rsa_mod[i]

    # step 2 xor bytes 13-16 with bytes 52-55
    for i in range(0, 4):
        rsa_mod[13 + i] ^= rsa_mod[52 + i]

    # step 3 xor first 64 bytes with last 64 bytes
    for i in range(0, 64):
        rsa_mod[i] ^= rsa_mod[0x40 + i]

    # step 4 xor 0-4 with 77-80
    for i in range(0, 4):
        rsa_mod[i], rsa_mod[77 + i] = rsa_mod[77 + i], rsa_mod[i]

    return int.from_bytes(rsa_mod, byteorder="big")
