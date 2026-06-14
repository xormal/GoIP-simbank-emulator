#!/usr/bin/env python3
"""DBLTEK SIMBank loginlimit challenge-response helper.

The telnet service on some SIMBank firmware builds starts a restricted
loginlimit flow on TCP/13000. This tool calculates the response for lab devices
you own and administer. It intentionally contains no network client; paste the
result into the telnet session yourself.
"""
import argparse
import math
import struct


S0 = [
    7, 1, 3, 2, 4, 5, 6, 0, 9, 8, 15, 14, 17, 13, 11, 10,
    18, 12, 16, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 91, 90, 92, 93, 94, 95,
    99, 97, 98, 96, 103, 107, 102, 100, 104, 105, 106, 101, 108, 109,
    110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
    124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137,
    138, 139, 142, 141, 140, 143, 148, 145, 146, 147, 144, 149, 150, 151,
    152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
    166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
    194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
    208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221,
    222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235,
    236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249,
    250, 251, 252, 253, 254, 255,
]


def u32(value):
    """Return value truncated to an unsigned 32-bit integer."""
    return value & 0xFFFFFFFF


def s32(value):
    """Return value interpreted with C signed 32-bit integer semantics."""
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def rol(value, count):
    """Rotate a 32-bit integer left."""
    return u32((value << count) | (value >> (32 - count)))


def md5_loginlimit(data):
    """Return the firmware's modified MD5 digest used by loginlimit.

    The structure follows MD5, but several sine-table constants are adjusted.
    Keeping the routine local makes the exact firmware-compatible variant
    auditable and avoids monkey-patching hashlib.
    """
    msg = bytearray(data)
    bitlen = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bitlen)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    constants = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
    constants[1] = u32(constants[1] - 1)
    constants[15] = u32(constants[15] + 1)
    constants[26] = u32(constants[26] + 0x8000)
    constants[36] = u32(constants[36] + 1)
    constants[52] = u32(constants[52] + 0x100000)

    shifts = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
    order = (
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        + [1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12]
        + [5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2]
        + [0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9]
    )

    for block_pos in range(0, len(msg), 64):
        words = list(struct.unpack("<16I", msg[block_pos : block_pos + 64]))
        a, b, c, d = a0, b0, c0, d0
        for i in range(64):
            if i < 16:
                f = (b & c) | (~b & d)
            elif i < 32:
                f = (d & b) | (~d & c)
            elif i < 48:
                f = b ^ c ^ d
            else:
                f = c ^ (b | ~d)
            f = u32(f + a + constants[i] + words[order[i]])
            a, d, c, b = d, c, b, u32(b + rol(f, shifts[i]))
        a0, b0, c0, d0 = u32(a0 + a), u32(b0 + b), u32(c0 + c), u32(d0 + d)

    return struct.pack("<4I", a0, b0, c0, d0)


def rc4_init(key):
    """Initialize the firmware RC4 state using the non-standard S0 table."""
    if not key:
        raise ValueError("empty RC4 key")
    state = S0[:]
    j = 0
    key_index = 0
    for i in range(256):
        j = (j + state[i] + key[key_index]) & 0xFF
        state[i], state[j] = state[j], state[i]
        key_index += 1
        if key_index >= len(key):
            key_index = 0
    return [0, 0, state]


def rc4_xor(ctx, data):
    """Encrypt/decrypt bytes with the mutable RC4 context."""
    i, j, state = ctx
    out = bytearray(data)
    for pos, value in enumerate(out):
        i = (i + 1) & 0xFF
        x = state[i]
        j = (j + x) & 0xFF
        y = state[j]
        state[i], state[j] = y, x
        out[pos] = value ^ state[(x + y) & 0xFF]
    ctx[0], ctx[1] = i, j
    return bytes(out)


def c_hex(value):
    """Format a value as C-style unsigned lowercase hex without 0x."""
    return format(u32(value), "x")


def c_dec(value):
    """Format a value as C-style signed decimal."""
    return str(s32(value))


def parse_challenge(value):
    """Parse loginlimit challenges in either 'H123' or plain integer form."""
    value = value.strip()
    if value.startswith(("H", "h")):
        value = value[1:]
    return int(value, 0)


def dbladm_response(challenge):
    """Calculate the dbladm password for a loginlimit numeric challenge."""
    challenge = u32(challenge)
    decimal = str(s32(challenge)).encode()
    d = list(decimal + b"\x00" * 5)

    key1 = (
        c_dec(u32(challenge + (s32(challenge) >> 3)))
        + c_dec(s32(challenge) >> 4)
        + c_hex(d[2])
        + c_hex(d[0] - d[2] - 1)
        + c_dec(d[4] - d[1] - 1)
        + c_hex(-(d[3] + d[1] + 1))
    ).encode()
    block = bytearray(64)
    block[: len(key1)] = key1
    digest = bytearray(md5_loginlimit(block))

    key2 = (
        c_dec(digest[5] - digest[2] - 1)
        + c_hex(digest[13] + digest[1])
        + c_hex(digest[7] - digest[14] - 1)
        + c_dec(-(digest[6] + digest[10] + 1))
        + "F2GM1V"
    ).encode()
    encrypted = rc4_xor(rc4_init(key2), digest)

    values = [
        (encrypted[3] - encrypted[5] - 1) & 0xFF,
        (encrypted[3] - encrypted[8] - 1) & 0xFF,
        (encrypted[0] + encrypted[1]) & 0xFF,
        (encrypted[6] - encrypted[15] - 1) & 0xFF,
        (2 * encrypted[9]) & 0xFF,
        (encrypted[12] - encrypted[7] - 1) & 0xFF,
        (encrypted[0] - encrypted[2] - 1) & 0xFF,
        (encrypted[6] - encrypted[13] - 1) & 0xFF,
    ]
    return "".join(f"{value:02x}" for value in values)


def secid_response(challenge, secid_hex):
    """Calculate the secid password using a 16-byte secid seed in hex form."""
    challenge = u32(challenge)
    seed = f"{s32(challenge)}{0x34:x}{0x1a}".encode()
    block = bytearray(64)
    encrypted = rc4_xor(rc4_init(secid_hex.encode()), seed)
    block[: len(encrypted)] = encrypted
    return md5_loginlimit(block).hex()


def main():
    """CLI entry point for loginlimit challenge-response calculation."""
    parser = argparse.ArgumentParser(description="SIMBank loginlimit telnet challenge calculator")
    sub = parser.add_subparsers(dest="mode", required=True)

    dbladm = sub.add_parser("dbladm", help="calculate password for Login: dbladm, challenge H<number>")
    dbladm.add_argument("challenge")

    secid = sub.add_parser("secid", help="calculate password for Login: secid, requires /dev/mtd/7 secid hex")
    secid.add_argument("challenge")
    secid.add_argument("secid_hex")

    args = parser.parse_args()
    challenge = parse_challenge(args.challenge)
    if args.mode == "dbladm":
        print(dbladm_response(challenge))
    else:
        secid_hex = args.secid_hex.strip().lower()
        if len(secid_hex) != 32 or any(ch not in "0123456789abcdef" for ch in secid_hex):
            raise SystemExit("secid_hex must be 32 lowercase/uppercase hex characters")
        print(secid_response(challenge, secid_hex))


if __name__ == "__main__":
    main()
