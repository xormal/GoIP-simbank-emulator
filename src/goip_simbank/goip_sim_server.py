#!/usr/bin/env python3
"""Transparent GoIP remote-SIM bridge backed by a local PC/SC smart-card reader.

This module implements the DBLTEK-style TCP frame format, APDU parsing, a
single-slot transparent card bridge, and small compatibility adapters needed by
older GoIP firmware. The full SIMBank-authenticated multi-reader server reuses
these classes from goip_sim_server_full.py.
"""
import argparse
import asyncio
import hashlib
import logging
import os
import signal
import struct
import time
from dataclasses import dataclass

from smartcard.Exceptions import CardConnectionException, NoCardException
from smartcard.scard import SCARD_RESET_CARD
from smartcard.System import readers


MAGIC = b"\x78\x56\x21\x43"
TOKEN_COMMANDS = {0x0001, 0x0003, 0x0014, 0x001E, 0x001F, 0x0032, 0x00C8}
INS_NAMES = {
    0x10: "TERMINAL PROFILE",
    0x12: "FETCH",
    0x14: "TERMINAL RESPONSE",
    0x20: "VERIFY",
    0x88: "AUTHENTICATE/RUN GSM ALGORITHM",
    0xA4: "SELECT",
    0xA2: "SEEK/SEARCH RECORD",
    0xB0: "READ BINARY",
    0xB2: "READ RECORD",
    0xC0: "GET RESPONSE",
    0xD6: "UPDATE BINARY",
    0xF2: "STATUS",
}
FILE_NAMES = {
    "3f00": "MF",
    "2fe2": "EF ICCID",
    "6f05": "EF LI",
    "6f07": "EF IMSI",
    "6f08": "EF Keys",
    "6f09": "EF KeysPS",
    "6f20": "EF Kc",
    "6f31": "EF HPPLMN",
    "6f38": "EF SST/UST",
    "6f40": "EF MSISDN",
    "6f42": "EF SMSP",
    "6f44": "EF LP",
    "6f45": "EF CBMI",
    "6f46": "EF SPN",
    "6f48": "EF CNL",
    "6f56": "EF EST",
    "6f60": "EF PLMNwAcT",
    "6f73": "EF PSLOCI",
    "6fb7": "EF ECC",
    "6fad": "EF AD",
}
PROFILE_NAME = "LABNET"
HOME_PLMN = bytes.fromhex("00f110")  # MCC/MNC 001/01, BCD encoded.
PLMN_ACT_GSM_UMTS_LTE = bytes.fromhex("c080")
USIM_AID_PREFIX = bytes.fromhex("a0000000871002")
DEFAULT_USIM_AID = bytes.fromhex("a0000000871002ffffffff8907090000")
MCC_MNC_LENGTH_BY_MCC = {
    "001": 2,
}
OPERATOR_NAME_BY_PLMN = {
    "00101": "LABNET",
}
ECC_FILE_SUFFIX = "6fb7"
GOIP_ECC_RECORD_LEN = 4
GOIP_ECC_SHAPE_ADAPTER = False
# Delay (seconds) between the 0x00C9 reset-ack and the unsolicited ATR.
# Some GoIP remote-SIM modems reject an instant ATR after reset. A hardware
# SIMBank naturally introduces reset latency, so the emulator defaults to a
# conservative 6-second delay; tune via GOIP_ATR_DELAY / --atr-delay.
GOIP_ATR_DELAY = float(os.getenv("GOIP_ATR_DELAY", "6"))
GOIP_FILE_SIZE_LIMITS = {
    "6f38": 12,  # EF UST compatibility profile uses the classic 12-byte prefix.
    "6f56": 1,   # EF EST: only the first byte is used by the GoIP initialization path.
}
GOIP_TRANSPARENT_SIZE_HINTS = {
    "6f05": 10,
    "6f46": 17,
    "6fad": 4,
    "6f38": 12,
    "6f56": 1,
    "6f60": 60,
    "6f61": 60,
    "6f7b": 12,
    "6f7e": 11,
    "6f31": 1,
    "6fd9": 6,
    "6f48": 10,
    "6f73": 14,
}


def transparent_fcp(fid: str, size: int, sfi: int) -> bytes:
    """Build a standard FCP template for a transparent EF."""
    return bytes.fromhex(
        "621f820241218302"
        + fid
        + "a506c00100ca01808a01058b036f0602"
        + size.to_bytes(2, "big").hex()
        + "8801"
        + sfi.to_bytes(1, "big").hex()
    )


def compact_transparent_fcp(fid: str, size: int, sfi: int, security_ref: int = 0x07) -> bytes:
    """Build a compact FCP template accepted by SIMBank-compatible GoIP firmware."""
    body = bytes.fromhex("820241218302" + fid)
    body += bytes.fromhex("8a01058b036f06") + bytes([security_ref])
    body += bytes.fromhex("8002") + size.to_bytes(2, "big")
    body += bytes.fromhex("8801") + bytes([sfi])
    return b"\x62" + bytes([len(body)]) + body


def plmnwact_entries(entries: list[bytes], total_len: int) -> bytes:
    """Encode PLMN-with-access-technology entries and pad the EF body."""
    data = b"".join(plmn + PLMN_ACT_GSM_UMTS_LTE for plmn in entries)
    return data.ljust(total_len, b"\xff")[:total_len]


def repeat_ff(length: int) -> bytes:
    """Return an erased transparent EF body of the requested length."""
    return b"\xff" * length


def is_all_ff(data: bytes) -> bool:
    """Return true when an EF body is present and completely erased."""
    return bool(data) and all(byte == 0xFF for byte in data)


def is_empty_plmn_act_list(data: bytes) -> bool:
    """Detect an empty PLMNwAcT-style list encoded as erased PLMN plus zero AcT."""
    if not data or len(data) % 5:
        return False
    return all(data[pos : pos + 5] == b"\xff\xff\xff\x00\x00" for pos in range(0, len(data), 5))


def encode_plmn_bcd(mcc: str, mnc: str) -> bytes | None:
    """Encode MCC/MNC into the 3-byte GSM BCD PLMN representation."""
    if len(mcc) != 3 or len(mnc) not in {2, 3} or not (mcc + mnc).isdigit():
        return None
    mnc3 = "f" if len(mnc) == 2 else mnc[2]
    return bytes(
        [
            (int(mcc[1]) << 4) | int(mcc[0]),
            (int(mnc3, 16) << 4) | int(mcc[2]),
            (int(mnc[1]) << 4) | int(mnc[0]),
        ]
    )


def is_ecc_file(selected_file: str | None) -> bool:
    """Return true when the selected file path points to EF ECC."""
    return bool(selected_file and selected_file.lower().endswith(ECC_FILE_SUFFIX))


def file_suffix(selected_file: str | None) -> str | None:
    """Return the final 2-byte FID from a selected file path or AID path."""
    if not selected_file:
        return None
    return selected_file.lower()[-4:]


PROFILE_TRANSPARENT_DATA = {
    "7fff6f05": b"enru".ljust(10, b"\xff"),
    "7fff6f46": (b"\x00" + PROFILE_NAME.encode("ascii")).ljust(17, b"\xff"),
    "7fff6fad": bytes.fromhex("00000002"),
    "7fff6f38": bytes.fromhex("9e7b1f9ce33e040040001000"),
    "7fff6f56": bytes.fromhex("00"),
    "7fff6f60": plmnwact_entries([HOME_PLMN], 60),
    "7fff6f61": plmnwact_entries([HOME_PLMN], 60),
    "7fff6f7b": repeat_ff(12),
    "7fff6f7e": bytes.fromhex("ffffffff00f110fffeff01"),
    "7fff6f31": bytes.fromhex("03"),
    "7fff6fd9": repeat_ff(6),
    "7fff6f48": repeat_ff(10),
    "7fff6f73": bytes.fromhex("ffffffffffffff00f110fffeff01"),
}
PROFILE_FCP = {
    "7fff6f05": transparent_fcp("6f05", 10, 0x10),
    "7fff6f46": transparent_fcp("6f46", 17, 0x00),
    "7fff6f38": bytes.fromhex("621f8202412183026f38a506c00100ca01808a01058b036f06028002000c880120"),
    "7fff6f56": bytes.fromhex("621f8202412183026f56a506c00100ca01808a01058b036f060580020001880128"),
    "7fff6fad": bytes.fromhex("62278202412183026fada50ec001009b063f007f206fadca01808a01058b036f060780020004880118"),
    "7fff6f60": transparent_fcp("6f60", 60, 0x0A),
    "7fff6f61": transparent_fcp("6f61", 60, 0x0B),
    "7fff6f7b": transparent_fcp("6f7b", 12, 0x58),
    "7fff6f7e": transparent_fcp("6f7e", 11, 0x58),
    "7fff6f31": transparent_fcp("6f31", 1, 0x00),
    "7fff6fd9": transparent_fcp("6fd9", 6, 0xE8),
    "7fff6f48": transparent_fcp("6f48", 10, 0x70),
    "7fff6f73": transparent_fcp("6f73", 14, 0x00),
}
COMPACT_PROFILE_FCP = {
    "7fff6f05": compact_transparent_fcp("6f05", 10, 0x10),
    "7fff6f46": compact_transparent_fcp("6f46", 17, 0x00),
    "7fff6fad": compact_transparent_fcp("6fad", 4, 0x18),
    "7fff6f38": compact_transparent_fcp("6f38", 12, 0x20),
    "7fff6f56": compact_transparent_fcp("6f56", 1, 0x28),
    "7fff6f60": compact_transparent_fcp("6f60", 60, 0x50),
    "7fff6f61": compact_transparent_fcp("6f61", 60, 0x88),
    "7fff6f7b": compact_transparent_fcp("6f7b", 12, 0x68),
    "7fff6f7e": compact_transparent_fcp("6f7e", 11, 0x58),
    "7fff6f31": compact_transparent_fcp("6f31", 1, 0x90),
    "7fff6fd9": compact_transparent_fcp("6fd9", 6, 0xE8),
    "7fff6f48": compact_transparent_fcp("6f48", 10, 0x70),
    "7fff6f73": compact_transparent_fcp("6f73", 14, 0x60),
}
SW_NAMES = {
    0x9000: "normal processing",
    0x6A82: "file/application not found",
    0x6A86: "incorrect P1/P2",
    0x6982: "security status not satisfied",
    0x6985: "conditions of use not satisfied",
    0x6700: "wrong length",
    0x6D00: "instruction not supported",
    0x6E00: "class not supported",
}


def hx(data: bytes) -> str:
    """Return a compact lowercase hex string for logs."""
    return data.hex()


def printable(data: bytes) -> str:
    """Render bytes as ASCII with dots for non-printable values."""
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data)


def frame(line_id: int, command: int, msg_type: int, payload: bytes = b"") -> bytes:
    """Build a DBLTEK GoIP/SIMBank TCP frame."""
    return MAGIC + struct.pack("<IHH", line_id, command, msg_type) + payload


def line_slot(line_id: int) -> int:
    """Extract the GoIP slot number from a line id."""
    return line_id % 100


def parse_short_apdu_len(buf: bytes) -> int | None:
    """Infer the length of a short ISO 7816 APDU if enough bytes are available."""
    if len(buf) < 4:
        return None
    if len(buf) == 4:
        return 4

    cla, ins, p1, p2, p3 = buf[:5]

    if ins in {0x10, 0x14, 0x88, 0xA2, 0xA4, 0xD6, 0xDC, 0xDA} and p3 <= 0xEF:
        need = 5 + p3
        if len(buf) < need:
            return None
        if len(buf) == need + 1:
            return need + 1
        return need

    return 5


def infer_frame_len(buf: bytes) -> int | None:
    """Infer one complete TCP frame length from a buffered byte stream."""
    if len(buf) < 12:
        return None
    if not buf.startswith(MAGIC):
        return None

    command = int.from_bytes(buf[8:10], "little")
    if command in TOKEN_COMMANDS:
        return 32 if len(buf) >= 32 else None
    if command in {0x0028, 0x005B}:
        return 12
    if command in {0x0047, 0x0048, 0x004A, 0x0069}:
        next_magic = buf.find(MAGIC, 12)
        return next_magic if next_magic > 0 else len(buf)
    if command == 0x0000:
        if len(buf) < 32:
            return None
        next_magic = buf.find(MAGIC, 12)
        if next_magic > 0:
            return next_magic
        apdu_len = parse_short_apdu_len(buf[32:])
        if apdu_len is None:
            return None
        need = 32 + apdu_len
        return need if len(buf) >= need else None

    next_magic = buf.find(MAGIC, 12)
    return next_magic if next_magic > 0 else len(buf)


@dataclass
class ParsedFrame:
    """Decoded DBLTEK TCP frame header and payload."""

    line_id: int
    command: int
    msg_type: int
    payload: bytes


@dataclass
class ParsedApdu:
    """Parsed short APDU command with ISO 7816 case metadata."""

    raw: bytes
    cla: int
    ins: int
    p1: int
    p2: int
    p3: int | None
    data: bytes
    le: int | None
    case: str
    valid: bool
    error: str = ""


def parse_frame(raw: bytes) -> ParsedFrame:
    """Decode a raw DBLTEK TCP frame."""
    if len(raw) < 12 or not raw.startswith(MAGIC):
        raise ValueError("bad frame")
    line_id, command, msg_type = struct.unpack("<IHH", raw[4:12])
    return ParsedFrame(line_id, command, msg_type, raw[12:])


def file_name(fid_or_path: str | None) -> str:
    """Return a human-friendly name for a known SIM file id or path."""
    if not fid_or_path:
        return ""
    if fid_or_path in FILE_NAMES:
        return FILE_NAMES[fid_or_path]
    if len(fid_or_path) >= 4 and fid_or_path[-4:] in FILE_NAMES:
        return FILE_NAMES[fid_or_path[-4:]]
    if fid_or_path.startswith("a0000000871002"):
        return "ETSI/3GPP UICC application"
    return fid_or_path


def parse_apdu(raw: bytes) -> ParsedApdu:
    """Parse a short APDU command into header, data, and Le fields."""
    if len(raw) < 4:
        return ParsedApdu(raw, 0, 0, 0, 0, None, b"", None, "short", False, "length < 4")

    cla, ins, p1, p2 = raw[:4]
    if len(raw) == 4:
        return ParsedApdu(raw, cla, ins, p1, p2, None, b"", None, "case1", True)

    p3 = raw[4]
    tail = raw[5:]
    if not tail:
        return ParsedApdu(raw, cla, ins, p1, p2, p3, b"", p3, "case2", True)
    if len(tail) == p3:
        return ParsedApdu(raw, cla, ins, p1, p2, p3, tail, None, "case3", True)
    if len(tail) == p3 + 1:
        return ParsedApdu(raw, cla, ins, p1, p2, p3, tail[:p3], tail[-1], "case4", True)
    return ParsedApdu(
        raw,
        cla,
        ins,
        p1,
        p2,
        p3,
        tail,
        None,
        "bad-length",
        False,
        f"tail length {len(tail)} does not match Lc={p3} or Lc+Le={p3 + 1}",
    )


def apdu_warnings(apdu: ParsedApdu) -> list[str]:
    """Return non-fatal APDU shape warnings for logs."""
    warnings = []
    if not apdu.valid:
        return warnings
    if apdu.ins not in INS_NAMES:
        warnings.append(f"unknown INS 0x{apdu.ins:02x}")
    if apdu.ins in {0xB0, 0xB2, 0xC0, 0xF2} and apdu.case != "case2":
        warnings.append(f"{INS_NAMES.get(apdu.ins, 'command')} is expected as 5-byte Le command, got {apdu.case}")
    if apdu.ins == 0xA4:
        if apdu.case not in {"case3", "case4"}:
            warnings.append("SELECT is expected to carry file id/path/AID data")
        elif apdu.p1 == 0x04 and len(apdu.data) not in {5, 6, 7, 8, 12, 16}:
            warnings.append(f"SELECT by AID has unusual AID length {len(apdu.data)}")
        elif apdu.p1 != 0x04 and len(apdu.data) not in {2, 4, 6, 8}:
            warnings.append(f"SELECT by file/path has unusual data length {len(apdu.data)}")
    if apdu.ins in {0xD6, 0x88, 0xA2, 0x10, 0x14} and apdu.case not in {"case3", "case4"}:
        warnings.append(f"{INS_NAMES.get(apdu.ins, 'command')} is expected to carry Lc/data, got {apdu.case}")
    return warnings


def bcd_digits(raw: bytes, low_first: bool = True) -> str:
    """Decode BCD nibbles into a digit string."""
    digits = []
    for byte in raw:
        nibbles = (byte & 0x0F, byte >> 4) if low_first else (byte >> 4, byte & 0x0F)
        for nibble in nibbles:
            if nibble == 0xF:
                continue
            if 0 <= nibble <= 9:
                digits.append(str(nibble))
            else:
                digits.append(f"?{nibble:x}")
    return "".join(digits)


def decode_imsi(raw: bytes) -> str:
    """Decode an EF IMSI body into the printable IMSI string."""
    if not raw:
        return ""
    length = raw[0]
    body = raw[1 : 1 + length]
    if not body:
        return ""
    return str((body[0] >> 4) & 0x0F) + bcd_digits(body[1:], low_first=True)


def sw_text(sw1: int, sw2: int) -> str:
    """Describe a SIM status word pair for logs."""
    sw = (sw1 << 8) | sw2
    if sw in SW_NAMES:
        return SW_NAMES[sw]
    if sw1 == 0x61:
        return f"{sw2} response bytes available"
    if sw1 == 0x62:
        return "warning, state unchanged"
    if sw1 == 0x63:
        if (sw2 & 0xF0) == 0xC0:
            return f"warning, retries left={sw2 & 0x0F}"
        return "warning"
    if sw1 == 0x6C:
        return f"wrong Le, retry with Le=0x{sw2:02x}"
    if sw1 == 0x91:
        return f"SIM Toolkit/proactive data, {sw2} bytes"
    return "unknown status"


def parse_tlv(raw: bytes, max_depth: int = 4, depth: int = 0):
    """Parse a BER-TLV buffer into nested (tag, value, children) tuples."""
    result = []
    pos = 0
    while pos < len(raw):
        tag = raw[pos]
        pos += 1
        if (tag & 0x1F) == 0x1F and pos < len(raw):
            tag = (tag << 8) | raw[pos]
            pos += 1
        if pos >= len(raw):
            result.append((tag, raw[pos:], []))
            break
        length = raw[pos]
        pos += 1
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or pos + n > len(raw):
                break
            length = int.from_bytes(raw[pos : pos + n], "big")
            pos += n
        value = raw[pos : pos + length]
        pos += length
        children = parse_tlv(value, max_depth, depth + 1) if depth < max_depth and tag in {0x62, 0x6F, 0xA5, 0xC6} else []
        result.append((tag, value, children))
    return result


def tlv_find(tlvs, tag: int):
    """Yield matching TLV values recursively."""
    for item_tag, value, children in tlvs:
        if item_tag == tag:
            yield value
        yield from tlv_find(children, tag)


def summarize_fcp(data: bytes) -> str:
    """Summarize a File Control Parameters template for readable APDU logs."""
    if not data or data[0] not in {0x62, 0x6F, 0xF2, 0xC0}:
        return ""
    if data[0] in {0xF2, 0xC0}:
        data = data[1:]
    if not data or data[0] not in {0x62, 0x6F}:
        return ""
    tlvs = parse_tlv(data)
    parts = []
    file_id_values = list(tlv_find(tlvs, 0x83))
    if file_id_values:
        fid = file_id_values[0].hex()
        parts.append(f"FID={fid} {file_name(fid)}".strip())
    size_values = list(tlv_find(tlvs, 0x80))
    if size_values and size_values[0]:
        parts.append(f"size={int.from_bytes(size_values[0], 'big')}")
    descriptor_values = list(tlv_find(tlvs, 0x82))
    if descriptor_values and descriptor_values[0]:
        desc = descriptor_values[0][0]
        kind = {0x38: "DF/ADF", 0x39: "DF/ADF", 0x01: "transparent EF", 0x02: "linear fixed EF", 0x06: "cyclic EF"}.get(desc & 0x3F, f"descriptor=0x{desc:02x}")
        parts.append(kind)
        if len(descriptor_values[0]) >= 5:
            parts.append(f"record_len={descriptor_values[0][3]} records={descriptor_values[0][4]}")
    aid_values = list(tlv_find(tlvs, 0x84))
    if aid_values:
        parts.append(f"AID={aid_values[0].hex()}")
    return "; ".join(parts)


def decode_apdu_command(apdu: ParsedApdu, selected_file: str | None) -> str:
    """Return a concise human-readable APDU command description."""
    if not apdu.valid:
        return apdu.error
    name = INS_NAMES.get(apdu.ins, f"INS 0x{apdu.ins:02x}")
    selected = file_name(selected_file)
    if apdu.ins == 0xA4:
        if apdu.p1 == 0x04:
            return f"SELECT by AID aid={apdu.data.hex()} case={apdu.case}"
        if apdu.data:
            fid = apdu.data.hex()
            return f"SELECT file={fid} {file_name(fid)} case={apdu.case}".strip()
        return f"SELECT p1=0x{apdu.p1:02x} p2=0x{apdu.p2:02x} case={apdu.case}"
    if apdu.ins == 0xC0:
        return f"GET RESPONSE le={apdu.p3}"
    if apdu.ins == 0xB0:
        offset = ((apdu.p1 & 0x7F) << 8) | apdu.p2
        return f"READ BINARY offset={offset} le={apdu.p3} selected={selected}"
    if apdu.ins == 0xB2:
        return f"READ RECORD rec={apdu.p1} mode=0x{apdu.p2:02x} le={apdu.p3} selected={selected}"
    if apdu.ins == 0xA2:
        return f"SEEK/SEARCH RECORD mode=0x{apdu.p2:02x} lc={apdu.p3} pattern={apdu.data.hex()} selected={selected}"
    if apdu.ins == 0xD6:
        offset = ((apdu.p1 & 0x7F) << 8) | apdu.p2
        return f"UPDATE BINARY offset={offset} lc={apdu.p3} data={apdu.data.hex()} selected={selected}"
    if apdu.ins == 0x20:
        target = {0x01: "CHV1/PIN1", 0x81: "ADM/CHV? 0x81"}.get(apdu.p2, f"ref=0x{apdu.p2:02x}")
        return f"VERIFY {target} p3={apdu.p3}"
    if apdu.ins == 0x88:
        return f"AUTHENTICATE/RUN GSM ALGORITHM lc={apdu.p3} p2=0x{apdu.p2:02x} data={apdu.data.hex()}"
    if apdu.ins == 0xF2:
        return f"STATUS p1=0x{apdu.p1:02x} p2=0x{apdu.p2:02x} le={apdu.p3}"
    if apdu.ins == 0x10:
        return f"TERMINAL PROFILE lc={apdu.p3} profile={apdu.data.hex()}"
    if apdu.ins == 0x12:
        return f"FETCH le={apdu.p3}"
    if apdu.ins == 0x14:
        return f"TERMINAL RESPONSE lc={apdu.p3} data={apdu.data.hex()}"
    return f"{name} cla=0x{apdu.cla:02x} p1=0x{apdu.p1:02x} p2=0x{apdu.p2:02x} p3={apdu.p3} case={apdu.case}"


def decode_apdu_response(response: bytes, command: ParsedApdu, selected_file: str | None) -> str:
    """Return a concise human-readable APDU response description."""
    if len(response) < 2:
        return "INVALID_RESPONSE length < 2"
    data = response[:-2]
    if data and data[0] == command.ins:
        data = data[1:]
    sw1, sw2 = response[-2:]
    details = []
    fcp = summarize_fcp(data)
    if fcp:
        details.append(f"fcp={fcp}")
    selected = file_name(selected_file)
    if command.ins == 0xB0 and selected == "EF ICCID" and data:
        details.append(f"ICCID={bcd_digits(data, low_first=True)}")
    elif command.ins == 0xB0 and selected == "EF IMSI" and data:
        details.append(f"IMSI={decode_imsi(data)} raw={data.hex()}")
    elif data:
        text = printable(data)
        details.append(f"data={data.hex()} ascii={text}")
    suffix = " ".join(details)
    return f"SW={sw1:02x}{sw2:02x} {sw_text(sw1, sw2)}" + (f" {suffix}" if suffix else "")


class SimCard:
    """Thread-safe async wrapper around one PC/SC reader connection."""

    def __init__(self, reader_index: int = 0):
        self.reader_index = reader_index
        self.reader_name = None
        self.conn = None
        self.atr = b""
        self.lock = asyncio.Lock()

    def connect_sync(self) -> bytes:
        """Connect to the configured reader and return the ATR."""
        available = readers()
        if not available:
            raise RuntimeError("no PC/SC readers")
        reader = available[self.reader_index]
        self.reader_name = str(reader)
        conn = reader.createConnection()
        conn.connect(disposition=SCARD_RESET_CARD)
        self.conn = conn
        self.atr = bytes(conn.getATR())
        return self.atr

    async def connect(self) -> bytes:
        """Async wrapper for connect_sync."""
        async with self.lock:
            return await asyncio.to_thread(self.connect_sync)

    async def current_atr(self) -> bytes:
        """Return the cached ATR, connecting to the card if needed."""
        async with self.lock:
            if self.atr:
                return self.atr
            return await asyncio.to_thread(self.connect_sync)

    def reset_sync(self) -> bytes:
        """Reset the card by reconnecting the PC/SC session."""
        if self.conn is not None:
            try:
                self.conn.disconnect()
            except Exception as exc:
                logging.warning("PC/SC disconnect before reset failed: %s", exc)
            finally:
                self.conn = None
        return self.connect_sync()

    async def reset(self) -> bytes:
        """Async wrapper for reset_sync."""
        async with self.lock:
            return await asyncio.to_thread(self.reset_sync)

    def transmit_sync(self, apdu: bytes) -> bytes:
        """Transmit one APDU and return data plus SW1/SW2."""
        if self.conn is None:
            self.connect_sync()
        try:
            data, sw1, sw2 = self.conn.transmit(list(apdu))
        except (CardConnectionException, NoCardException):
            self.conn = None
            self.connect_sync()
            data, sw1, sw2 = self.conn.transmit(list(apdu))
        return bytes(data) + bytes([sw1, sw2])

    async def transmit(self, apdu: bytes) -> bytes:
        """Async wrapper for transmit_sync."""
        async with self.lock:
            return await asyncio.to_thread(self.transmit_sync, apdu)

    async def run_hidden(self, apdus: list[bytes]) -> list[bytes]:
        """Transmit helper APDUs without exposing them to the GoIP tunnel."""
        async with self.lock:
            return await asyncio.to_thread(self.run_hidden_sync, apdus)

    def run_hidden_sync(self, apdus: list[bytes]) -> list[bytes]:
        """Synchronous helper for run_hidden."""
        responses = []
        for apdu in apdus:
            responses.append(self.transmit_sync(apdu))
        return responses


class GoipSimServer:
    """Single-slot transparent GoIP remote-SIM server."""

    def __init__(
        self,
        host: str,
        port: int,
        real_slot: int,
        empty_slots: set[int],
        auth_mode: str,
        echo_control: bool,
        compat_fcp: bool,
        profile_overlay: bool,
        profile_fcp_overlay: bool,
        adf_context_adapter: bool,
        derived_profile_adapter: bool,
        compact_profile_fcp: bool,
        fcp_size_cap: bool = False,
        atr_delay: float = 6.0,
    ):
        self.host = host
        self.port = port
        self.real_slot = real_slot
        self.empty_slots = empty_slots
        self.auth_mode = auth_mode
        self.echo_control = echo_control
        self.compat_fcp = compat_fcp
        self.profile_overlay = profile_overlay
        self.profile_fcp_overlay = profile_fcp_overlay
        self.adf_context_adapter = adf_context_adapter
        self.derived_profile_adapter = derived_profile_adapter
        self.compact_profile_fcp = compact_profile_fcp
        self.fcp_size_cap = fcp_size_cap
        self.atr_delay = atr_delay
        self.card = SimCard()
        self.server_seq = {}
        self.card_context = "mf"
        self.usim_aid: bytes | None = None
        self.imsi: str | None = None
        self.mnc_len: int | None = None
        self.ecc_real_record_len = GOIP_ECC_RECORD_LEN
        self.ecc_record_count = 5

    def next_seq(self, line_id: int) -> bytes:
        """Return the next little-endian server sequence for a line id."""
        value = self.server_seq.get(line_id)
        if value is None:
            value = int(time.time() * 1000) & 0xFFFFFFFF
        else:
            value = (value + 1) & 0xFFFFFFFF
        self.server_seq[line_id] = value
        return struct.pack("<I", value)

    def make_auth_blob(self, line_id: int, seq: bytes, client_blob: bytes, apdu_response: bytes) -> bytes:
        """Build a transparent-mode response blob according to the selected mode."""
        if self.auth_mode == "echo":
            return client_blob[:16].ljust(16, b"\x00")
        if self.auth_mode == "md5":
            return hashlib.md5(struct.pack("<I", line_id) + seq + apdu_response).digest()
        return b"\x00" * 16

    def make_c9_payload(self, line_id: int, slot: int, request_payload: bytes) -> bytes:
        """Build the reset-ack payload for command 0x00C9."""
        # Firmware-compatible SIMBank replies use 0x0004E608 + slot.
        seq = struct.pack("<I", 0x0004E608 + slot)
        blob = hashlib.md5(struct.pack("<I", line_id) + request_payload + b"\xc9").digest()
        return seq + blob

    def make_unsolicited_card_payload(self, line_id: int, card_payload: bytes) -> bytes:
        """Wrap an unsolicited ATR/APDU response in seq/blob/card payload."""
        seq = self.next_seq(line_id)
        blob = self.make_auth_blob(line_id, seq, b"\x00" * 16, card_payload)
        return seq + blob + card_payload

    def synthetic_apdu_response(self, parsed_apdu: ParsedApdu, selected_file: str | None) -> bytes | None:
        """Return a synthetic compatibility response when enabled and applicable."""
        if not self.compat_fcp or not parsed_apdu.valid:
            return None
        if self.profile_overlay and parsed_apdu.ins == 0xB0 and selected_file in PROFILE_TRANSPARENT_DATA:
            data = PROFILE_TRANSPARENT_DATA[selected_file]
            offset = ((parsed_apdu.p1 & 0x7F) << 8) | parsed_apdu.p2
            le = parsed_apdu.p3 or max(0, len(data) - offset)
            return data[offset : offset + le].ljust(le, b"\xff") + b"\x90\x00"
        if self.profile_overlay and parsed_apdu.ins == 0xD6 and selected_file in PROFILE_TRANSPARENT_DATA:
            # Keep the overlay stable. The real card is not modified for files we virtualize.
            return b"\x90\x00"
        if parsed_apdu.ins != 0xC0:
            return None
        if self.compact_profile_fcp and selected_file in COMPACT_PROFILE_FCP:
            fcp = COMPACT_PROFILE_FCP[selected_file]
            logging.info(
                "APDU_ADAPT action=compact_profile_fcp file=%s fcp=%s",
                file_name(selected_file),
                hx(fcp),
            )
            return fcp + b"\x90\x00"
        if (self.profile_overlay or self.profile_fcp_overlay) and selected_file in PROFILE_FCP:
            return PROFILE_FCP[selected_file] + b"\x90\x00"
        return None

    def normalize_apdu_response(self, apdu: bytes, response: bytes, selected_file: str | None) -> bytes:
        """Normalize selected card responses for GoIP firmware compatibility."""
        parsed = parse_apdu(apdu)
        if self.fcp_size_cap and parsed.valid and parsed.ins == 0xC0:
            # Non-transparent: caps UST 6F38->12 / EST 6F56->1. OFF by default — a real
            # SIMBank presents the card's REAL FCP size (firmware paths may expose UST 15, our card 17),
            # and the local slot presents the real size too. Truncating the USIM service
            # table diverges from both. Enable only as a fallback for buggy GoIP firmware.
            response = self.normalize_limited_fcp_for_goip(response, selected_file)
        if GOIP_ECC_SHAPE_ADAPTER and parsed.valid and parsed.ins == 0xC0 and is_ecc_file(selected_file):
            response = self.normalize_ecc_fcp_for_goip(response)
        if self.compat_fcp and apdu[:4] == b"\x00\xa4\x08\x04":
            if self.compact_profile_fcp and selected_file in COMPACT_PROFILE_FCP:
                return bytes([0x61, len(COMPACT_PROFILE_FCP[selected_file])])
            if (self.profile_overlay or self.profile_fcp_overlay) and selected_file in PROFILE_FCP:
                return bytes([0x61, len(PROFILE_FCP[selected_file])])
        if self.compat_fcp and apdu == bytes.fromhex("80f200003b"):
            return response.replace(bytes.fromhex("8b032f0601"), bytes.fromhex("8b032f0604"), 1)
        return response

    def remember_profile_response(self, parsed_apdu: ParsedApdu, response: bytes, selected_file: str | None) -> None:
        """Remember IMSI/AD profile hints used by the derived profile adapter."""
        if not parsed_apdu.valid or parsed_apdu.ins not in {0xB0, 0xB2} or len(response) < 2 or response[-2:] != b"\x90\x00":
            return
        suffix = file_suffix(selected_file)
        data = response[:-2]
        if suffix == "6f07" and parsed_apdu.ins == 0xB0:
            decoded = decode_imsi(data)
            if decoded:
                self.imsi = decoded
        elif suffix == "6fad" and parsed_apdu.ins == 0xB0 and len(data) >= 4:
            candidate = data[3] & 0x0F
            if candidate in {2, 3}:
                self.mnc_len = candidate

    def home_plmn(self) -> tuple[bytes, str] | None:
        """Derive the home PLMN from IMSI and EF AD metadata."""
        if not self.imsi or len(self.imsi) < 5:
            return None
        mcc = self.imsi[:3]
        mnc_len = self.mnc_len or MCC_MNC_LENGTH_BY_MCC.get(mcc, 2)
        if len(self.imsi) < 3 + mnc_len:
            return None
        mnc = self.imsi[3 : 3 + mnc_len]
        encoded = encode_plmn_bcd(mcc, mnc)
        if encoded is None:
            return None
        return encoded, mcc + mnc

    def derived_profile_response(self, parsed_apdu: ParsedApdu, response: bytes, selected_file: str | None) -> bytes:
        """Fill selected empty profile EFs from data read from the real card."""
        if (
            not self.derived_profile_adapter
            or not parsed_apdu.valid
            or parsed_apdu.ins != 0xB0
            or len(response) < 2
            or response[-2:] != b"\x90\x00"
        ):
            return response

        suffix = file_suffix(selected_file)
        data = response[:-2]
        derived = None
        action = None
        source = "real-card-derived"

        if suffix == "6f05" and is_all_ff(data):
            derived = b"enru".ljust(len(data), b"\xff")
            action = "empty_li"
        elif suffix == "6f46" and len(data) >= 2 and data[0] in {0x00, 0xFF} and is_all_ff(data[1:]):
            home = self.home_plmn()
            plmn_key = home[1] if home else ""
            name = OPERATOR_NAME_BY_PLMN.get(plmn_key, f"PLMN {plmn_key}" if plmn_key else "USIM")
            derived = (b"\x00" + name.encode("ascii", errors="ignore"))[: len(data)].ljust(len(data), b"\xff")
            action = "empty_spn"
            source = f"imsi={self.imsi or ''}"
        elif suffix in {"6f60", "6f61"} and is_empty_plmn_act_list(data):
            home = self.home_plmn()
            if home:
                derived = (home[0] + PLMN_ACT_GSM_UMTS_LTE).ljust(len(data), b"\xff")[: len(data)]
                action = "empty_plmn_act"
                source = f"imsi={self.imsi or ''}"

        if derived is None or derived == data:
            return response

        normalized = derived + b"\x90\x00"
        logging.info(
            "APDU_DERIVE action=%s file=%s source=%s real=%s derived=%s",
            action,
            file_name(selected_file),
            source,
            hx(response),
            hx(normalized),
        )
        return normalized

    def to_simbank_response(self, apdu: ParsedApdu, response: bytes) -> bytes:
        """Convert a PC/SC response into SIMBank wire response format."""
        if not apdu.valid or len(response) <= 2:
            return response
        return bytes([apdu.ins]) + response

    def normalize_limited_fcp_for_goip(self, response: bytes, selected_file: str | None) -> bytes:
        """Apply optional FCP size caps for legacy GoIP compatibility."""
        suffix = file_suffix(selected_file)
        limit = GOIP_FILE_SIZE_LIMITS.get(suffix or "")
        if limit is None or len(response) < 4 or response[-2:] != b"\x90\x00" or response[0] != 0x62:
            return response

        fcp = bytearray(response[:-2])
        pos = 2
        real_size = None
        changed = False

        while pos < len(fcp):
            tag = fcp[pos]
            pos += 1
            if (tag & 0x1F) == 0x1F and pos < len(fcp):
                tag = (tag << 8) | fcp[pos]
                pos += 1
            if pos >= len(fcp):
                break
            length = fcp[pos]
            pos += 1
            if length & 0x80:
                n = length & 0x7F
                if n == 0 or pos + n > len(fcp):
                    break
                length = int.from_bytes(fcp[pos : pos + n], "big")
                pos += n
            value_pos = pos
            value_end = value_pos + length
            if value_end > len(fcp):
                break

            if tag == 0x80 and length == 2:
                real_size = int.from_bytes(fcp[value_pos : value_pos + 2], "big")
                if real_size > limit:
                    fcp[value_pos : value_pos + 2] = limit.to_bytes(2, "big")
                    changed = True
                break
            pos = value_end

        normalized = bytes(fcp) + b"\x90\x00"
        if changed:
            logging.info(
                "APDU_ADAPT action=fcp_size_limit file=%s real_size=%s goip_size=%s real=%s goip=%s",
                file_name(selected_file),
                real_size,
                limit,
                hx(response),
                hx(normalized),
            )
        return normalized

    def normalize_ecc_fcp_for_goip(self, response: bytes) -> bytes:
        """Adapt EF ECC record metadata for firmware that expects 4-byte records."""
        if len(response) < 4 or response[-2:] != b"\x90\x00" or response[0] != 0x62:
            return response

        fcp = bytearray(response[:-2])
        pos = 2
        size_value_pos = None
        record_count = self.ecc_record_count
        real_record_len = self.ecc_real_record_len

        while pos < len(fcp):
            tag = fcp[pos]
            pos += 1
            if (tag & 0x1F) == 0x1F and pos < len(fcp):
                tag = (tag << 8) | fcp[pos]
                pos += 1
            if pos >= len(fcp):
                break
            length = fcp[pos]
            pos += 1
            if length & 0x80:
                n = length & 0x7F
                if n == 0 or pos + n > len(fcp):
                    break
                length = int.from_bytes(fcp[pos : pos + n], "big")
                pos += n
            value_pos = pos
            value_end = value_pos + length
            if value_end > len(fcp):
                break

            if tag == 0x82 and length >= 5:
                real_record_len = fcp[value_pos + 3]
                record_count = fcp[value_pos + 4]
                fcp[value_pos + 3] = GOIP_ECC_RECORD_LEN
            elif tag == 0x80 and length == 2:
                size_value_pos = value_pos
            pos = value_end

        self.ecc_real_record_len = max(real_record_len, GOIP_ECC_RECORD_LEN)
        self.ecc_record_count = record_count or self.ecc_record_count
        if size_value_pos is not None:
            goip_size = self.ecc_record_count * GOIP_ECC_RECORD_LEN
            fcp[size_value_pos : size_value_pos + 2] = goip_size.to_bytes(2, "big")

        normalized = bytes(fcp) + b"\x90\x00"
        if normalized != response:
            logging.info(
                "APDU_ADAPT action=ecc_fcp_shape real_record_len=%s goip_record_len=%s records=%s real=%s goip=%s",
                self.ecc_real_record_len,
                GOIP_ECC_RECORD_LEN,
                self.ecc_record_count,
                hx(response),
                hx(normalized),
            )
        return normalized

    def card_apdu_for_goip_request(self, parsed_apdu: ParsedApdu, apdu: bytes, selected_file: str | None) -> bytes:
        """Adapt selected APDUs before forwarding them to the physical card."""
        suffix = file_suffix(selected_file)
        if (
            self.profile_fcp_overlay
            and parsed_apdu.valid
            and parsed_apdu.ins == 0xB0
            and parsed_apdu.p3 is not None
            and suffix in GOIP_TRANSPARENT_SIZE_HINTS
            and parsed_apdu.p3 > GOIP_TRANSPARENT_SIZE_HINTS[suffix]
        ):
            capped = apdu[:4] + bytes([GOIP_TRANSPARENT_SIZE_HINTS[suffix]])
            logging.info(
                "APDU_ADAPT action=read_cap file=%s goip=%s card=%s",
                file_name(selected_file),
                hx(apdu),
                hx(capped),
            )
            return capped
        if (
            GOIP_ECC_SHAPE_ADAPTER
            and
            parsed_apdu.valid
            and is_ecc_file(selected_file)
            and parsed_apdu.ins == 0xB2
            and parsed_apdu.p3 == GOIP_ECC_RECORD_LEN
            and self.ecc_real_record_len > GOIP_ECC_RECORD_LEN
        ):
            adapted = apdu[:4] + bytes([self.ecc_real_record_len])
            logging.info("APDU_ADAPT action=ecc_read_expand goip=%s card=%s", hx(apdu), hx(adapted))
            return adapted
        return apdu

    def pad_profile_read_response(self, parsed_apdu: ParsedApdu, response: bytes, selected_file: str | None) -> bytes:
        """Pad short transparent EF reads to the length requested by the gateway."""
        suffix = file_suffix(selected_file)
        if (
            not self.profile_fcp_overlay
            or not parsed_apdu.valid
            or parsed_apdu.ins != 0xB0
            or parsed_apdu.p3 is None
            or suffix not in GOIP_TRANSPARENT_SIZE_HINTS
            or len(response) < 2
            or response[-2:] != b"\x90\x00"
        ):
            return response

        data = response[:-2]
        if len(data) >= parsed_apdu.p3:
            return response
        padded = data.ljust(parsed_apdu.p3, b"\xff") + b"\x90\x00"
        logging.info(
            "APDU_ADAPT action=read_pad file=%s real_len=%s goip_len=%s real=%s goip=%s",
            file_name(selected_file),
            len(data),
            parsed_apdu.p3,
            hx(response),
            hx(padded),
        )
        return padded

    def compact_ecc_record_for_goip(self, parsed_apdu: ParsedApdu, response: bytes, selected_file: str | None) -> bytes:
        """Compact EF ECC records when the GoIP expects the legacy record shape."""
        if (
            not GOIP_ECC_SHAPE_ADAPTER
            or not parsed_apdu.valid
            or not is_ecc_file(selected_file)
            or parsed_apdu.ins != 0xB2
            or parsed_apdu.p3 != GOIP_ECC_RECORD_LEN
            or len(response) < 2 + GOIP_ECC_RECORD_LEN
            or response[-2:] != b"\x90\x00"
        ):
            return response

        data = response[:-2]
        if len(data) <= GOIP_ECC_RECORD_LEN:
            return response
        compact = data[:3] + data[-1:]
        normalized = compact + b"\x90\x00"
        logging.info(
            "APDU_ADAPT action=ecc_read_compact real_record_len=%s real=%s goip=%s",
            len(data),
            hx(response),
            hx(normalized),
        )
        return normalized

    async def ensure_adf_context(self, slot: int, client_seq: bytes, selected_path: bytes) -> None:
        """Select the USIM ADF before forwarding reserved ADF-path requests."""
        if not self.adf_context_adapter or self.card_context == "adf":
            return
        if not selected_path.startswith(b"\x7f\xff"):
            return
        aid = await self.discover_usim_aid(slot, client_seq)
        response = await self.card.transmit(bytes([0x00, 0xA4, 0x04, 0x04, len(aid)]) + aid)
        logging.info(
            "APDU_ADAPT slot=%s seq=%s action=select_usim_aid aid=%s response=%s",
            slot,
            hx(client_seq),
            hx(aid),
            hx(response),
        )
        if len(response) >= 2 and response[-2] in {0x61, 0x90}:
            self.card_context = "adf"
            if response[-2] == 0x61:
                get_response = bytes([0x00, 0xC0, 0x00, 0x00, response[-1]])
                gr = await self.card.transmit(get_response)
                logging.info(
                    "APDU_ADAPT slot=%s seq=%s action=get_usim_fcp raw=%s response=%s",
                    slot,
                    hx(client_seq),
                    hx(get_response),
                    hx(gr),
                )

    async def discover_usim_aid(self, slot: int, client_seq: bytes) -> bytes:
        """Find the USIM AID through EF DIR, falling back to a standard test AID."""
        if self.usim_aid:
            return self.usim_aid

        select_dir = bytes.fromhex("00a40804022f00")
        dir_response = await self.card.transmit(select_dir)
        logging.info(
            "APDU_ADAPT slot=%s seq=%s action=select_ef_dir raw=%s response=%s",
            slot,
            hx(client_seq),
            hx(select_dir),
            hx(dir_response),
        )
        record_len = 0x26
        records = 2
        if len(dir_response) >= 2 and dir_response[-2] == 0x61:
            fcp = await self.card.transmit(bytes([0x00, 0xC0, 0x00, 0x00, dir_response[-1]]))
            logging.info("APDU_ADAPT slot=%s seq=%s action=get_ef_dir_fcp response=%s", slot, hx(client_seq), hx(fcp))
            parsed = fcp[:-2] if len(fcp) >= 2 else b""
            record_len, records = self.fcp_record_shape(parsed, record_len, records)

        for record in range(1, records + 1):
            read_record = bytes([0x00, 0xB2, record, 0x04, record_len])
            rr = await self.card.transmit(read_record)
            logging.info(
                "APDU_ADAPT slot=%s seq=%s action=read_ef_dir_record_%s raw=%s response=%s",
                slot,
                hx(client_seq),
                record,
                hx(read_record),
                hx(rr),
            )
            aid = self.find_usim_aid(rr[:-2] if len(rr) >= 2 and rr[-2:] == b"\x90\x00" else rr)
            if aid:
                self.usim_aid = aid
                return aid
        return DEFAULT_USIM_AID

    @staticmethod
    def fcp_record_shape(fcp: bytes, default_record_len: int, default_records: int) -> tuple[int, int]:
        """Extract record length/count from FCP, or return provided defaults."""
        for tag, _value, children in parse_tlv(fcp):
            stack = [(tag, _value, children)]
            while stack:
                item_tag, value, item_children = stack.pop()
                if item_tag == 0x82 and len(value) >= 5:
                    return value[3], value[4]
                stack.extend(item_children)
        return default_record_len, default_records

    @staticmethod
    def find_usim_aid(data: bytes) -> bytes | None:
        """Find a USIM AID in a TLV record."""
        for tag, value, children in parse_tlv(data):
            if tag == 0x4F and value.startswith(USIM_AID_PREFIX):
                return value
            found = GoipSimServer.find_usim_aid_from_children(children)
            if found:
                return found
        return None

    @staticmethod
    def find_usim_aid_from_children(tlvs) -> bytes | None:
        """Find a USIM AID recursively in TLV child nodes."""
        for tag, value, children in tlvs:
            if tag == 0x4F and value.startswith(USIM_AID_PREFIX):
                return value
            found = GoipSimServer.find_usim_aid_from_children(children)
            if found:
                return found
        return None

    def update_card_context(self, apdu: ParsedApdu, response: bytes) -> None:
        """Track whether subsequent GoIP file paths should target MF or ADF context."""
        if not apdu.valid or apdu.ins != 0xA4 or not apdu.data or len(response) < 2:
            return
        if response[-2] not in {0x61, 0x90}:
            return
        if apdu.p1 == 0x04 and apdu.data.startswith(USIM_AID_PREFIX):
            self.usim_aid = apdu.data
            self.card_context = "adf"
            return
        if apdu.data.startswith(b"\x7f\xff"):
            self.card_context = "adf"
            return
        if apdu.data.startswith(b"\x3f\x00") or apdu.data.startswith(b"\x2f") or apdu.data.startswith(b"\x7f\x10") or apdu.data.startswith(b"\x7f\x20"):
            self.card_context = "mf"

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle one GoIP TCP session in transparent single-slot mode."""
        peer = writer.get_extra_info("peername")
        buf = b""
        login_payload = None
        accepted = False
        line_id = None
        slot = None
        sent_accept_tail = False
        selected_file = None

        logging.info("tcp connect peer=%s", peer)
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buf += chunk

                while True:
                    pos = buf.find(MAGIC)
                    if pos < 0:
                        buf = b""
                        break
                    if pos > 0:
                        logging.warning("discarding %d bytes before magic from %s", pos, peer)
                        buf = buf[pos:]

                    flen = infer_frame_len(buf)
                    if flen is None:
                        break
                    raw, buf = buf[:flen], buf[flen:]
                    pf = parse_frame(raw)
                    line_id = pf.line_id
                    slot = line_slot(line_id)
                    logging.info(
                        "rx peer=%s slot=%s line_id=%s cmd=0x%04x type=0x%04x len=%d payload=%s ascii=%s",
                        peer,
                        slot,
                        line_id,
                        pf.command,
                        pf.msg_type,
                        len(raw),
                        hx(pf.payload),
                        printable(pf.payload),
                    )

                    if pf.command == 0x0003 and pf.msg_type == 0x0002:
                        login_payload = pf.payload
                        if slot != self.real_slot:
                            logging.info("slot %s is empty/unserved: closing like empty SIM Bank slot", slot)
                            writer.close()
                            await writer.wait_closed()
                            return
                        writer.write(frame(line_id, 0x005B, 0x0001))
                        writer.write(frame(line_id, 0x0028, 0x0000))
                        writer.write(frame(line_id, 0x0003, 0x0002, login_payload))
                        writer.write(frame(line_id, 0x0001, 0x0002, login_payload))
                        await writer.drain()
                        accepted = True
                        sent_accept_tail = True
                        logging.info("tx slot=%s cmd=0x005b + cmd=0x0028 + cmd=0x0003 echo + cmd=0x0001 echo", slot)
                        continue

                    if not accepted:
                        logging.info("slot=%s not accepted yet; ignoring cmd=0x%04x", slot, pf.command)
                        continue

                    if pf.command in {0x001E, 0x0001} and login_payload and not sent_accept_tail:
                        writer.write(frame(line_id, 0x0028, 0x0000))
                        writer.write(frame(line_id, 0x0003, 0x0002, login_payload))
                        await writer.drain()
                        sent_accept_tail = True
                        logging.info("tx slot=%s cmd=0x0028 + cmd=0x0003 echo", slot)
                        continue

                    if pf.command == 0x00C8 and pf.msg_type == 0x0002:
                        # Match the firmware-compatible SIM-bank ordering: send 0x00C9 ack FIRST
                        # (immediately), then reset the card, then (optionally after a
                        # delay) push the unsolicited ATR.
                        c9_payload = self.make_c9_payload(line_id, slot, pf.payload)
                        writer.write(frame(line_id, 0x00C9, 0x0001, c9_payload))
                        await writer.drain()
                        logging.info("tx slot=%s cmd=0x00c9 type=0x0001 payload=%s", slot, hx(c9_payload))
                        try:
                            atr = await self.card.reset()
                            self.card_context = "mf"
                        except Exception as exc:
                            logging.warning("failed to reset/read card ATR before remote SIM session: %s", exc)
                            atr = await self.card.current_atr()
                        if self.atr_delay > 0:
                            await asyncio.sleep(self.atr_delay)
                        if atr:
                            writer.write(frame(line_id, 0x0000, 0x0001, self.make_unsolicited_card_payload(line_id, atr)))
                            await writer.drain()
                            logging.info("tx slot=%s cmd=0x0000 type=0x0001 unsolicited ATR=%s (delay=%ss)", slot, hx(atr), self.atr_delay)
                            logging.info("APDU_RESP slot=%s unsolicited=ATR data=%s", slot, hx(atr))
                        continue

                    if pf.command == 0x0001 and pf.msg_type == 0x0002 and self.echo_control:
                        writer.write(frame(line_id, 0x0001, 0x0002, pf.payload))
                        await writer.drain()
                        logging.info("tx slot=%s cmd=0x0001 type=0x0002 echo", slot)
                        continue

                    if pf.command == 0x0000 and pf.msg_type == 0x0002:
                        if len(pf.payload) < 20:
                            logging.warning("short APDU payload from %s", peer)
                            continue
                        client_seq = pf.payload[:4]
                        client_blob = pf.payload[4:20]
                        apdu = pf.payload[20:]

                        parsed_apdu = parse_apdu(apdu)
                        logging.info(
                            "APDU_REQ slot=%s seq=%s auth=%s raw=%s decode=%s selected=%s",
                            slot,
                            hx(client_seq),
                            hx(client_blob),
                            hx(apdu),
                            decode_apdu_command(parsed_apdu, selected_file),
                            file_name(selected_file),
                        )
                        if not parsed_apdu.valid:
                            logging.error(
                                "INVALID_APDU slot=%s seq=%s raw=%s reason=%s",
                                slot,
                                hx(client_seq),
                                hx(apdu),
                                parsed_apdu.error,
                            )
                            response = b"\x67\x00"
                        else:
                            for warning in apdu_warnings(parsed_apdu):
                                logging.warning(
                                    "APDU_WARN slot=%s seq=%s raw=%s warning=%s",
                                    slot,
                                    hx(client_seq),
                                    hx(apdu),
                                    warning,
                                )
                            response = self.synthetic_apdu_response(parsed_apdu, selected_file)
                            if response is None:
                                if parsed_apdu.ins == 0xA4 and parsed_apdu.p1 in {0x08, 0x09} and parsed_apdu.data.startswith(b"\x7f\xff"):
                                    await self.ensure_adf_context(slot, client_seq, parsed_apdu.data)
                                card_apdu = self.card_apdu_for_goip_request(parsed_apdu, apdu, selected_file)
                                response = await self.card.transmit(card_apdu)
                            else:
                                logging.info(
                                    "APDU_COMPAT slot=%s seq=%s selected=%s raw=%s synthetic_pcsc=%s",
                                    slot,
                                    hx(client_seq),
                                    file_name(selected_file),
                                    hx(apdu),
                                    hx(response),
                                )

                        pending_selected_file = None
                        if parsed_apdu.valid and parsed_apdu.ins == 0xA4 and parsed_apdu.data:
                            pending_selected_file = parsed_apdu.data.hex()
                        if pending_selected_file and len(response) >= 2 and response[-2] in {0x61, 0x90}:
                            selected_file = pending_selected_file

                        self.remember_profile_response(parsed_apdu, response, selected_file)
                        response = self.derived_profile_response(parsed_apdu, response, selected_file)
                        response = self.pad_profile_read_response(parsed_apdu, response, selected_file)
                        response = self.compact_ecc_record_for_goip(parsed_apdu, response, selected_file)
                        normalized_response = self.normalize_apdu_response(apdu, response, selected_file)
                        self.update_card_context(parsed_apdu, normalized_response)
                        wire_response = self.to_simbank_response(parsed_apdu, normalized_response)
                        seq = self.next_seq(line_id)
                        blob = self.make_auth_blob(line_id, seq, client_blob, wire_response)
                        writer.write(frame(line_id, 0x0000, 0x0001, seq + blob + wire_response))
                        await writer.drain()
                        logging.info(
                            "APDU_RESP slot=%s seq=%s raw=%s pcsc=%s decode=%s selected=%s",
                            slot,
                            hx(seq),
                            hx(wire_response),
                            hx(normalized_response),
                            decode_apdu_response(wire_response, parsed_apdu, selected_file),
                            file_name(selected_file),
                        )
                        if wire_response != normalized_response:
                            logging.info("apdu slot=%s %s -> %s wire=%s", slot, hx(apdu), hx(normalized_response), hx(wire_response))
                        elif normalized_response != response:
                            logging.info("apdu slot=%s %s -> %s normalized=%s", slot, hx(apdu), hx(response), hx(normalized_response))
                        else:
                            logging.info("apdu slot=%s %s -> %s", slot, hx(apdu), hx(response))
                        continue

                    if pf.command in {0x0047, 0x0048, 0x004A}:
                        continue

                    logging.info("ignored slot=%s cmd=0x%04x type=0x%04x", slot, pf.command, pf.msg_type)
        except Exception:
            logging.exception("client failure peer=%s line_id=%s slot=%s", peer, line_id, slot)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logging.info("tcp close peer=%s", peer)

    async def run(self):
        """Connect to the PC/SC card and run the TCP listener until stopped."""
        atr = await self.card.connect()
        logging.info("PC/SC reader=%s ATR=%s", self.card.reader_name, hx(atr))
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
        logging.info("listening on %s", sockets)

        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        async with server:
            await stop.wait()
        logging.info("stopping")


def parse_slots(value: str) -> set[int]:
    """Parse slot lists such as '1,3-5' into a set of integers."""
    result = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            result.update(range(int(start), int(end) + 1))
        else:
            result.add(int(part))
    return result


def main():
    """CLI entry point for the transparent single-slot server."""
    parser = argparse.ArgumentParser(description="GoIP Remote SIM prototype server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=56012)
    parser.add_argument("--real-slot", type=int, default=1)
    parser.add_argument("--empty-slots", default="2-16")
    parser.add_argument("--auth-mode", choices=("zero", "echo", "md5"), default=os.getenv("GOIP_AUTH_MODE", "zero"))
    parser.add_argument(
        "--echo-control",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("GOIP_ECHO_CONTROL", "1") not in {"0", "false", "False", "no"},
    )
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"))
    parser.add_argument(
        "--compat-fcp",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("GOIP_COMPAT_FCP", "0") not in {"0", "false", "False", "no"},
        help="Normalize selected USIM FCP responses to the DBLTEK SIMBank compatibility shape.",
    )
    parser.add_argument(
        "--profile-overlay",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("GOIP_PROFILE_OVERLAY", "0") not in {"0", "false", "False", "no"},
        help="Use a coherent LABNET/00101 profile overlay for non-cryptographic SIM EFs.",
    )
    parser.add_argument(
        "--profile-fcp-overlay",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("GOIP_PROFILE_FCP_OVERLAY", "0") not in {"0", "false", "False", "no"},
        help="Use legacy SIMBank-like FCP metadata for selected profile EFs while reading data from the real card.",
    )
    parser.add_argument(
        "--adf-context-adapter",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("GOIP_ADF_CONTEXT_ADAPTER", "1") not in {"0", "false", "False", "no"},
        help="Select the real USIM ADF before forwarding GoIP paths that start with the reserved 7FFF ADF FID.",
    )
    parser.add_argument(
        "--derived-profile-adapter",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("GOIP_DERIVED_PROFILE_ADAPTER", "0") not in {"0", "false", "False", "no"},
        help="Fill selected empty display/preferred-PLMN EFs from real IMSI-derived home PLMN data. Logs APDU_DERIVE.",
    )
    parser.add_argument(
        "--compact-profile-fcp",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("GOIP_COMPACT_PROFILE_FCP", "0") not in {"0", "false", "False", "no"},
        help="Use compact SIMBank-like FCP metadata for selected USIM profile EFs. Data reads still use the card/derived adapter.",
    )
    parser.add_argument(
        "--fcp-size-cap",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("GOIP_FCP_SIZE_CAP", "0") not in {"0", "false", "False", "no"},
        help="Cap UST 6F38->12 / EST 6F56->1 FCP size (NON-transparent, truncates the USIM "
             "service table). OFF by default — present the card's real size like a hardware SIMBank/local slot.",
    )
    parser.add_argument(
        "--atr-delay",
        type=float,
        default=GOIP_ATR_DELAY,
        help="Seconds to wait after the card reset before pushing the unsolicited ATR "
             "(default 6, env GOIP_ATR_DELAY). REQUIRED for full AUTHENTICATE/registration: "
             "the GoIP modem rejects an instant ATR. Tune down to find the minimum.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    empty_slots = parse_slots(args.empty_slots)
    empty_slots.discard(args.real_slot)
    server = GoipSimServer(
        args.host,
        args.port,
        args.real_slot,
        empty_slots,
        args.auth_mode,
        args.echo_control,
        args.compat_fcp,
        args.profile_overlay,
        args.profile_fcp_overlay,
        args.adf_context_adapter,
        args.derived_profile_adapter,
        args.compact_profile_fcp,
        args.fcp_size_cap,
        args.atr_delay,
    )
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
