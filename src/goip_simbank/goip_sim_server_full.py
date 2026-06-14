#!/usr/bin/env python3
"""
GoIP Remote SIM — FULL-EMULATION server.

Extends the proven transparent emulator with:

  1. Real SMB wire authentication, implemented from firmware-reviewed behavior
     (see GOIP_SIMBANK_AUTH.md). All three directions are authentic:
       GoIP->SIMBank (login 0x0003, APDU 0x0000 t2):
         MD5( SMB_KEY + str(N) + hex(line_id) ); N=line_id (token) / N=seq (msg)
       SIMBank->GoIP 0x00C9 reset-ack:
         MD5( SCHE_SMB_KEY + str(seq) + hex(seq) )
       SIMBank->GoIP APDU response (0x0000 t1):
         MD5( SCHE_SMB_KEY + str(seq) + hex(local_id) ),
         local_id = SCHE_SMB_ID*1000 + slot  (firmware-compatible)
     Settings: SMB_ID, SMB_KEY, SCHE_SMB_KEY, SCHE_SMB_ID.
     --strict-auth optionally VALIDATEs the GoIP's login token / per-message blobs.
     --no-sign-blobs falls back to echo (GoIP does not validate the server blob).

  2. Multiple USB PC/SC readers — one real SIM per GoIP channel/slot.
     --reader-map "1=0,2=1,3=OMNIKEY,..."  maps slot -> PC/SC reader
     (by index or by name substring). Each slot gets its own card + ISO-7816
     context, served concurrently. Slots with no mapped reader behave like an
     empty SIM-bank slot (connection closed on login).

The transparent APDU path (ADF context, T=0 INS-prefix, UST/EST FCP cap) is
reused unchanged from goip_sim_server.GoipSimServer — one engine instance per
slot, each owning its reader. This file does NOT replace the deployed
transparent server; it is the optional full-emulation variant.
"""
import argparse
import asyncio
import hashlib
import logging
import os
import signal
import struct

try:
    from .goip_sim_server import (
        MAGIC,
        GoipSimServer,
        SimCard,
        apdu_warnings,
        decode_apdu_command,
        decode_apdu_response,
        file_name,
        frame,
        hx,
        infer_frame_len,
        line_slot,
        parse_apdu,
        parse_frame,
        printable,
    )
except ImportError:
    from goip_sim_server import (
        MAGIC,
        GoipSimServer,
        SimCard,
        apdu_warnings,
        decode_apdu_command,
        decode_apdu_response,
        file_name,
        frame,
        hx,
        infer_frame_len,
        line_slot,
        parse_apdu,
        parse_frame,
        printable,
    )

# DBLTEK-style SIMBank firmware uses 0x0004E608 + slot for reset-ack sequence numbers.
C9_SEQ_BASE = 0x0004E608

# Seconds to wait after the card reset before pushing the ATR. ROOT-CAUSE FIX:
# the GoIP remote-SIM modem rejects an instant ATR; needs a post-reset delay
# (hardware SIMBank ATR can arrive several seconds later). Measured in lab:
# 3s/4s FAIL, 5s/7s WORK -> min ~5s;
# default 6s (5s + margin). 0 = legacy/broken. Tune via GOIP_ATR_DELAY/--atr-delay.
ATR_DELAY = float(os.getenv("GOIP_ATR_DELAY", "6"))

FALSEY = {"0", "false", "False", "no", "off", ""}


# ---------------------------------------------------------------------------
# SMB authentication primitives (derived from firmware control flow).
# ---------------------------------------------------------------------------
def smb_blob(smb_key: str, line_id: int, n: int) -> bytes:
    """16-byte MAC = MD5( SMB_KEY + str(N) + hex(line_id) ).

    N is rendered with C printf "%d" semantics (signed 32-bit), line_id with
    "%x" (unsigned, lowercase, no 0x). This matches snprintf("%s%d%x", ...) in
    the GoIP firmware (bin/smb_module).
    """
    n32 = n & 0xFFFFFFFF
    n_signed = n32 - 0x100000000 if n32 >= 0x80000000 else n32
    return hashlib.md5(f"{smb_key}{n_signed}{line_id:x}".encode()).digest()


def smb_login_token(smb_key: str, line_id: int) -> bytes:
    """Login token (cmd 0x0003 payload tail): N == line_id -> static per line."""
    return smb_blob(smb_key, line_id, line_id)


# smb_scheduler / smb_sim key for the SIMBank->GoIP MACs (NOT SMB_KEY).
# Configurable: GOIP_SCHE_SMB_KEY.
#   0x00C9 reset-ack : MD5(SCHE_SMB_KEY + str(seq) + hex(seq))      firmware-compatible
#   0x0000 S->G APDU : MD5(SCHE_SMB_KEY + str(seq) + hex(local_id)) firmware-compatible
#     local_id = SCHE_SMB_ID*1000 + slot (smb_scheduler rewrites the wire id to
#     the GoIP line_id but does NOT recompute the blob -> blob carries local id).
SCHE_SMB_KEY = os.getenv("GOIP_SCHE_SMB_KEY", "lab-sche-key")
SCHE_SMB_ID = int(os.getenv("GOIP_SCHE_SMB_ID", "200"))


def _signed32_str(n: int) -> str:
    """C printf '%d' semantics for the firmware's int seq (signed 32-bit)."""
    n32 = n & 0xFFFFFFFF
    return str(n32 - 0x100000000 if n32 >= 0x80000000 else n32)


def c9_blob(seq: int, sche_smb_key: str = SCHE_SMB_KEY) -> bytes:
    """0x00C9 reset-ack blob = MD5(SCHE_SMB_KEY + str(seq) + hex(seq))."""
    return hashlib.md5(f"{sche_smb_key}{_signed32_str(seq)}{seq:x}".encode()).digest()


def simbank_apdu_blob(sche_smb_key: str, local_id: int, seq: int) -> bytes:
    """Authentic SIMBank->GoIP APDU blob = MD5(SCHE_SMB_KEY + str(seq) + hex(local_id))."""
    return hashlib.md5(f"{sche_smb_key}{_signed32_str(seq)}{local_id:x}".encode()).digest()


# ---------------------------------------------------------------------------
# Reader-map resolution: "1=0,2=1" or "1=OMNIKEY,2=Identive" -> {slot: index}
# ---------------------------------------------------------------------------
def resolve_reader_map(spec: str) -> dict[int, int]:
    """Resolve a slot-to-PC/SC-reader map from CLI text into reader indexes."""
    from smartcard.System import readers as list_readers

    available = [str(r) for r in list_readers()]
    logging.info("PC/SC readers present: %s", available or "(none)")
    mapping: dict[int, int] = {}
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        slot_s, sep, target = part.partition("=")
        if not sep:
            raise ValueError(f"bad --reader-map entry {part!r} (expected slot=reader)")
        slot = int(slot_s.strip())
        target = target.strip()
        if target.isdigit():
            idx = int(target)
            if idx >= len(available):
                raise ValueError(
                    f"slot {slot}: reader index {idx} out of range "
                    f"({len(available)} reader(s) present)"
                )
        else:
            matches = [i for i, n in enumerate(available) if target.lower() in n.lower()]
            if not matches:
                raise ValueError(
                    f"slot {slot}: no PC/SC reader matches name {target!r}; "
                    f"present: {available}"
                )
            idx = matches[0]
        if idx in mapping.values():
            logging.warning("reader index %d mapped to more than one slot", idx)
        mapping[slot] = idx
    if not mapping:
        raise ValueError("--reader-map resolved to no slots")
    return mapping


def build_engine(slot: int, reader_index: int) -> GoipSimServer:
    """A per-slot transparent engine bound to one PC/SC reader.

    Reuses GoipSimServer for the proven transparent APDU path; only its card is
    swapped for the slot's reader. Auth on this engine is unused — the full
    server computes blobs with SMB_KEY itself.
    """
    eng = GoipSimServer(
        host="",
        port=0,
        real_slot=slot,
        empty_slots=set(),
        auth_mode="echo",
        echo_control=True,
        compat_fcp=False,
        profile_overlay=False,
        profile_fcp_overlay=False,
        adf_context_adapter=True,
        derived_profile_adapter=False,
        compact_profile_fcp=False,
    )
    eng.card = SimCard(reader_index)
    return eng


# ---------------------------------------------------------------------------
# Full-emulation server: routes each connection to its slot's engine and signs
# every S->G frame with SMB_KEY.
# ---------------------------------------------------------------------------
class FullGoipSimServer:
    """Full SIMBank-compatible server with SMB authentication and per-slot readers."""

    def __init__(
        self,
        host: str,
        port: int,
        smb_id: int,
        smb_key: str,
        reader_map: dict[int, int],
        strict_auth: bool,
        sign_blobs: bool,
        echo_control: bool = True,
        atr_delay: float = 6.0,
        sche_smb_key: str = SCHE_SMB_KEY,
        sche_smb_id: int = SCHE_SMB_ID,
    ):
        self.host = host
        self.port = port
        self.smb_id = smb_id
        self.smb_key = smb_key
        self.strict_auth = strict_auth
        self.sign_blobs = sign_blobs
        self.echo_control = echo_control
        self.atr_delay = atr_delay
        self.sche_smb_key = sche_smb_key
        self.sche_smb_id = sche_smb_id
        self.reader_map = reader_map
        self.engines: dict[int, GoipSimServer] = {
            slot: build_engine(slot, idx) for slot, idx in reader_map.items()
        }

    # ---- auth helpers -----------------------------------------------------
    def server_blob(self, line_id: int, seq_bytes: bytes, client_blob: bytes) -> bytes:
        """Return the SIMBank->GoIP APDU response blob for a server frame."""
        # Firmware-compatible SIMBank->GoIP APDU blob (cmd 0x0000 type 1):
        #   MD5( SCHE_SMB_KEY + str(seq) + hex(local_id) )
        #   local_id = SCHE_SMB_ID*1000 + slot ; slot = line_id % 100.
        # smb_scheduler rewrites the wire id to the GoIP line_id but does NOT recompute
        # the blob, so the blob carries the LOCAL SIMBank id.
        if self.sign_blobs:
            slot = line_id % 100
            local_id = self.sche_smb_id * 1000 + slot
            seq = struct.unpack("<I", seq_bytes)[0]
            return simbank_apdu_blob(self.sche_smb_key, local_id, seq)
        # echo (transparent-compatible, also registers)
        return (client_blob[:16] if client_blob else b"").ljust(16, b"\x00")

    def expected_line_id(self, slot: int) -> int:
        """Return the external GoIP line id for a configured SMB_ID and slot."""
        return self.smb_id * 100 + slot

    def check_login(self, line_id: int, slot: int, token: bytes) -> bool:
        """Validate the GoIP login token for a line when strict auth is enabled."""
        expect = smb_login_token(self.smb_key, line_id)
        if line_id != self.expected_line_id(slot):
            logging.warning(
                "AUTH line_id=%s does not match SMB_ID*100+slot=%s",
                line_id, self.expected_line_id(slot),
            )
        ok = token == expect
        logging.info(
            "AUTH login slot=%s line_id=%s token=%s expect=%s -> %s",
            slot, line_id, hx(token), hx(expect), "OK" if ok else "MISMATCH",
        )
        return ok

    # ---- connection handler ----------------------------------------------
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Serve one GoIP TCP session, route APDUs to the slot reader, and sign replies."""
        peer = writer.get_extra_info("peername")
        buf = b""
        login_payload = None
        accepted = False
        line_id = None
        slot = None
        engine: GoipSimServer | None = None
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
                        peer, slot, line_id, pf.command, pf.msg_type, len(raw),
                        hx(pf.payload), printable(pf.payload),
                    )

                    # ---- login ------------------------------------------------
                    if pf.command == 0x0003 and pf.msg_type == 0x0002:
                        login_payload = pf.payload
                        engine = self.engines.get(slot)
                        if engine is None:
                            logging.info("slot %s has no mapped reader: closing (empty SIM-bank slot)", slot)
                            writer.close()
                            await writer.wait_closed()
                            return
                        token = pf.payload[4:20] if len(pf.payload) >= 20 else b""
                        ok = self.check_login(line_id, slot, token)
                        if self.strict_auth and not ok:
                            logging.error("AUTH strict: login rejected slot=%s line_id=%s", slot, line_id)
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
                        logging.info("tx slot=%s accept (005b+0028+0003 echo+0001 echo)", slot)
                        continue

                    if not accepted or engine is None:
                        logging.info("slot=%s not accepted yet; ignoring cmd=0x%04x", slot, pf.command)
                        continue

                    if pf.command in {0x001E, 0x0001} and login_payload and not sent_accept_tail:
                        writer.write(frame(line_id, 0x0028, 0x0000))
                        writer.write(frame(line_id, 0x0003, 0x0002, login_payload))
                        await writer.drain()
                        sent_accept_tail = True
                        logging.info("tx slot=%s cmd=0x0028 + cmd=0x0003 echo", slot)
                        continue

                    # ---- 0x001F query -> 0x0069 "0,," -------------------------
                    # DBLTEK SIMBank firmware answers 0x001F (a token-frame query,
                    # once per channel) with cmd=0x0069 payload "0,,". This branch is
                    # defensive completeness for gateway firmware that emits 0x001F.
                    if pf.command == 0x001F:
                        writer.write(frame(line_id, 0x0069, 0x0000, b"0,,"))
                        await writer.drain()
                        logging.info("tx slot=%s cmd=0x0069 payload='0,,' (reply to 0x001F)", slot)
                        continue

                    # ---- session reset (0x00C8 -> 0x00C9 + unsolicited ATR) ----
                    if pf.command == 0x00C8 and pf.msg_type == 0x0002:
                        # SIMBank 0x00C9: seq = 0x0004E608+slot,
                        # blob = MD5(SCHE_SMB_KEY + str(seq) + hex(seq)).
                        # ROOT-CAUSE FIX: send 0x00C9 immediately, then reset, then
                        # push the ATR after ATR_DELAY seconds. An instant ATR is
                        # rejected by the GoIP modem (SIM never "ready", no full auth);
                        # a hardware SIMBank reset path naturally introduces delay.
                        c9_seq_int = C9_SEQ_BASE + slot
                        c9_payload = struct.pack("<I", c9_seq_int) + c9_blob(c9_seq_int, self.sche_smb_key)
                        writer.write(frame(line_id, 0x00C9, 0x0001, c9_payload))
                        await writer.drain()
                        logging.info("tx slot=%s cmd=0x00c9 payload=%s", slot, hx(c9_payload))
                        try:
                            atr = await engine.card.reset()
                            engine.card_context = "mf"
                        except Exception as exc:
                            logging.warning("slot=%s card reset failed: %s", slot, exc)
                            atr = await engine.card.current_atr()
                        if self.atr_delay > 0:
                            await asyncio.sleep(self.atr_delay)
                        if atr:
                            seq = engine.next_seq(line_id)
                            blob = self.server_blob(line_id, seq, b"\x00" * 16)
                            writer.write(frame(line_id, 0x0000, 0x0001, seq + blob + atr))
                            await writer.drain()
                            logging.info("tx slot=%s unsolicited ATR=%s (delay=%ss)", slot, hx(atr), self.atr_delay)
                        continue

                    if pf.command == 0x0001 and pf.msg_type == 0x0002 and self.echo_control:
                        writer.write(frame(line_id, 0x0001, 0x0002, pf.payload))
                        await writer.drain()
                        logging.info("tx slot=%s cmd=0x0001 echo", slot)
                        continue

                    # ---- APDU tunnel ------------------------------------------
                    if pf.command == 0x0000 and pf.msg_type == 0x0002:
                        if len(pf.payload) < 20:
                            logging.warning("short APDU payload from %s", peer)
                            continue
                        client_seq = pf.payload[:4]
                        client_blob = pf.payload[4:20]
                        apdu = pf.payload[20:]

                        if self.strict_auth:
                            exp = smb_blob(self.smb_key, line_id, struct.unpack("<I", client_seq)[0])
                            if client_blob != exp:
                                logging.warning(
                                    "AUTH blob mismatch slot=%s seq=%s got=%s expect=%s",
                                    slot, hx(client_seq), hx(client_blob), hx(exp),
                                )

                        parsed_apdu = parse_apdu(apdu)
                        logging.info(
                            "APDU_REQ slot=%s seq=%s auth=%s raw=%s decode=%s selected=%s",
                            slot, hx(client_seq), hx(client_blob), hx(apdu),
                            decode_apdu_command(parsed_apdu, selected_file), file_name(selected_file),
                        )
                        if not parsed_apdu.valid:
                            logging.error("INVALID_APDU slot=%s raw=%s reason=%s", slot, hx(apdu), parsed_apdu.error)
                            response = b"\x67\x00"
                        else:
                            for warning in apdu_warnings(parsed_apdu):
                                logging.warning("APDU_WARN slot=%s raw=%s warning=%s", slot, hx(apdu), warning)
                            response = engine.synthetic_apdu_response(parsed_apdu, selected_file)
                            if response is None:
                                if (parsed_apdu.ins == 0xA4 and parsed_apdu.p1 in {0x08, 0x09}
                                        and parsed_apdu.data.startswith(b"\x7f\xff")):
                                    await engine.ensure_adf_context(slot, client_seq, parsed_apdu.data)
                                card_apdu = engine.card_apdu_for_goip_request(parsed_apdu, apdu, selected_file)
                                response = await engine.card.transmit(card_apdu)

                        pending_selected_file = None
                        if parsed_apdu.valid and parsed_apdu.ins == 0xA4 and parsed_apdu.data:
                            pending_selected_file = parsed_apdu.data.hex()
                        if pending_selected_file and len(response) >= 2 and response[-2] in {0x61, 0x90}:
                            selected_file = pending_selected_file

                        engine.remember_profile_response(parsed_apdu, response, selected_file)
                        response = engine.derived_profile_response(parsed_apdu, response, selected_file)
                        response = engine.pad_profile_read_response(parsed_apdu, response, selected_file)
                        response = engine.compact_ecc_record_for_goip(parsed_apdu, response, selected_file)
                        normalized = engine.normalize_apdu_response(apdu, response, selected_file)
                        engine.update_card_context(parsed_apdu, normalized)
                        wire_response = engine.to_simbank_response(parsed_apdu, normalized)

                        seq = engine.next_seq(line_id)
                        blob = self.server_blob(line_id, seq, client_blob)
                        writer.write(frame(line_id, 0x0000, 0x0001, seq + blob + wire_response))
                        await writer.drain()
                        logging.info(
                            "APDU_RESP slot=%s seq=%s raw=%s decode=%s selected=%s",
                            slot, hx(seq), hx(wire_response),
                            decode_apdu_response(wire_response, parsed_apdu, selected_file), file_name(selected_file),
                        )
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
        """Start all PC/SC readers and run the TCP listener until SIGINT/SIGTERM."""
        # Bring up each slot's reader so failures surface at startup.
        for slot in sorted(self.engines):
            eng = self.engines[slot]
            try:
                atr = await eng.card.connect()
                logging.info("slot=%s reader=%s ATR=%s", slot, eng.card.reader_name, hx(atr))
            except Exception as exc:
                logging.error("slot=%s reader index %s failed to connect: %s",
                              slot, eng.card.reader_index, exc)
        logging.info(
            "FULL emulation: SMB_ID=%s key=%s sign_blobs=%s strict_auth=%s slots=%s",
            self.smb_id, "set" if self.smb_key else "(empty)",
            self.sign_blobs, self.strict_auth,
            {s: self.engines[s].card.reader_index for s in sorted(self.engines)},
        )
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        sockets = ", ".join(str(s.getsockname()) for s in server.sockets or [])
        logging.info("listening on %s", sockets)

        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        async with server:
            await stop.wait()
        logging.info("stopping")


def env_flag(name: str, default: str) -> bool:
    """Read a boolean environment variable using common false-like strings."""
    return os.getenv(name, default) not in FALSEY


def main():
    """CLI entry point for the full-emulation server."""
    p = argparse.ArgumentParser(description="GoIP Remote SIM — full-emulation server (multi-reader + SMB auth)")
    p.add_argument("--host", default=os.getenv("GOIP_HOST", "0.0.0.0"))
    p.add_argument("--port", type=int, default=int(os.getenv("GOIP_PORT", "56012")))
    p.add_argument("--smb-id", type=int, default=int(os.getenv("GOIP_SMB_ID", "1001")),
                   help="Gateway SMB ID (line_id = SMB_ID*100 + slot). Web field smb_id.")
    p.add_argument("--smb-key", default=os.getenv("GOIP_SMB_KEY", "lab-smb-key"),
                   help="Shared SMB key (web field smb_key) used for the MD5 auth MAC.")
    p.add_argument("--reader-map", default=os.getenv("GOIP_READER_MAP", "1=0"),
                   help='slot->reader, e.g. "1=0,2=1,3=OMNIKEY" (index or name substring).')
    p.add_argument("--strict-auth", action=argparse.BooleanOptionalAction,
                   default=env_flag("GOIP_STRICT_AUTH", "0"),
                   help="Validate the GoIP login token / per-message blobs against SMB_KEY.")
    p.add_argument("--sign-blobs", action=argparse.BooleanOptionalAction,
                   default=env_flag("GOIP_SIGN_BLOBS", "1"),
                   help="Emit firmware-compatible S->G APDU blobs "
                        "(MD5(SCHE_SMB_KEY+seq+hex(local_id))). Default ON. "
                        "--no-sign-blobs falls back to echo.")
    p.add_argument("--sche-smb-key", default=SCHE_SMB_KEY,
                   help="SIMBank scheduler/sim key for S->G MACs (0x00C9 + APDU), "
                        "from env GOIP_SCHE_SMB_KEY.")
    p.add_argument("--sche-smb-id", type=int, default=SCHE_SMB_ID,
                   help="SIMBank-internal id; local_id = SCHE_SMB_ID*1000 + slot "
                        "(env GOIP_SCHE_SMB_ID).")
    p.add_argument("--echo-control", action=argparse.BooleanOptionalAction,
                   default=env_flag("GOIP_ECHO_CONTROL", "1"))
    p.add_argument("--atr-delay", type=float, default=ATR_DELAY,
                   help="Seconds to wait after card reset before pushing the ATR (default 6, "
                        "env GOIP_ATR_DELAY). REQUIRED for full auth — the GoIP modem rejects an "
                        "instant ATR. Measured min ~5s.")
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"))
    args = p.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    reader_map = resolve_reader_map(args.reader_map)
    server = FullGoipSimServer(
        host=args.host,
        port=args.port,
        smb_id=args.smb_id,
        smb_key=args.smb_key,
        reader_map=reader_map,
        strict_auth=args.strict_auth,
        sign_blobs=args.sign_blobs,
        echo_control=args.echo_control,
        atr_delay=args.atr_delay,
        sche_smb_key=args.sche_smb_key,
        sche_smb_id=args.sche_smb_id,
    )
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
