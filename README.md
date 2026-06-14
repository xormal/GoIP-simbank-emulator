# GoIP Remote SIMBank Emulator

English | [Русский](README.ru.md)

This repository documents the DBLTEK GoIP/SIMBank remote-SIM protocol and
contains a working SIMBank emulator that forwards APDUs to one or more local
PC/SC readers.

## Background

I ended up abroad with an Orange Pi and a HID Omnikey smart-card reader, while
the SIM card I wanted to use for calls was with me . At my home country there
was also a DBLTEK GoIP-4 gateway. The practical goal was simple: tunnel my own
SIM card to the GoIP over a VPN and let the gateway use it as if it were plugged
into a local SIMBank.

After a couple of evenings with the firmware, I implemented the emulator as
`goip_sim_server_full.py`. It speaks the SIMBank TCP framing, signs the relevant
messages, handles reset/ATR timing, and relays ISO 7816 APDUs to PC/SC readers.

## Repository Layout

- `src/goip_simbank/goip_sim_server_full.py` - full multi-reader SIMBank emulator with SMB authentication.
- `src/goip_simbank/goip_sim_server.py` - transparent single-slot APDU bridge and compatibility engine.
- `tools/simbank_telnet_key.py` - telnet `loginlimit` challenge-response helper.
- `tools_simbank_telnet_key.py` - compatibility wrapper using the original helper filename.
- `docs/protocol.en.md` and `docs/protocol.ru.md` - frame format and generation algorithms.
- `docs/telnet-access.en.md` and `docs/telnet-access.ru.md` - SIMBank telnet access notes for owned lab devices.
- `systemd/goip-sim-server-full.service` - example service with test values only.
- `examples/goip-sim-server-full.env.example` - sanitized environment example.

## Quick Start

The examples use documentation-only values: SIMBank IP `192.0.2.10`,
`SMB_ID=1001`, `SCHE_SMB_ID=200`, `SMB_KEY=lab-smb-key`,
`SCHE_SMB_KEY=lab-sche-key`.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -e .

goip-sim-server-full \
  --host 0.0.0.0 \
  --port 56012 \
  --smb-id 1001 \
  --smb-key lab-smb-key \
  --sche-smb-id 200 \
  --sche-smb-key lab-sche-key \
  --reader-map "1=0"
```

Point the GoIP SIMBank settings at the emulator host over your VPN. For slot 1
with `SMB_ID=1001`, the expected line id is `100101`.

## Requirements

- Linux host such as Orange Pi, Raspberry Pi, or x86 mini PC.
- Python 3.10 or newer.
- `pcscd` and a PC/SC-compatible reader such as HID Omnikey.
- A SIM card that you own and are allowed to use in the target gateway.

## Documentation

Read [Protocol Notes](docs/protocol.en.md) for the frame layout, MD5 MAC
formulas, sequence generation, APDU wrapping, reset/ATR flow, and profile
adapters.

Read [Telnet Access Notes](docs/telnet-access.en.md) for the optional
`loginlimit` helper and restricted-shell behavior on devices.

## Safety

This project is intended for interoperability research and for devices, SIMs,
and networks you own or are authorized to administer.

## License

This repository is source-available for personal, educational, research,
interoperability, and other non-commercial use. Commercial use requires prior
permission from the author; contact the repository owner through GitHub.
Illegal or unauthorized use is prohibited. See [LICENSE](LICENSE).
