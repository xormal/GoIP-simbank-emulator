# Telnet Access Notes

These notes are for SIMBank devices you own or are explicitly authorized to
administer. The examples use `192.0.2.10`, an RFC 5737 TEST-NET address.

Some DBLTEK SIMBank firmware exposes a telnet service on TCP port `13000`. The
login program prints `Start login`, asks for a user, and returns a numeric
challenge.

## dbladm Login

```text
$ telnet 192.0.2.10 13000
Start login
Login: dbladm
challenge: H123456789
Password:
```

Calculate the password locally:

```bash
python3 tools_simbank_telnet_key.py dbladm H123456789
```

Paste the printed hex string as the password. A successful login drops into a
restricted shell prompt:

```text
sh#
```

The helper is also available at:

```bash
python3 tools/simbank_telnet_key.py dbladm H123456789
```

## Challenge Algorithms

`dbladm` response generation:

1. Parse `H<number>` as a 32-bit challenge.
2. Build a first key string from signed decimal and unsigned hex fragments of the challenge.
3. Hash a 64-byte zero-padded block with the firmware's modified MD5 routine.
4. Build a second key from selected digest bytes plus the constant `F2GM1V`.
5. Encrypt the digest with the firmware RC4 variant using a non-standard initial S-box.
6. Select and combine eight encrypted bytes into the final lowercase hex password.

`secid` mode uses the same modified MD5 and RC4 primitives, but the RC4 key is
a 16-byte `secid` seed in hex form:

```bash
python3 tools_simbank_telnet_key.py secid H123456789 00112233445566778899aabbccddeeff
```

## Restricted Shell

The shell is not a normal BusyBox shell. Plain commands such as `ls`, `cat`,
`dd`, or absolute paths such as `/bin/ls` may be rejected. Firmware command
dispatch can still resolve some external commands when called through relative
paths. On affected builds, `../../bin/cp` is the most useful primitive.

## Running Commands through `../../bin/cp`

Use this only on your own lab device. Copying large flash partitions can wear
flash storage or fill temporary memory.

Copy firmware executables to a temporary file:

```text
sh# ../../bin/cp /usr/bin/smb_sim /tmp/smb_sim.bin
sh# ../../bin/cp /usr/bin/smb_scheduler /tmp/smb_scheduler.bin
```

Copy a flash partition when you know the layout:

```text
sh# ../../bin/cp /dev/mtd/7 /tmp/mtd7.bin
```

On firmware builds where the web server exposes selected files from `/tmp`, you
can retrieve the copied file from the HTTP interface:

```bash
curl -o smb_sim.bin http://192.0.2.10/default/en_US/smb_sim.bin
curl -o smb_scheduler.bin http://192.0.2.10/default/en_US/smb_scheduler.bin
```

If the web path is not exposed, use the vendor UI backup/export flow or another
authorized management channel.

## Useful Read-Only Commands

The restricted shell can execute several built-in or vendor commands directly
on some builds:

```text
sh# HWINFO
sh# ps
```

Use these to identify model, firmware process layout, and running SIMBank
services before copying files.
