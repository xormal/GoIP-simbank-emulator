# Telnet Access Notes

Заметки предназначены только для ваших личных SIMBank или GoIP, которые находятся в вашей собственности. В примерах используется `192.0.2.10`, адрес
RFC 5737 TEST-NET.

На некоторых прошивках DBLTEK SIMBank telnet-сервис доступен на TCP-порту
`13000`. Login-программа печатает `Start login`, спрашивает пользователя и
выдает numeric challenge.

## Логин dbladm

```text
$ telnet 192.0.2.10 13000
Start login
Login: dbladm
challenge: H123456789
Password:
```

Посчитать пароль локально:

```bash
python3 tools_simbank_telnet_key.py dbladm H123456789
```

Вставьте напечатанную hex-строку как password. Успешный вход дает restricted
shell prompt:

```text
sh#
```

Helper также доступен по пути:

```bash
python3 tools/simbank_telnet_key.py dbladm H123456789
```

## Алгоритмы Challenge

Генерация ответа `dbladm`:

1. `H<number>` парсится как 32-bit challenge.
2. Из signed decimal и unsigned hex фрагментов challenge собирается первая key string.
3. 64-byte zero-padded block хэшируется firmware-вариантом modified MD5.
4. Из выбранных байтов digest и константы `F2GM1V` собирается вторая key.
5. Digest шифруется firmware RC4 variant с нестандартным initial S-box.
6. Восемь выбранных encrypted bytes комбинируются в итоговый lowercase hex password.

`secid` mode использует те же modified MD5 и RC4 primitives, но RC4 key это
16-byte `secid` seed в hex form (не известно, как он генерируется):

```bash
python3 tools_simbank_telnet_key.py secid H123456789 00112233445566778899aabbccddeeff
```

## Restricted Shell

Это не обычный BusyBox shell. Простые команды вроде `ls`, `cat`, `dd` или
абсолютные пути вроде `/bin/ls` могут отклоняться. Firmware command dispatch на
части сборок все равно способен резолвить некоторые внешние комманды через
относительные пути. На таких сборках самый полезная комманда `../../bin/cp`.

## Запуск через `../../bin/cp`

Используйте только на собственных устройствах. Копирование больших flash
partitions может изнашивать flash storage или заполнить временную память, которой всего 128МБ.

Скопировать firmware executables во временный файл:

```text
sh# ../../bin/cp /usr/bin/smb_sim /tmp/smb_sim.bin
sh# ../../bin/cp /usr/bin/smb_scheduler /tmp/smb_scheduler.bin
```

Скопировать flash partition, если вы точно знаете layout:

```text
sh# ../../bin/cp /dev/mtd/7 /tmp/mtd7.bin
```

На прошивках, где web server отдает выбранные файлы из `/tmp`, файл можно
забрать через HTTP:

```bash
curl -o smb_sim.bin http://192.0.2.10/default/en_US/smb_sim.bin
curl -o smb_scheduler.bin http://192.0.2.10/default/en_US/smb_scheduler.bin
```

Если web path не опубликован, используйте vendor UI backup/export flow или
другой канал.

## Полезные Read-Only комманды

Restricted shell на части сборок умеет выполнять некоторые built-in или vendor
встроенные комманды напрямую:

```text
sh# HWINFO
sh# ps
```

Они помогают понять model, firmware process layout и запущенные SIMBank
services.
