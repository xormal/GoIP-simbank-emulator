# Эмулятор GoIP Remote SIMBank

[English](README.md) | Русский

Репозиторий описывает протокол DBLTEK GoIP/SIMBank Remote SIM и содержит
рабочий эмулятор SIMBank, который прокидывает APDU в один или несколько
локальных PC/SC-считывателей.

## История

Я оказался в другой стране с Orange Pi и HID Omnikey, а SIM-карта, с которой
нужно было совершать звонки в моей стране, физически находилась у меня. Дома же
неожиданно оказался DBLTEK GoIP-4. Задача получилась практичная: прокинуть мою
SIM-карту до GoIP через VPN так, чтобы шлюз видел ее как обычный слот SIMBank.

После пары вечеров с прошивками я реализовал эмулятор в виде
`goip_sim_server_full.py`. Используется TCP-протокол SIMBank, использует оригинальное шифрование, выдерживает задержку reset/ATR и пересылает ISO 7816 APDU в
PC/SC-считыватели.

## Структура

- `src/goip_simbank/goip_sim_server_full.py` - полный multi-reader эмулятор SIMBank с SMB-аутентификацией.
- `src/goip_simbank/goip_sim_server.py` - прозрачный single-slot APDU bridge и совместимый протокол, для понимания работы.
- `tools/simbank_telnet_key.py` - helper для telnet `loginlimit` challenge-response.
- `tools_simbank_telnet_key.py` - совместимый wrapper с исходным именем helper-скрипта.
- `docs/protocol.en.md` и `docs/protocol.ru.md` - формат кадров и алгоритмы генерации.
- `docs/telnet-access.en.md` и `docs/telnet-access.ru.md` - telnet-доступ к устройствам DBLTEK.
- `systemd/goip-sim-server-full.service` - пример systemd unit только с тестовыми значениями.
- `examples/goip-sim-server-full.env.example` - пример окружения без реальных секретов.

## Быстрый запуск

В примерах используются только документационные значения: IP SIMBank
`192.0.2.10`, `SMB_ID=1001`, `SCHE_SMB_ID=200`,
`SMB_KEY=lab-smb-key`, `SCHE_SMB_KEY=lab-sche-key`.

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

В настройках GoIP укажите адрес хоста. Для slot 1 при
`SMB_ID=1001` ожидаемый line id равен `100101`, для slot 2 - `100102` и так далее.

## Требования

- Linux-хост: Orange Pi, Raspberry Pi или x86 mini PC.
- Python 3.10 или новее.
- `pcscd` и PC/SC-считыватель, например HID Omnikey, который использовался в проекте.
- Ваша собственная SIM-карта, которую разрешено использовать в этом оборудовании.

## Документация

См. [Protocol Notes](docs/protocol.ru.md): формат кадров, MD5 MAC, генерация
sequence, APDU wrapping, reset/ATR flow и profile adapters.

См. [Telnet Access Notes](docs/telnet-access.ru.md): helper для `loginlimit` и
особенности restricted shell на оборудовании DBLTEK.

## Безопасность

Проект предназначен для исследований взаимодействия устройств, SIM-карт и
сетей, которые находятся в вашей собственности.

## Лицензия

Репозиторий является source-available для личного, образовательного,
исследовательского, interoperability и другого некоммерческого использования.
Коммерческое использование требует предварительного разрешения автора;
свяжитесь с владельцем репозитория через GitHub. Незаконное или
неавторизованное использование запрещено. См. [LICENSE](LICENSE).
