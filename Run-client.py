#!/usr/bin/env python3

from ktc.client import KTCClient

client = KTCClient(
    server_ip='127.0.0.1',
    server_port=51820,
    keys_path='client.keys',
)

if client.connect():
    # Отправка данных
    frames = client.send(b'Hello, KTC!')
    print(f"Sent {len(frames)} frames")

    # Работа...
    import time
    time.sleep(5)

    client.close()
