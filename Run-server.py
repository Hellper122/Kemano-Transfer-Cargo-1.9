#!/usr/bin/env python3

from ktc.server import KTCServer

server = KTCServer(
    port=51820,
    clients_db_path='clients.json',
    default_mask_profile=0,
)
server.start()
