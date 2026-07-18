import os
import json
import struct


def generate_client_keys(client_id: str) -> dict:
    """Сгенерировать ключи для нового клиента."""
    from ktc.crypto import generate_root_key, derive_handshake_key, derive_legend_key

    root_key = generate_root_key()
    return {
        'client_id': client_id,
        'root_key': root_key.hex(),
        'handshake_key': derive_handshake_key(root_key).hex(),
        'legend_key': derive_legend_key(root_key).hex(),
    }


def save_keys(filepath: str, keys: dict):
    """Сохранить ключи в файл."""
    with open(filepath, 'w') as f:
        json.dump(keys, f, indent=2)
    os.chmod(filepath, 0o600)


def load_keys(filepath: str) -> dict:
    """Загрузить ключи из файла."""
    with open(filepath, 'r') as f:
        return json.load(f)


def load_clients_db(filepath: str) -> dict[str, dict]:
    """Загрузить БД клиентов."""
    with open(filepath, 'r') as f:
        return json.load(f)
