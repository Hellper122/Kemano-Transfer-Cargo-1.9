import time
from ktc.crypto import (
    derive_handshake_key, derive_legend_key, derive_session_key,
    generate_x25519_keypair, x25519_shared,
    compute_legend_sig, compute_server_proof,
)
from ktc.packets import (
    build_ktc0, parse_ktc0,
    build_ktca, parse_ktca,
)


TIMESTAMP_WINDOW_MS = 30000


def client_prepare_handshake(root_key: bytes, tpm_quote: bytes,
                             hw_mac_proof: bytes) -> dict:
    """Подготовка данных для KTC0."""
    handshake_key = derive_handshake_key(root_key)
    legend_key = derive_legend_key(root_key)
    priv_bytes, pub_bytes = generate_x25519_keypair()
    timestamp = int(time.time() * 1000)
    legend_sig = compute_legend_sig(legend_key, timestamp, pub_bytes,
                                    tpm_quote, hw_mac_proof)
    return {
        'handshake_key': handshake_key,
        'legend_key': legend_key,
        'client_priv': priv_bytes,
        'client_pub': pub_bytes,
        'timestamp': timestamp,
        'legend_sig': legend_sig,
    }


def client_build_ktc0(state: dict, tpm_quote: bytes, hw_mac_proof: bytes) -> bytes:
    """Собрать KTC0."""
    return build_ktc0(
        state['handshake_key'],
        state['timestamp'],
        state['client_pub'],
        tpm_quote,
        hw_mac_proof,
        state['legend_sig'],
    )


def client_process_ktca(state: dict, data: bytes) -> dict | None:
    """Обработать KTCA, вернуть состояние сессии."""
    parsed = parse_ktca(state['handshake_key'], data)
    if parsed is None:
        return None
    if parsed['echoed_timestamp'] != state['timestamp']:
        return None

    expected_proof = compute_server_proof(
        state['legend_key'],
        parsed['server_x25519'],
        parsed['echoed_timestamp'],
    )
    if parsed['server_proof'] != expected_proof:
        return None

    shared = x25519_shared(state['client_priv'], parsed['server_x25519'])
    session_key = derive_session_key(shared)

    return {
        'session_key': session_key,
        'mask_profile': parsed['mask_profile'],
    }


def server_process_ktc0(handshake_key: bytes, legend_key: bytes, data: bytes) -> dict | None:
    """Обработать KTC0, вернуть состояние для KTCA."""
    parsed = parse_ktc0(handshake_key, data)
    if parsed is None:
        return None

    now = int(time.time() * 1000)
    if abs(now - parsed['timestamp']) > TIMESTAMP_WINDOW_MS:
        return None

    expected_sig = compute_legend_sig(
        legend_key,
        parsed['timestamp'],
        parsed['client_x25519'],
        parsed['tpm_quote'],
        parsed['hw_mac_proof'],
    )
    if parsed['legend_sig'] != expected_sig:
        return None

    # TPM_Quote и HW_MAC_Proof проверяются в реальной реализации
    # (здесь заглушка — проверка наличия)

    server_priv, server_pub = generate_x25519_keypair()
    server_proof = compute_server_proof(legend_key, server_pub, parsed['timestamp'])
    shared = x25519_shared(server_priv, parsed['client_x25519'])
    session_key = derive_session_key(shared)

    return {
        'handshake_key': handshake_key,
        'server_priv': server_priv,
        'server_pub': server_pub,
        'server_proof': server_proof,
        'echoed_timestamp': parsed['timestamp'],
        'client_pub': parsed['client_x25519'],
        'session_key': session_key,
    }


def server_build_ktca(state: dict, mask_profile: int = 0) -> bytes:
    """Собрать KTCA."""
    return build_ktca(
        state['handshake_key'],
        state['echoed_timestamp'],
        state['server_pub'],
        state['server_proof'],
        mask_profile,
    )
