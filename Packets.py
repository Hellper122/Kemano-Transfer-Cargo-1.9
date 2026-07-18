import struct
import os
from ktc.crypto import aead_encrypt, aead_decrypt, cargo_nonce


KTC0_SIZE = 156
KTCA_SIZE = 108

# Frame Flags
FLAG_EXT_LENGTH  = 0b00000001
FLAG_COMPRESSED  = 0b00000010
FLAG_SACK        = 0b00000100
FLAG_MASK_TRIGGER = 0b00001000
FLAG_HALT        = 0b00010000
FLAG_ALIVE       = 0b00100000


def build_ktc0_inner(timestamp: int, client_x25519: bytes,
                     tpm_quote: bytes, hw_mac_proof: bytes,
                     legend_sig: bytes) -> bytes:
    """Внутренняя структура KTC0 (128 байт)."""
    return struct.pack('>Q', timestamp) + client_x25519 + tpm_quote + hw_mac_proof + legend_sig


def parse_ktc0_inner(data: bytes) -> dict:
    """Парсинг внутренней структуры KTC0."""
    return {
        'timestamp': struct.unpack('>Q', data[0:8])[0],
        'client_x25519': data[8:40],
        'tpm_quote': data[40:72],
        'hw_mac_proof': data[72:104],
        'legend_sig': data[104:128],
    }


def build_ktc0(handshake_key: bytes, timestamp: int, client_x25519: bytes,
               tpm_quote: bytes, hw_mac_proof: bytes, legend_sig: bytes) -> bytes:
    """Собрать и зашифровать KTC0 (156 байт)."""
    inner = build_ktc0_inner(timestamp, client_x25519, tpm_quote, hw_mac_proof, legend_sig)
    nonce = os.urandom(12)
    ciphertext = aead_encrypt(handshake_key, nonce, inner)
    return nonce + ciphertext


def parse_ktc0(handshake_key: bytes, data: bytes) -> dict | None:
    """Расшифровать и распарсить KTC0."""
    if len(data) != KTC0_SIZE:
        return None
    nonce = data[:12]
    ciphertext = data[12:]
    plain = aead_decrypt(handshake_key, nonce, ciphertext)
    if plain is None:
        return None
    return parse_ktc0_inner(plain)


def build_ktca_inner(echoed_timestamp: int, server_x25519: bytes,
                     server_proof: bytes, mask_profile: int) -> bytes:
    """Внутренняя структура KTCA (80 байт)."""
    return (struct.pack('>Q', echoed_timestamp) +
            server_x25519 +
            server_proof +
            struct.pack('>Q', mask_profile))


def parse_ktca_inner(data: bytes) -> dict:
    """Парсинг внутренней структуры KTCA."""
    return {
        'echoed_timestamp': struct.unpack('>Q', data[0:8])[0],
        'server_x25519': data[8:40],
        'server_proof': data[40:72],
        'mask_profile': struct.unpack('>Q', data[72:80])[0],
    }


def build_ktca(handshake_key: bytes, echoed_timestamp: int,
               server_x25519: bytes, server_proof: bytes,
               mask_profile: int) -> bytes:
    """Собрать и зашифровать KTCA (108 байт)."""
    inner = build_ktca_inner(echoed_timestamp, server_x25519, server_proof, mask_profile)
    nonce = os.urandom(12)
    ciphertext = aead_encrypt(handshake_key, nonce, inner)
    return nonce + ciphertext


def parse_ktca(handshake_key: bytes, data: bytes) -> dict | None:
    """Расшифровать и распарсить KTCA."""
    if len(data) != KTCA_SIZE:
        return None
    nonce = data[:12]
    ciphertext = data[12:]
    plain = aead_decrypt(handshake_key, nonce, ciphertext)
    if plain is None:
        return None
    return parse_ktca_inner(plain)


def build_cargo_frame(session_key: bytes, stream_id: int, cargo_seq: int,
                      payload: bytes, flags: int = 0) -> bytes:
    """Собрать и зашифровать Cargo Frame."""
    inner = struct.pack('>I', cargo_seq)
    inner += struct.pack('>B', stream_id)
    inner += struct.pack('>B', flags)

    if flags & FLAG_EXT_LENGTH:
        inner += struct.pack('>H', 0)  # placeholder
        inner += struct.pack('>I', len(payload))
    else:
        inner += struct.pack('>H', len(payload))

    inner += payload
    nonce = cargo_nonce(stream_id, cargo_seq)
    ciphertext = aead_encrypt(session_key, nonce, inner)
    return ciphertext


def parse_cargo_frame(session_key: bytes, data: bytes) -> dict | None:
    """Расшифровать и распарсить Cargo Frame."""
    if len(data) < 24:
        return None

    


def parse_cargo_frame_with_context(session_key: bytes, data: bytes,
                                   stream_id: int, cargo_seq: int) -> dict | None:
    """Расшифровать Cargo Frame с известным stream_id и cargo_seq."""
    nonce = cargo_nonce(stream_id, cargo_seq)
    plain = aead_decrypt(session_key, nonce, data)
    if plain is None:
        return None
    if len(plain) < 8:
        return None

    seq = struct.unpack('>I', plain[0:4])[0]
    sid = plain[4]
    flags = plain[5]
    payload_len = struct.unpack('>H', plain[6:8])[0]
    offset = 8

    if flags & FLAG_EXT_LENGTH:
        if len(plain) < 12:
            return None
        payload_len = struct.unpack('>I', plain[8:12])[0]
        offset = 12

    payload = plain[offset:offset + payload_len]

    return {
        'cargo_seq': seq,
        'stream_id': sid,
        'flags': flags,
        'payload_len': payload_len,
        'payload': payload,
    }

def build_sack_block(ack_seq: int, ranges: list[tuple[int, int]]) -> bytes:
    """Собрать SACK-блок."""
    count = len(ranges)
    data = struct.pack('>H', count)
    data += struct.pack('>I', ack_seq)
    for start, end in ranges:
        data += struct.pack('>II', start, end)
    return data


def parse_sack_block(data: bytes) -> dict:
    """Распарсить SACK-блок."""
    count = struct.unpack('>H', data[0:2])[0]
    ack_seq = struct.unpack('>I', data[2:6])[0]
    ranges = []
    for i in range(count):
        off = 6 + i * 8
        start = struct.unpack('>I', data[off:off+4])[0]
        end = struct.unpack('>I', data[off+4:off+8])[0]
        ranges.append((start, end))
    return {'count': count, 'ack_seq': ack_seq, 'ranges': ranges}


def build_mask_trigger(new_profile: int) -> bytes:
    """Собрать payload для MASK_TRIGGER."""
    return struct.pack('>Q', new_profile)


def parse_mask_trigger(data: bytes) -> int:
    """Извлечь ID профиля из MASK_TRIGGER."""
    return struct.unpack('>Q', data)[0]


def build_halt_frame(session_key: bytes, stream_id: int, cargo_seq: int) -> bytes:
    """Собрать CCLH_HALT."""
    return build_cargo_frame(session_key, stream_id, cargo_seq, b'', FLAG_HALT)


def build_alive_frame(session_key: bytes, stream_id: int, cargo_seq: int) -> bytes:
    """Собрать CCLH_ALIVE."""
    return build_cargo_frame(session_key, stream_id, cargo_seq, b'', FLAG_ALIVE)
