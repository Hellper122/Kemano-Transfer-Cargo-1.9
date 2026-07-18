"""
Криптографические примитивы KTC v1.9.
ChaCha20-Poly1305, X25519, BLAKE3, HMAC-SHA256.
"""

import os
import hashlib
import hmac
import blake3
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

HANDSHAKE_CONTEXT = b"KTCv1.9-Handshake"
LEGEND_CONTEXT = b"KTCv1.9-Legend"
SESSION_CONTEXT = b"KTCv1.9-Session"
HW_BIND_CONTEXT = b"KTC-HW-Bind-v1.9"

def generate_root_key() -> bytes:
    """Генерация Root_Key (256 бит)."""
    return os.urandom(32)

def derive_handshake_key(root_key: bytes) -> bytes:
    """Handshake_Key = BLAKE3(Root_Key, 'KTCv1.9-Handshake')"""
    return blake3.derive_key(HANDSHAKE_CONTEXT, root_key)


def derive_legend_key(root_key: bytes) -> bytes:
    """Legend_Key = BLAKE3(Root_Key, 'KTCv1.9-Legend')"""
    return blake3.derive_key(LEGEND_CONTEXT, root_key)


def derive_session_key(shared_secret: bytes) -> bytes:
    """Session_Key = BLAKE3(Shared_Secret, 'KTCv1.9-Session')"""
    return blake3.derive_key(SESSION_CONTEXT, shared_secret)


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Генерация эфемерной пары X25519.
    Возвращает (private_bytes, public_bytes)."""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv.private_bytes_raw(), pub.public_bytes_raw()


def x25519_shared(priv_bytes: bytes, pub_bytes: bytes) -> bytes:
    """Вычисление Shared_Secret."""
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = X25519PublicKey.from_public_bytes(pub_bytes)
    return priv.exchange(pub)

def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """ChaCha20-Poly1305 encrypt. Возвращает ciphertext + tag."""
    cipher = ChaCha20Poly1305(key)
    return cipher.encrypt(nonce, plaintext, None)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes | None:
    """ChaCha20-Poly1305 decrypt. Возвращает plaintext или None."""
    cipher = ChaCha20Poly1305(key)
    try:
        return cipher.decrypt(nonce, ciphertext, None)
    except Exception:
        return None


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def compute_hw_mac_proof(device_secret: bytes, mac_address: str) -> bytes:
    """HW_MAC_Proof = HMAC-SHA256(Device_Secret, eth0_MAC || 'KTC-HW-Bind-v1.9')"""
    return hmac_sha256(device_secret, mac_address.encode() + HW_BIND_CONTEXT)


def compute_legend_sig(legend_key: bytes, timestamp: int,
                       client_x25519: bytes, tpm_quote: bytes,
                       hw_mac_proof: bytes) -> bytes:
    """Legend_Sig = HMAC-SHA256(Legend_Key, Timestamp || Client_X25519 || TPM_Quote || HW_MAC_Proof)"""
    data = (timestamp.to_bytes(8, 'big') + client_x25519 +
            tpm_quote + hw_mac_proof)
    return hmac_sha256(legend_key, data)[:24]


def compute_server_proof(legend_key: bytes, server_x25519: bytes,
                         echoed_timestamp: int) -> bytes:
    """Server_Proof = HMAC-SHA256(Legend_Key, Server_X25519 || Echoed_Timestamp)"""
    data = server_x25519 + echoed_timestamp.to_bytes(8, 'big')
    return hmac_sha256(legend_key, data)

def cargo_nonce(stream_id: int, cargo_seq: int) -> bytes:
    """Nonce = (Stream_ID << 32) | Cargo_Seq (96 бит)."""
    val = (stream_id << 32) | cargo_seq
    return val.to_bytes(12, 'big')
