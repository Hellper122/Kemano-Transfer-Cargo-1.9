
import unittest
from ktc.crypto import (
    generate_root_key,
    derive_handshake_key,
    derive_legend_key,
    derive_session_key,
    generate_x25519_keypair,
    x25519_shared,
    aead_encrypt,
    aead_decrypt,
    hmac_sha256,
    compute_legend_sig,
    compute_server_proof,
    cargo_nonce,
)


class TestCrypto(unittest.TestCase):

    def test_root_key_generation(self):
        key = generate_root_key()
        self.assertEqual(len(key), 32)

    def test_key_derivation(self):
        root = generate_root_key()
        hk = derive_handshake_key(root)
        lk = derive_legend_key(root)
        self.assertEqual(len(hk), 32)
        self.assertEqual(len(lk), 32)
        self.assertNotEqual(hk, lk)

    def test_x25519(self):
        priv1, pub1 = generate_x25519_keypair()
        priv2, pub2 = generate_x25519_keypair()
        shared1 = x25519_shared(priv1, pub2)
        shared2 = x25519_shared(priv2, pub1)
        self.assertEqual(shared1, shared2)

    def test_aead(self):
        key = generate_root_key()
        nonce = b'\x00' * 12
        plain = b'test data'
        ciphertext = aead_encrypt(key, nonce, plain)
        decrypted = aead_decrypt(key, nonce, ciphertext)
        self.assertEqual(plain, decrypted)

    def test_aead_tamper(self):
        key = generate_root_key()
        nonce = b'\x00' * 12
        ciphertext = aead_encrypt(key, nonce, b'data')
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        self.assertIsNone(aead_decrypt(key, nonce, tampered))

    def test_legend_sig(self):
        lk = derive_legend_key(generate_root_key())
        sig = compute_legend_sig(lk, 123456, b'\x00'*32, b'\x00'*32, b'\x00'*32)
        self.assertEqual(len(sig), 24)

    def test_server_proof(self):
        lk = derive_legend_key(generate_root_key())
        proof = compute_server_proof(lk, b'\x00'*32, 123456)
        self.assertEqual(len(proof), 32)

    def test_cargo_nonce(self):
        nonce = cargo_nonce(7, 123456)
        self.assertEqual(len(nonce), 12)


if __name__ == '__main__':
    unittest.main()
