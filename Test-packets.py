
import unittest
from ktc.crypto import generate_root_key, derive_handshake_key, derive_legend_key, generate_x25519_keypair
from ktc.packets import (
    build_ktc0, parse_ktc0,
    build_ktca, parse_ktca,
    KTC0_SIZE, KTCA_SIZE,
)


class TestPackets(unittest.TestCase):

    def setUp(self):
        self.root_key = generate_root_key()
        self.handshake_key = derive_handshake_key(self.root_key)
        self.legend_key = derive_legend_key(self.root_key)

    def test_ktc0_roundtrip(self):
        timestamp = 1234567890
        _, pub = generate_x25519_keypair()
        tpm_quote = b'\x00' * 32
        hw_mac = b'\x00' * 32
        from ktc.crypto import compute_legend_sig
        sig = compute_legend_sig(self.legend_key, timestamp, pub, tpm_quote, hw_mac)

        packet = build_ktc0(self.handshake_key, timestamp, pub, tpm_quote, hw_mac, sig)
        self.assertEqual(len(packet), KTC0_SIZE)

        result = parse_ktc0(self.handshake_key, packet)
        self.assertIsNotNone(result)
        self.assertEqual(result['timestamp'], timestamp)

    def test_ktc0_wrong_key(self):
        wrong_key = generate_root_key()
        wrong_hk = derive_handshake_key(wrong_key)
        timestamp = 1234567890
        _, pub = generate_x25519_keypair()
        tpm = b'\x00' * 32
        hw = b'\x00' * 32
        from ktc.crypto import compute_legend_sig
        sig = compute_legend_sig(self.legend_key, timestamp, pub, tpm, hw)

        packet = build_ktc0(self.handshake_key, timestamp, pub, tpm, hw, sig)
        result = parse_ktc0(wrong_hk, packet)
        self.assertIsNone(result)

    def test_ktca_roundtrip(self):
        timestamp = 1234567890
        _, pub = generate_x25519_keypair()
        from ktc.crypto import compute_server_proof
        proof = compute_server_proof(self.legend_key, pub, timestamp)
        mask = 9

        packet = build_ktca(self.handshake_key, timestamp, pub, proof, mask)
        self.assertEqual(len(packet), KTCA_SIZE)

        result = parse_ktca(self.handshake_key, packet)
        self.assertIsNotNone(result)
        self.assertEqual(result['echoed_timestamp'], timestamp)
        self.assertEqual(result['mask_profile'], mask)


if __name__ == '__main__':
    unittest.main()
