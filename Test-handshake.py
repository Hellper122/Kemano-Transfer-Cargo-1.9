
import unittest
from ktc.crypto import generate_root_key, derive_handshake_key, derive_legend_key
from ktc.handshake import (
    client_prepare_handshake,
    client_build_ktc0,
    client_process_ktca,
    server_process_ktc0,
    server_build_ktca,
)


class TestHandshake(unittest.TestCase):

    def test_full_handshake(self):
        # Общий Root_Key
        root_key = generate_root_key()
        handshake_key = derive_handshake_key(root_key)
        legend_key = derive_legend_key(root_key)

        tpm_quote = b'\x00' * 32
        hw_mac_proof = b'\x00' * 32

        # Клиент
        client_state = client_prepare_handshake(root_key, tpm_quote, hw_mac_proof)
        ktc0 = client_build_ktc0(client_state, tpm_quote, hw_mac_proof)

        # Сервер
        server_state = server_process_ktc0(handshake_key, legend_key, ktc0)
        self.assertIsNotNone(server_state)

        mask_profile = 9
        ktca = server_build_ktca(server_state, mask_profile)

        # Клиент принимает
        result = client_process_ktca(client_state, ktca)
        self.assertIsNotNone(result)
        self.assertEqual(result['mask_profile'], mask_profile)
        self.assertEqual(len(result['session_key']), 32)

    def test_wrong_root_key(self):
        root_key_1 = generate_root_key()
        root_key_2 = generate_root_key()

        tpm = b'\x00' * 32
        hw = b'\x00' * 32

        client_state = client_prepare_handshake(root_key_1, tpm, hw)
        ktc0 = client_build_ktc0(client_state, tpm, hw)

        # Сервер с другим ключом
        hk2 = derive_handshake_key(root_key_2)
        lk2 = derive_legend_key(root_key_2)
        server_state = server_process_ktc0(hk2, lk2, ktc0)
        self.assertIsNone(server_state)


if __name__ == '__main__':
    unittest.main()
