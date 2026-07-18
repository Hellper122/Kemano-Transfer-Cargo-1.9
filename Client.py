import socket
import time
import threading
from ktc.crypto import derive_handshake_key, derive_legend_key, compute_hw_mac_proof
from ktc.handshake import client_prepare_handshake, client_build_ktc0, client_process_ktca
from ktc.session import Session
from ktc.masking import MaskingEngine
from ktc.streams import StreamManager
from ktc.utils import load_keys


class KTCClient:
    """KTC Клиент."""

    def __init__(self, server_ip: str, server_port: int, keys_path: str):
        self.server_addr = (server_ip, server_port)
        self.keys = load_keys(keys_path)
        self.root_key = bytes.fromhex(self.keys['root_key'])
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.session: Session = None
        self.manager: StreamManager = None
        self.running = False

    def connect(self, tpm_quote: bytes = b'\x00' * 32,
                hw_mac_proof: bytes = None) -> bool:
        """Установить соединение."""
        if hw_mac_proof is None:
            # Заглушка — в реальности через TPM
            hw_mac_proof = compute_hw_mac_proof(b'\x00' * 32, '00:00:00:00:00:00')

        state = client_prepare_handshake(self.root_key, tpm_quote, hw_mac_proof)
        ktc0 = client_build_ktc0(state, tpm_quote, hw_mac_proof)

        self.sock.sendto(ktc0, self.server_addr)
        self.sock.settimeout(5.0)

        try:
            data, addr = self.sock.recvfrom(2048)
            if addr != self.server_addr:
                return False

            result = client_process_ktca(state, data)
            if result is None:
                return False

            self.session = Session(result['session_key'], result['mask_profile'])
            self.masking = MaskingEngine(result['mask_profile'])
            self.manager = StreamManager(self.session, self.masking)
            self.manager.start()
            self.running = True
            self.sock.settimeout(0.1)

            # Запуск приёма
            self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._recv_thread.start()

            print(f"[KTC Client] Connected. Profile: {self.masking.profile['name']}")
            return True

        except socket.timeout:
            print("[KTC Client] Connection timeout")
            return False

    def send(self, data: bytes) -> list[bytes]:
        """Отправить данные."""
        if not self.running:
            raise RuntimeError("Not connected")
        return self.manager.send_data(data)

    def _recv_loop(self):
        """Цикл приёма."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                if addr == self.server_addr:
                    # Обработка входящего фрейма
                    pass  # В реальной реализации
            except socket.timeout:
                continue
            except Exception:
                break

    def close(self):
        """Закрыть соединение."""
        if self.manager:
            halt = self.manager.session.send_halt()
            self.sock.sendto(halt, self.server_addr)
        self.running = False
        self.sock.close()
        print("[KTC Client] Disconnected")
