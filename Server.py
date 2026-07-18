import socket
import threading
import time
from ktc.crypto import derive_handshake_key, derive_legend_key
from ktc.handshake import server_process_ktc0, server_build_ktca
from ktc.session import Session
from ktc.masking import MaskingEngine
from ktc.streams import StreamManager
from ktc.utils import load_clients_db


class KTCServer:
    """KTC Сервер."""

    def __init__(self, port: int, clients_db_path: str, default_mask_profile: int = 0):
        self.port = port
        self.clients_db = load_clients_db(clients_db_path)
        self.default_mask_profile = default_mask_profile
        self.sessions: dict[tuple, Session] = {}  # (client_addr) -> Session
        self.managers: dict[tuple, StreamManager] = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = False

    def start(self):
        """Запустить сервер."""
        self.sock.bind(('0.0.0.0', self.port))
        self.running = True
        print(f"[KTC Server] Listening on UDP:{self.port}")

        recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        recv_thread.start()

        try:
            while self.running:
                self._tick()
                time.sleep(0.01)
        except KeyboardInterrupt:
            self.running = False
            print("[KTC Server] Shutting down...")

    def _recv_loop(self):
        """Цикл приёма пакетов."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                self._handle_packet(data, addr)
            except Exception as e:
                if self.running:
                    print(f"[KTC Server] Error: {e}")

    def _handle_packet(self, data: bytes, addr: tuple):
        """Обработать входящий пакет."""
        # Существующая сессия?
        if addr in self.managers:
            self._handle_cargo(data, addr)
            return

        # Слепой приём: перебор клиентов
        for client_id, client_data in self.clients_db.items():
            root_key = bytes.fromhex(client_data['root_key'])
            handshake_key = derive_handshake_key(root_key)
            legend_key = derive_legend_key(root_key)

            result = server_process_ktc0(handshake_key, legend_key, data)
            if result:
                print(f"[KTC Server] Client {client_id} authenticated from {addr}")
                ktca = server_build_ktca(result, self.default_mask_profile)

                # Создать сессию
                session = Session(result['session_key'], self.default_mask_profile)
                masking = MaskingEngine(self.default_mask_profile)
                manager = StreamManager(session, masking)
                manager.start()

                self.sessions[addr] = session
                self.managers[addr] = manager

                self.sock.sendto(ktca, addr)
                return

        # Ни один ключ не подошёл — тишина
        pass

    def _handle_cargo(self, data: bytes, addr: tuple):
        """Обработать Cargo Frame."""
        manager = self.managers[addr]
        # В реальной реализации: парсинг stream_id/seq через контекст
        # Здесь заглушка
        pass

    def _tick(self):
        """Периодические задачи."""
        dead = []
        for addr, manager in list(self.managers.items()):
            if manager.session.is_timed_out() or manager.session.closed:
                dead.append(addr)
                continue
            if manager.need_sack():
                for frame in manager.get_sack_frames():
                    self.sock.sendto(frame, addr)
            if manager.need_alive():
                frame = manager.send_alive()
                self.sock.sendto(frame, addr)

        for addr in dead:
            print(f"[KTC Server] Session closed: {addr}")
            del self.sessions[addr]
            del self.managers[addr]
