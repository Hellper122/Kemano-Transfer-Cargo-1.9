import socket
import sys


class Relay:
    """UDP-ретранслятор для KTC."""

    def __init__(self, listen_port: int, target_ip: str, target_port: int):
        self.listen_port = listen_port
        self.target_addr = (target_ip, target_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def run(self):
        """Запустить ретранслятор."""
        self.sock.bind(('0.0.0.0', self.listen_port))
        print(f"[KTC Relay] Listening on UDP:{self.listen_port} -> {self.target_addr}")

        # Словарь для обратной маршрутизации: client_addr -> None
        # Ответы просто летят обратно через NAT
        try:
            while True:
                data, client_addr = self.sock.recvfrom(65535)
                self.sock.sendto(data, self.target_addr)
                # Ответ от сервера придёт сюда же,
                # но надо переслать обратно клиенту.
                # В простом варианте: получаем ответ, но не знаем клиента.
                # Решение: слушать и пересылать в обе стороны.
        except KeyboardInterrupt:
            print("[KTC Relay] Shutting down...")
        finally:
            self.sock.close()


# Двунаправленный ретранслятор
class BidirectionalRelay:
    """Двунаправленный UDP-ретранслятор."""

    def __init__(self, listen_port: int, target_ip: str, target_port: int):
        self.listen_port = listen_port
        self.target_addr = (target_ip, target_port)
        self.clients = {}  # client_addr -> последнее время

    def run(self):
        """Запустить."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.listen_port))
        print(f"[KTC Relay] Bidirectional UDP:{self.listen_port} <-> {self.target_addr}")

        try:
            while True:
                data, addr = sock.recvfrom(65535)

                if addr == self.target_addr:
                    # Ответ от сервера — найти клиента и переслать
                    # В реальности нужна таблица сессий.
                    # Здесь упрощённо: используем последнего клиента.
                    if self.clients:
                        client = max(self.clients, key=self.clients.get)
                        sock.sendto(data, client)
                else:
                    # Запрос от клиента — переслать серверу
                    self.clients[addr] = __import__('time').time()
                    sock.sendto(data, self.target_addr)

        except KeyboardInterrupt:
            print("[KTC Relay] Shutting down...")
        finally:
            sock.close()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python relay.py <listen_port> <target_ip:target_port>")
        sys.exit(1)

    listen_port = int(sys.argv[1])
    target_ip, target_port = sys.argv[2].split(':')
    target_port = int(target_port)

    relay = BidirectionalRelay(listen_port, target_ip, target_port)
    relay.run()
