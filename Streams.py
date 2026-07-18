import threading
import time
import random
from ktc.session import Session
from ktc.masking import MaskingEngine


ALIVE_INTERVAL_MIN = 15
ALIVE_INTERVAL_MAX = 25
SACK_INTERVAL_FRAMES = 16
SACK_INTERVAL_MS = 0.010  # 10 мс


class StreamManager:
    """Управление 8 потоками одной сессии."""

    def __init__(self, session: Session, masking: MaskingEngine):
        self.session = session
        self.masking = masking
        self.running = False
        self._send_lock = threading.Lock()
        self._last_sack_time = 0
        self._frames_since_sack = 0
        self._last_alive = time.time()

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def send_data(self, data: bytes, compressed: bool = True) -> list[bytes]:
        """Разбить данные на блоки и отправить через потоки 1-7."""
        frames = []
        block_size = 65535
        blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]

        for i, block in enumerate(blocks):
            stream_id = (i % 7) + 1  # потоки 1-7
            padded = self.masking.pad_payload(block)
            frame = self.session.send_data(stream_id, padded, compressed)
            frames.append(frame)
            delay = self.masking.get_delay_ms() / 1000
            if delay > 0:
                time.sleep(delay)

        return frames

    def need_sack(self) -> bool:
        """Нужно ли отправить SACK."""
        self._frames_since_sack += 1
        now = time.time()
        if (self._frames_since_sack >= SACK_INTERVAL_FRAMES or
            (now - self._last_sack_time) >= SACK_INTERVAL_MS):
            self._frames_since_sack = 0
            self._last_sack_time = now
            return True
        return False

    def get_sack_frames(self) -> list[bytes]:
        """Получить SACK-фреймы для всех потоков."""
        frames = []
        for stream_id in range(1, 8):
            stream = self.session.streams[stream_id]
            sack_data = stream.sack.build_sack()
            if sack_data and len(sack_data) > 2:  # не пустой
                frame = self.session.send_sack(stream_id, sack_data)
                frames.append(frame)
        return frames

    def need_alive(self) -> bool:
        """Нужно ли отправить keepalive."""
        now = time.time()
        interval = random.uniform(ALIVE_INTERVAL_MIN, ALIVE_INTERVAL_MAX)
        return (now - self._last_alive) >= interval

    def send_alive(self) -> bytes:
        """Отправить keepalive."""
        self._last_alive = time.time()
        return self.session.send_alive()

    def process_incoming(self, data: bytes, stream_id: int, expected_seq: int) -> dict | None:
        """Обработать входящий фрейм."""
        result = self.session.receive(data, stream_id, expected_seq)
        if result:
            self.session.streams[stream_id].sack.add(result['cargo_seq'])
        return result
