import time
from ktc.packets import (
    build_cargo_frame, parse_cargo_frame_with_context,
    build_halt_frame, build_alive_frame,
    FLAG_HALT, FLAG_ALIVE, FLAG_SACK, FLAG_COMPRESSED,
)
from ktc.sack import SackManager


SILENCE_TIMEOUT_MS = 30000
ALIVE_INTERVAL_MIN = 15
ALIVE_INTERVAL_MAX = 25


class Session:
    """Одна KTC-сессия."""

    def __init__(self, session_key: bytes, mask_profile: int = 0):
        self.session_key = session_key
        self.mask_profile = mask_profile
        self.streams = {}  # stream_id -> Stream
        for i in range(8):
            self.streams[i] = Stream(i)
        self.last_received = time.time()
        self.closed = False

    def send_data(self, stream_id: int, payload: bytes, compressed: bool = False) -> bytes:
        """Отправить данные в потоке."""
        if stream_id < 1 or stream_id > 7:
            raise ValueError("Data streams: 1-7")
        stream = self.streams[stream_id]
        flags = FLAG_COMPRESSED if compressed else 0
        seq = stream.next_seq()
        return build_cargo_frame(self.session_key, stream_id, seq, payload, flags)

    def send_sack(self, stream_id: int, sack_data: bytes) -> bytes:
        """Отправить SACK."""
        flags = FLAG_SACK
        seq = self.streams[stream_id].next_seq()
        return build_cargo_frame(self.session_key, stream_id, seq, sack_data, flags)

    def send_halt(self) -> bytes:
        """Отправить HALT."""
        seq = self.streams[0].next_seq()
        return build_halt_frame(self.session_key, 0, seq)

    def send_alive(self) -> bytes:
        """Отправить keepalive."""
        seq = self.streams[0].next_seq()
        return build_alive_frame(self.session_key, 0, seq)

    def receive(self, data: bytes, stream_id: int, expected_seq: int) -> dict | None:
        """Принять и расшифровать фрейм."""
        result = parse_cargo_frame_with_context(self.session_key, data, stream_id, expected_seq)
        if result:
            self.last_received = time.time()
            if result['flags'] & FLAG_HALT:
                self.closed = True
        return result

    def is_timed_out(self) -> bool:
        """Проверить таймаут."""
        return (time.time() - self.last_received) * 1000 > SILENCE_TIMEOUT_MS


class Stream:
    """Один поток внутри сессии."""

    def __init__(self, stream_id: int):
        self.stream_id = stream_id
        self._seq = 0
        self.sack = SackManager()

    def next_seq(self) -> int:
        seq = self._seq
        self._seq += 1
        return seq

    @property
    def current_seq(self) -> int:
        return self._seq
