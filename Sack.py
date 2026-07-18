from ktc.packets import build_sack_block, parse_sack_block


class SackManager:
    """Управление выборочными подтверждениями."""

    def __init__(self):
        self.received: set[int] = set()
        self.max_continuous: int = -1
        self.max_seen: int = -1

    def add(self, seq: int):
        """Зарегистрировать полученный Seq."""
        self.received.add(seq)
        if seq > self.max_seen:
            self.max_seen = seq
        self._update_continuous()

    def _update_continuous(self):
        """Обновить непрерывную последовательность."""
        c = self.max_continuous
        while (c + 1) in self.received:
            c += 1
        self.max_continuous = c

    def get_ack_seq(self) -> int:
        """Последний непрерывный Seq."""
        return max(0, self.max_continuous)

    def get_ranges(self) -> list[tuple[int, int]]:
        """Диапазоны полученных, но не непрерывных Seq."""
        if self.max_continuous >= self.max_seen:
            return []

        missing = set(range(self.max_continuous + 1, self.max_seen + 1)) - self.received
        if not missing:
            return [(self.max_continuous + 1, self.max_seen)]

        ranges = []
        received_above = sorted(set(range(self.max_continuous + 1, self.max_seen + 1)) - missing)
        if not received_above:
            return []

        start = received_above[0]
        end = received_above[0]
        for s in received_above[1:]:
            if s == end + 1:
                end = s
            else:
                ranges.append((start, end))
                start = s
                end = s
        ranges.append((start, end))
        return ranges

    def build_sack(self) -> bytes:
        """Собрать SACK-блок."""
        return build_sack_block(self.get_ack_seq(), self.get_ranges())

    def cleanup(self, acked: set[int]):
        """Очистить подтверждённые Seq."""
        self.received -= acked
