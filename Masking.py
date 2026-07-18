import random
import time

PROFILES = {
    0: {'name': 'RAW',              'size_range': None,      'timing': None},
    1: {'name': 'YouTube Live',     'size_range': (1200, 1400), 'timing': 'burst_100_200'},
    2: {'name': 'Zoom Video',       'size_range': (200, 400),   'timing': 'uniform_20'},
    3: {'name': 'Discord Voice',    'size_range': (80, 120),    'timing': 'uniform_20'},
    4: {'name': 'WebRTC Generic',   'size_range': (1100, 1300), 'timing': 'variable_10_50'},
    5: {'name': 'HTTPS CDN',        'size_range': (1460, 1460), 'timing': 'bulk'},
    6: {'name': 'DNS-over-HTTPS',   'size_range': (400, 600),   'timing': 'pairs_100_500'},
    7: {'name': 'Steam Download',   'size_range': (1400, 1500), 'timing': 'continuous'},
    8: {'name': 'STUN/WebRTC',      'size_range': (80, 120),    'timing': 'uniform_20'},
    9: {'name': 'HTTP/3 QUIC',      'size_range': (1200, 1400), 'timing': 'quic'},
    10: {'name': 'Cloudflare Spectrum', 'size_range': None,     'timing': None},
    11: {'name': 'Google QUIC',     'size_range': (1200, 1400), 'timing': 'quic'},
}


class MaskingEngine:
    """Движок маскировки."""

    def __init__(self, profile_id: int = 0):
        self.profile_id = profile_id
        self.profile = PROFILES.get(profile_id, PROFILES[0])

    def set_profile(self, profile_id: int):
        """Сменить профиль."""
        self.profile_id = profile_id
        self.profile = PROFILES.get(profile_id, PROFILES[0])

    def pad_payload(self, payload: bytes) -> bytes:
        """Дополнить payload до размера профиля."""
        size_range = self.profile['size_range']
        if size_range is None:
            return payload

        target = random.randint(*size_range)
        if len(payload) >= target:
            return payload

        return payload + bytes(random.randint(0, 255) for _ in range(target - len(payload)))

    def get_delay_ms(self) -> int:
        """Получить задержку согласно профилю."""
        timing = self.profile['timing']
        if timing is None:
            return 0

        jitter = random.uniform(0.9, 1.1)

        if timing == 'uniform_20':
            return int(20 * jitter)
        elif timing == 'variable_10_50':
            return int(random.randint(10, 50) * jitter)
        elif timing == 'burst_100_200':
            return int(random.randint(100, 200) * jitter)
        elif timing == 'bulk':
            return int(random.randint(1, 5) * jitter)
        elif timing == 'pairs_100_500':
            return int(random.randint(100, 500) * jitter)
        elif timing == 'continuous':
            return int(random.randint(5, 20) * jitter)
        elif timing == 'quic':
            return int(random.randint(5, 30) * jitter)
        return 0
