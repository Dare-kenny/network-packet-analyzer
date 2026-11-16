"""
Milestone 2: in-memory packet store.
Thread safe because packets arrive on a background capture thread while
the Flask request thread reads them at the same time.
"""

import threading


class PacketStore:
    def __init__(self, max_packets=5000):
        self.max_packets = max_packets
        self._lock = threading.Lock()
        self._infos = []
        self._raw_by_id = {}
        self._next_id = 1

    def add(self, raw_packet, info):
        with self._lock:
            info.id = self._next_id
            self._next_id += 1
            self._infos.append(info)
            self._raw_by_id[info.id] = raw_packet

            if len(self._infos) > self.max_packets:
                oldest = self._infos.pop(0)
                self._raw_by_id.pop(oldest.id, None)

    def get_since(self, last_id):
        with self._lock:
            return [i for i in self._infos if i.id > last_id]

    def get_detail(self, packet_id):
        with self._lock:
            raw = self._raw_by_id.get(packet_id)
        if raw is None:
            return None
        return raw.show(dump=True)

    def all(self):
        with self._lock:
            return list(self._infos)

    def raw_packets(self):
        """
        Every retained raw packet, in capture order.

        Driven off _infos rather than the dict so the order always matches
        the records the analysis and the UI are showing, even after the
        ring buffer has evicted the oldest packets.
        """
        with self._lock:
            return [
                self._raw_by_id[info.id]
                for info in self._infos
                if info.id in self._raw_by_id
            ]

    def clear(self):
        with self._lock:
            self._infos = []
            self._raw_by_id = {}
            self._next_id = 1
