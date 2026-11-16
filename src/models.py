"""
Milestone 2: structured packet data.
A clean, typed structure for one captured packet, instead of printing
straight to the terminal.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class PacketInfo:
    id: int
    timestamp: float
    src: str
    dst: str
    protocol: str
    size: int
    sport: Optional[int] = None
    dport: Optional[int] = None

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "src": self.src,
            "dst": self.dst,
            "protocol": self.protocol,
            "size": self.size,
            "sport": self.sport,
            "dport": self.dport,
        }
