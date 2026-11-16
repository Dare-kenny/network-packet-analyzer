"""Shared helpers for the test suite."""

import pytest

from models import PacketInfo


@pytest.fixture
def make_packet():
    """
    Factory for PacketInfo records with sensible defaults.

    Tests override only the fields they care about, which keeps each case
    about the behaviour under test instead of packet boilerplate.
    """
    counter = {"n": 0}

    def _make(
        src="10.0.0.1",
        dst="10.0.0.2",
        protocol="TCP",
        size=100,
        sport=1234,
        dport=80,
        timestamp=None,
    ):
        counter["n"] += 1
        return PacketInfo(
            id=counter["n"],
            timestamp=1000.0 if timestamp is None else timestamp,
            src=src,
            dst=dst,
            protocol=protocol,
            size=size,
            sport=sport,
            dport=dport,
        )

    return _make
