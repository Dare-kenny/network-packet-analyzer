"""Unit tests for the in-memory packet store."""

from models import PacketInfo
from store import PacketStore


def info(src="10.0.0.1", dst="10.0.0.2", size=100):
    return PacketInfo(
        id=0,
        timestamp=1000.0,
        src=src,
        dst=dst,
        protocol="TCP",
        size=size,
        sport=1234,
        dport=80,
    )


class TestAdd:
    def test_assigns_sequential_ids_starting_at_one(self):
        store = PacketStore()

        store.add("raw-1", info())
        store.add("raw-2", info())

        assert [i.id for i in store.all()] == [1, 2]

    def test_retains_packets_in_capture_order(self):
        store = PacketStore()

        store.add("raw-1", info(src="first"))
        store.add("raw-2", info(src="second"))

        assert [i.src for i in store.all()] == ["first", "second"]


class TestRingBuffer:
    def test_never_grows_past_max_packets(self):
        store = PacketStore(max_packets=3)

        for _ in range(10):
            store.add("raw", info())

        assert len(store.all()) == 3

    def test_evicts_the_oldest_records_first(self):
        store = PacketStore(max_packets=3)

        for n in range(1, 6):
            store.add("raw-%d" % n, info())

        assert [i.id for i in store.all()] == [3, 4, 5]

    def test_evicted_raw_packets_are_released(self):
        store = PacketStore(max_packets=2)

        for n in range(1, 4):
            store.add("raw-%d" % n, info())

        assert store.get_detail(1) is None
        assert len(store.raw_packets()) == 2


class TestGetSince:
    def test_returns_only_newer_packets(self):
        store = PacketStore()

        for _ in range(5):
            store.add("raw", info())

        assert [i.id for i in store.get_since(3)] == [4, 5]

    def test_since_zero_returns_everything(self):
        store = PacketStore()
        store.add("raw", info())

        assert len(store.get_since(0)) == 1

    def test_returns_nothing_when_caught_up(self):
        store = PacketStore()
        store.add("raw", info())

        assert store.get_since(1) == []


class TestRawPackets:
    def test_empty_store_has_no_raw_packets(self):
        assert PacketStore().raw_packets() == []

    def test_returns_raw_packets_in_capture_order(self):
        store = PacketStore()

        store.add("raw-1", info())
        store.add("raw-2", info())
        store.add("raw-3", info())

        assert store.raw_packets() == ["raw-1", "raw-2", "raw-3"]

    def test_stays_aligned_with_records_after_eviction(self):
        store = PacketStore(max_packets=2)

        for n in range(1, 5):
            store.add("raw-%d" % n, info())

        assert store.raw_packets() == ["raw-3", "raw-4"]
        assert len(store.raw_packets()) == len(store.all())


class TestGetDetail:
    def test_unknown_id_returns_none(self):
        assert PacketStore().get_detail(999) is None


class TestClear:
    def test_drops_all_packets_and_restarts_ids(self):
        store = PacketStore()
        store.add("raw", info())
        store.add("raw", info())

        store.clear()

        assert store.all() == []
        assert store.raw_packets() == []

        store.add("raw", info())
        assert store.all()[0].id == 1
