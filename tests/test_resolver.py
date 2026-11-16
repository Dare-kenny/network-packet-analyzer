"""
Unit tests for reverse DNS resolution.

Every test injects a fake resolve function, so the suite never issues a
real DNS query and never depends on a network being present.
"""

import socket

import resolver as dns


def make_resolver(names, **kwargs):
    """A resolver backed by a dict, recording which addresses it looked up."""
    looked_up = []

    def fake_resolve(ip):
        looked_up.append(ip)
        return names.get(ip)

    instance = dns.HostnameResolver(
        resolve=fake_resolve, start=False, **kwargs
    )
    instance.looked_up = looked_up

    return instance


class TestLookup:
    def test_first_call_has_no_name_yet(self):
        r = make_resolver({"8.8.8.8": "dns.google"})

        assert r.lookup("8.8.8.8") is None

    def test_name_is_available_after_resolution(self):
        r = make_resolver({"8.8.8.8": "dns.google"})

        r.lookup("8.8.8.8")
        r.drain()

        assert r.lookup("8.8.8.8") == "dns.google"

    def test_an_address_is_only_looked_up_once(self):
        r = make_resolver({"8.8.8.8": "dns.google"})

        for _ in range(5):
            r.lookup("8.8.8.8")
        r.drain()
        for _ in range(5):
            r.lookup("8.8.8.8")
        r.drain()

        assert r.looked_up == ["8.8.8.8"]

    def test_queued_address_is_not_queued_twice_before_it_resolves(self):
        r = make_resolver({"8.8.8.8": "dns.google"})

        r.lookup("8.8.8.8")
        r.lookup("8.8.8.8")
        r.drain()

        assert r.looked_up == ["8.8.8.8"]

    def test_an_address_with_no_ptr_record_is_remembered_as_a_miss(self):
        r = make_resolver({})

        r.lookup("10.0.0.1")
        r.drain()

        assert r.lookup("10.0.0.1") is None
        assert r.cached() == {"10.0.0.1": None}

        # Cached miss: looked up once, never retried.
        r.lookup("10.0.0.1")
        r.drain()
        assert r.looked_up == ["10.0.0.1"]

    def test_empty_address_is_never_looked_up(self):
        r = make_resolver({})

        assert r.lookup("") is None
        assert r.lookup(None) is None

        r.drain()
        assert r.looked_up == []

    def test_disabled_resolver_never_looks_anything_up(self):
        r = make_resolver({"8.8.8.8": "dns.google"}, enabled=False)

        assert r.lookup("8.8.8.8") is None

        r.drain()
        assert r.looked_up == []

    def test_a_full_queue_drops_the_address_rather_than_blocking(self):
        r = make_resolver({}, max_queue=2)

        for n in range(10):
            assert r.lookup("10.0.0.%d" % n) is None

        # Only what fitted in the queue is pending; nothing raised.
        r.drain()
        assert len(r.looked_up) == 2

    def test_a_dropped_address_can_be_retried_later(self):
        r = make_resolver({"10.0.0.9": "late.example"}, max_queue=1)

        r.lookup("10.0.0.1")  # fills the queue
        r.lookup("10.0.0.9")  # dropped
        r.drain()

        # Not stuck in the queued set, so a later poll picks it up.
        r.lookup("10.0.0.9")
        r.drain()

        assert r.lookup("10.0.0.9") == "late.example"


class TestSystemResolve:
    """
    socket.gethostbyaddr is stubbed rather than called: a real lookup here
    would reach the network and hang the suite on a slow resolver.
    """

    def test_returns_the_ptr_name(self, monkeypatch):
        monkeypatch.setattr(
            dns.socket, "gethostbyaddr", lambda ip: ("dns.google", [], [ip])
        )

        assert dns.system_resolve("8.8.8.8") == "dns.google"

    def test_resolver_failures_become_none_rather_than_raising(self, monkeypatch):
        for error in (
            socket.herror("no PTR"),
            socket.gaierror("no address"),
            OSError("network unreachable"),
            UnicodeError("bad encoding"),
            ValueError("not an address"),
        ):

            def failing(ip, exc=error):
                raise exc

            monkeypatch.setattr(dns.socket, "gethostbyaddr", failing)

            assert dns.system_resolve("10.0.0.1") is None


class TestEnabledByEnvironment:
    def test_enabled_when_unset(self):
        assert dns.enabled_by_environment({}) is True

    def test_disabled_by_falsey_values(self):
        for value in ["0", "false", "FALSE", "no", "off", "", "  "]:
            assert dns.enabled_by_environment({"PACKET_ANALYZER_DNS": value}) is False

    def test_enabled_by_other_values(self):
        for value in ["1", "true", "yes", "on"]:
            assert dns.enabled_by_environment({"PACKET_ANALYZER_DNS": value}) is True


class TestAnnotate:
    def test_adds_a_name_field_beside_the_address(self):
        r = make_resolver({"8.8.8.8": "dns.google"})
        rows = [{"host": "8.8.8.8"}]

        dns.annotate(rows, r)
        r.drain()
        dns.annotate(rows, r)

        assert rows[0]["host_name"] == "dns.google"

    def test_field_is_present_even_before_a_name_resolves(self):
        # The payload shape must not change between polls.
        r = make_resolver({"8.8.8.8": "dns.google"})
        rows = [{"host": "8.8.8.8"}]

        dns.annotate(rows, r)

        assert rows[0]["host_name"] is None

    def test_annotates_several_fields(self):
        r = make_resolver({"1.1.1.1": "one.one.one.one", "2.2.2.2": "two.example"})
        rows = [{"host": "1.1.1.1", "target": "2.2.2.2"}]

        dns.annotate(rows, r, fields=("host", "target"))
        r.drain()
        dns.annotate(rows, r, fields=("host", "target"))

        assert rows[0]["host_name"] == "one.one.one.one"
        assert rows[0]["target_name"] == "two.example"

    def test_a_null_field_resolves_to_no_name(self):
        # host_fanout anomalies carry target=None.
        r = make_resolver({})
        rows = [{"host": "1.1.1.1", "target": None}]

        dns.annotate(rows, r, fields=("host", "target"))

        assert rows[0]["target_name"] is None

    def test_empty_rows_are_fine(self):
        assert dns.annotate([], make_resolver({})) == []
