"""Unit tests for the traffic analysis functions."""

import analysis


class TestProtocolBreakdown:
    def test_empty_capture_yields_no_rows(self):
        assert analysis.protocol_breakdown([]) == []

    def test_counts_packets_and_bytes_per_protocol(self, make_packet):
        packets = [
            make_packet(protocol="TCP", size=100),
            make_packet(protocol="TCP", size=200),
            make_packet(protocol="UDP", size=50),
        ]

        rows = {r["protocol"]: r for r in analysis.protocol_breakdown(packets)}

        assert rows["TCP"]["packets"] == 2
        assert rows["TCP"]["bytes"] == 300
        assert rows["UDP"]["packets"] == 1
        assert rows["UDP"]["bytes"] == 50

    def test_percentages_are_relative_to_the_whole_capture(self, make_packet):
        packets = [
            make_packet(protocol="TCP", size=750),
            make_packet(protocol="UDP", size=250),
        ]

        rows = {r["protocol"]: r for r in analysis.protocol_breakdown(packets)}

        assert rows["TCP"]["packet_pct"] == 50.0
        assert rows["TCP"]["byte_pct"] == 75.0
        assert rows["UDP"]["byte_pct"] == 25.0

    def test_ordered_by_packet_count_descending(self, make_packet):
        packets = (
            [make_packet(protocol="UDP")]
            + [make_packet(protocol="TCP") for _ in range(3)]
            + [make_packet(protocol="ICMP") for _ in range(2)]
        )

        order = [r["protocol"] for r in analysis.protocol_breakdown(packets)]

        assert order == ["TCP", "ICMP", "UDP"]

    def test_equal_counts_break_ties_by_name_for_stable_output(self, make_packet):
        packets = [make_packet(protocol="UDP"), make_packet(protocol="ICMP")]

        order = [r["protocol"] for r in analysis.protocol_breakdown(packets)]

        assert order == ["ICMP", "UDP"]

    def test_unknown_ip_protocols_are_their_own_bucket(self, make_packet):
        packets = [make_packet(protocol="IP proto 47")]

        assert analysis.protocol_breakdown(packets)[0]["protocol"] == "IP proto 47"


class TestTopTalkers:
    def test_empty_capture_yields_no_rows(self):
        assert analysis.top_talkers([]) == []

    def test_counts_both_directions_for_each_host(self, make_packet):
        packets = [
            make_packet(src="A", dst="B", size=100),
            make_packet(src="B", dst="A", size=30),
        ]

        rows = {r["host"]: r for r in analysis.top_talkers(packets)}

        assert rows["A"]["bytes_sent"] == 100
        assert rows["A"]["bytes_received"] == 30
        assert rows["A"]["packets_sent"] == 1
        assert rows["A"]["packets_received"] == 1
        assert rows["A"]["total_bytes"] == 130
        assert rows["B"]["bytes_sent"] == 30
        assert rows["B"]["bytes_received"] == 100

    def test_ranked_by_total_bytes_descending(self, make_packet):
        packets = [
            make_packet(src="quiet", dst="server", size=10),
            make_packet(src="loud", dst="server", size=5000),
        ]

        order = [r["host"] for r in analysis.top_talkers(packets)]

        assert order[0] == "server"  # received everything
        assert order.index("loud") < order.index("quiet")

    def test_peer_count_tracks_distinct_counterparties(self, make_packet):
        packets = [
            make_packet(src="A", dst="B"),
            make_packet(src="A", dst="C"),
            make_packet(src="A", dst="B"),
        ]

        rows = {r["host"]: r for r in analysis.top_talkers(packets)}

        assert rows["A"]["peers"] == 2
        assert rows["B"]["peers"] == 1

    def test_host_talking_to_itself_is_not_its_own_peer(self, make_packet):
        packets = [make_packet(src="127.0.0.1", dst="127.0.0.1")]

        rows = analysis.top_talkers(packets)

        assert len(rows) == 1
        assert rows[0]["peers"] == 0

    def test_limit_truncates_to_the_busiest_hosts(self, make_packet):
        packets = [
            make_packet(src="10.0.0.%d" % i, dst="server", size=i)
            for i in range(1, 11)
        ]

        assert len(analysis.top_talkers(packets, limit=3)) == 3

    def test_limit_none_returns_every_host(self, make_packet):
        packets = [
            make_packet(src="10.0.0.%d" % i, dst="server") for i in range(1, 6)
        ]

        # five sources plus the shared destination
        assert len(analysis.top_talkers(packets, limit=None)) == 6


class TestDetectAnomalies:
    def test_quiet_capture_flags_nothing(self, make_packet):
        packets = [make_packet(src="A", dst="B", dport=80) for _ in range(50)]

        assert analysis.detect_anomalies(packets) == []

    def test_flags_host_contacting_many_addresses(self, make_packet):
        packets = [
            make_packet(src="scanner", dst="10.0.0.%d" % i, dport=80)
            for i in range(1, 31)
        ]

        anomalies = analysis.detect_anomalies(packets)
        fanout = [a for a in anomalies if a["kind"] == "host_fanout"]

        assert len(fanout) == 1
        assert fanout[0]["host"] == "scanner"
        assert fanout[0]["value"] == 30

    def test_fanout_just_below_threshold_is_not_flagged(self, make_packet):
        packets = [
            make_packet(src="busy", dst="10.0.0.%d" % i, dport=80)
            for i in range(1, 10)
        ]

        anomalies = analysis.detect_anomalies(packets, fanout_threshold=10)

        assert [a for a in anomalies if a["kind"] == "host_fanout"] == []

    def test_fanout_at_threshold_is_flagged(self, make_packet):
        packets = [
            make_packet(src="busy", dst="10.0.0.%d" % i, dport=80)
            for i in range(1, 11)
        ]

        anomalies = analysis.detect_anomalies(packets, fanout_threshold=10)

        assert [a["kind"] for a in anomalies] == ["host_fanout"]

    def test_flags_many_ports_on_one_target(self, make_packet):
        packets = [
            make_packet(src="scanner", dst="victim", dport=port)
            for port in range(1, 41)
        ]

        anomalies = analysis.detect_anomalies(packets)
        scans = [a for a in anomalies if a["kind"] == "port_scan"]

        assert len(scans) == 1
        assert scans[0]["host"] == "scanner"
        assert scans[0]["target"] == "victim"
        assert scans[0]["value"] == 40

    def test_portless_protocols_never_trigger_a_port_scan(self, make_packet):
        packets = [
            make_packet(src="pinger", dst="victim", protocol="ICMP", dport=None)
            for _ in range(100)
        ]

        assert analysis.detect_anomalies(packets) == []

    def test_strongest_signal_is_reported_first(self, make_packet):
        packets = [
            make_packet(src="sweeper", dst="10.0.0.%d" % i, dport=80)
            for i in range(1, 51)
        ] + [
            make_packet(src="prober", dst="victim", dport=port)
            for port in range(1, 21)
        ]

        anomalies = analysis.detect_anomalies(packets)

        assert anomalies[0]["value"] >= anomalies[-1]["value"]
        assert anomalies[0]["host"] == "sweeper"

    def test_detail_is_human_readable(self, make_packet):
        packets = [
            make_packet(src="scanner", dst="10.0.0.%d" % i, dport=80)
            for i in range(1, 31)
        ]

        detail = analysis.detect_anomalies(packets)[0]["detail"]

        assert "scanner" in detail
        assert "30" in detail


class TestSummarize:
    def test_empty_capture_is_all_zeros_and_empty_lists(self):
        summary = analysis.summarize([])

        assert summary["total_packets"] == 0
        assert summary["total_bytes"] == 0
        assert summary["unique_hosts"] == 0
        assert summary["duration_seconds"] == 0.0
        assert summary["packets_per_second"] == 0.0
        assert summary["first_seen"] is None
        assert summary["last_seen"] is None
        assert summary["protocols"] == []
        assert summary["top_talkers"] == []
        assert summary["anomalies"] == []

    def test_reports_totals_and_host_count(self, make_packet):
        packets = [
            make_packet(src="A", dst="B", size=100),
            make_packet(src="B", dst="C", size=200),
        ]

        summary = analysis.summarize(packets)

        assert summary["total_packets"] == 2
        assert summary["total_bytes"] == 300
        assert summary["unique_hosts"] == 3

    def test_duration_and_rate_come_from_packet_timestamps(self, make_packet):
        packets = [
            make_packet(timestamp=1000.0),
            make_packet(timestamp=1002.0),
            make_packet(timestamp=1004.0),
        ]

        summary = analysis.summarize(packets)

        assert summary["first_seen"] == 1000.0
        assert summary["last_seen"] == 1004.0
        assert summary["duration_seconds"] == 4.0
        assert summary["packets_per_second"] == 0.75

    def test_single_packet_has_no_span_so_no_rate(self, make_packet):
        summary = analysis.summarize([make_packet(timestamp=1000.0)])

        assert summary["duration_seconds"] == 0.0
        assert summary["packets_per_second"] == 0.0

    def test_passes_top_n_through_to_top_talkers(self, make_packet):
        packets = [
            make_packet(src="10.0.0.%d" % i, dst="server") for i in range(1, 21)
        ]

        assert len(analysis.summarize(packets, top_n=5)["top_talkers"]) == 5

    def test_passes_thresholds_through_to_detection(self, make_packet):
        packets = [
            make_packet(src="host", dst="10.0.0.%d" % i, dport=80)
            for i in range(1, 6)
        ]

        assert analysis.summarize(packets)["anomalies"] == []
        assert analysis.summarize(packets, fanout_threshold=5)["anomalies"] != []
