"""Unit tests for packet parsing and capture file writing."""

import os

import pytest
from scapy.all import ARP, ICMP, IP, IPv6, Ether, Raw, TCP, UDP, rdpcap

import capture


class TestParsePacket:
    def test_ipv4_tcp_keeps_addresses_and_ports(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=4321, dport=443)

        info = capture.parse_packet(packet)

        assert info.protocol == "TCP"
        assert info.src == "10.0.0.1"
        assert info.dst == "10.0.0.2"
        assert info.sport == 4321
        assert info.dport == 443

    def test_ipv4_udp_keeps_ports(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5353, dport=53)

        info = capture.parse_packet(packet)

        assert info.protocol == "UDP"
        assert info.sport == 5353
        assert info.dport == 53

    def test_icmp_has_no_ports(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()

        info = capture.parse_packet(packet)

        assert info.protocol == "ICMP"
        assert info.sport is None
        assert info.dport is None

    def test_other_ipv4_protocols_are_labelled_by_number(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2", proto=47) / Raw(b"payload")

        assert capture.parse_packet(packet).protocol == "IP proto 47"

    def test_ipv6_is_parsed_not_discarded(self):
        packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(
            sport=1234, dport=80
        )

        info = capture.parse_packet(packet)

        assert info is not None
        assert info.protocol == "TCP"
        assert info.src == "2001:db8::1"
        assert info.dst == "2001:db8::2"
        assert info.dport == 80

    def test_ipv6_udp_is_parsed(self):
        packet = IPv6(src="::1", dst="::2") / UDP(sport=5353, dport=53)

        info = capture.parse_packet(packet)

        assert info.protocol == "UDP"
        assert info.dport == 53

    def test_other_ipv6_protocols_are_labelled_by_next_header(self):
        packet = IPv6(src="::1", dst="::2", nh=59)

        assert capture.parse_packet(packet).protocol == "IPv6 proto 59"

    def test_packets_without_an_ip_layer_are_skipped(self):
        assert capture.parse_packet(Ether() / ARP()) is None

    def test_size_is_the_whole_packet_length(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP() / Raw(b"x" * 100)

        assert capture.parse_packet(packet).size == len(packet)

    def test_uses_the_sniffer_capture_time_when_present(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
        packet.time = 1700000000.5

        assert capture.parse_packet(packet).timestamp == 1700000000.5

    def test_falls_back_to_wall_clock_without_a_capture_time(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
        packet.time = 0

        assert capture.parse_packet(packet).timestamp > 0


class TestSafeCaptureName:
    def test_strips_directory_traversal(self):
        assert capture.safe_capture_name("../../evil.pcap") == "evil.pcap"

    def test_strips_windows_directory_parts(self):
        assert capture.safe_capture_name(r"C:\windows\x.pcap") == "x.pcap"

    def test_adds_the_pcap_extension_when_missing(self):
        assert capture.safe_capture_name("monday") == "monday.pcap"

    def test_replaces_unsafe_characters(self):
        assert capture.safe_capture_name("my cap!.pcap") == "my_cap_.pcap"

    def test_keeps_safe_characters(self):
        assert capture.safe_capture_name("lab-run_2.pcap") == "lab-run_2.pcap"

    def test_falls_back_to_a_timestamped_name_when_nothing_is_left(self):
        for name in ["", "   ", "...", "/"]:
            assert capture.safe_capture_name(name).startswith("capture-")
            assert capture.safe_capture_name(name).endswith(".pcap")


class TestSavePcap:
    def test_writes_packets_that_can_be_read_back(self, tmp_path):
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80),
            IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80),
        ]

        path, count = capture.save_pcap(packets, str(tmp_path), "run.pcap")

        assert count == 2
        assert os.path.isfile(path)

        recovered = rdpcap(path)
        assert len(recovered) == 2
        assert recovered[0][IP].dst == "10.0.0.2"

    def test_refuses_to_write_an_empty_capture(self, tmp_path):
        with pytest.raises(ValueError):
            capture.save_pcap([], str(tmp_path))

    def test_generates_a_timestamped_name_when_none_is_given(self, tmp_path):
        packets = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP()]

        path, _ = capture.save_pcap(packets, str(tmp_path))

        assert os.path.basename(path).startswith("capture-")

    def test_creates_the_target_directory(self, tmp_path):
        target = tmp_path / "does" / "not" / "exist"
        packets = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP()]

        path, _ = capture.save_pcap(packets, str(target))

        assert os.path.isfile(path)

    def test_a_traversing_filename_stays_inside_the_target_directory(self, tmp_path):
        target = tmp_path / "captures"
        packets = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP()]

        path, _ = capture.save_pcap(packets, str(target), "../escaped.pcap")

        assert os.path.dirname(os.path.abspath(path)) == str(target)
