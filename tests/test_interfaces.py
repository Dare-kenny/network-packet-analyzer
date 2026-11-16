"""Unit tests for adapter filtering and the capture readiness check."""

import capture


class FakeInterface:
    """Stands in for a Scapy NetworkInterface."""

    def __init__(self, name, description, mac="", ipv4=None):
        self.name = name
        self.description = description
        self.mac = mac
        self.ips = {4: list(ipv4 or []), 6: []}


# The real interface list from a Windows laptop: two adapters buried in
# six pseudo-interfaces.
WAN_MINIPORT = FakeInterface(
    "Local Area Connection* 8", "WAN Miniport (Network Monitor)"
)
WAN_MINIPORT_IP = FakeInterface("Local Area Connection* 6", "WAN Miniport (IP)")
LOOPBACK = FakeInterface(
    "Loopback Pseudo-Interface 1",
    "Software Loopback Interface 1",
    mac="00:00:00:00:00:00",
    ipv4=["127.0.0.1"],
)
WIFI_DIRECT = FakeInterface(
    "Local Area Connection* 9",
    "Microsoft Wi-Fi Direct Virtual Adapter",
    mac="22:2b:20:82:b6:61",
    ipv4=["169.254.36.185"],
)
WIFI = FakeInterface(
    "WiFi",
    "MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter",
    mac="20:2b:20:82:96:41",
    ipv4=["192.168.1.42"],
)
ETHERNET = FakeInterface(
    "Ethernet",
    "Realtek Gaming GbE Family Controller",
    mac="7c:57:58:61:7f:7f",
    ipv4=["169.254.252.45"],
)

ALL_INTERFACES = [
    WAN_MINIPORT,
    WAN_MINIPORT_IP,
    WIFI,
    WIFI_DIRECT,
    LOOPBACK,
    ETHERNET,
]


class TestIsRealAdapter:
    def test_wan_miniport_has_no_mac_so_is_not_an_adapter(self):
        assert capture.is_real_adapter(WAN_MINIPORT) is False
        assert capture.is_real_adapter(WAN_MINIPORT_IP) is False

    def test_loopback_has_an_all_zero_mac_so_is_not_an_adapter(self):
        assert capture.is_real_adapter(LOOPBACK) is False

    def test_virtual_adapter_is_excluded_despite_a_plausible_mac(self):
        assert capture.is_real_adapter(WIFI_DIRECT) is False

    def test_wifi_is_an_adapter(self):
        assert capture.is_real_adapter(WIFI) is True

    def test_disconnected_ethernet_is_still_an_adapter(self):
        # Real hardware with no lease: listed, not hidden.
        assert capture.is_real_adapter(ETHERNET) is True

    def test_dashed_zero_mac_is_also_rejected(self):
        assert capture.is_real_adapter(
            FakeInterface("x", "y", mac="00-00-00-00-00-00")
        ) is False

    def test_missing_attributes_do_not_raise(self):
        class Bare:
            pass

        assert capture.is_real_adapter(Bare()) is False


class TestDescribeInterface:
    def test_reports_a_routable_address_as_connected(self):
        described = capture.describe_interface(WIFI)

        assert described["name"] == "WiFi"
        assert described["ip"] == "192.168.1.42"
        assert described["connected"] is True

    def test_link_local_address_is_not_a_connection(self):
        described = capture.describe_interface(ETHERNET)

        assert described["ip"] == "169.254.252.45"
        assert described["connected"] is False

    def test_interface_without_an_address_is_not_connected(self):
        described = capture.describe_interface(WAN_MINIPORT)

        assert described["ip"] == ""
        assert described["connected"] is False

    def test_prefers_a_routable_address_over_a_link_local_one(self):
        iface = FakeInterface(
            "Mixed", "d", mac="aa:bb:cc:dd:ee:ff",
            ipv4=["169.254.1.1", "10.0.0.5"],
        )

        assert capture.describe_interface(iface)["ip"] == "10.0.0.5"


class TestListInterfaces:
    def test_hides_pseudo_interfaces(self, monkeypatch):
        monkeypatch.setattr(capture, "get_working_ifaces", lambda: ALL_INTERFACES)

        names = [i["name"] for i in capture.list_interfaces()]

        assert names == ["WiFi", "Ethernet"]

    def test_connected_adapters_are_listed_first(self, monkeypatch):
        monkeypatch.setattr(
            capture, "get_working_ifaces", lambda: [ETHERNET, WIFI]
        )

        names = [i["name"] for i in capture.list_interfaces()]

        assert names == ["WiFi", "Ethernet"]

    def test_include_virtual_returns_the_unfiltered_list(self, monkeypatch):
        monkeypatch.setattr(capture, "get_working_ifaces", lambda: ALL_INTERFACES)

        assert len(capture.list_interfaces(include_virtual=True)) == 6


class TestCaptureReadiness:
    def _patch(self, monkeypatch, elevated, driver, interfaces):
        monkeypatch.setattr(capture, "is_elevated", lambda: elevated)
        monkeypatch.setattr(capture, "has_capture_driver", lambda: driver)
        monkeypatch.setattr(capture, "get_working_ifaces", lambda: interfaces)

    def test_ready_when_elevated_with_a_driver_and_a_connected_adapter(
        self, monkeypatch
    ):
        self._patch(monkeypatch, True, True, [WIFI])

        readiness = capture.capture_readiness()

        assert readiness["ready"] is True
        assert readiness["problems"] == []
        assert readiness["adapters"] == 1

    def test_missing_elevation_blocks_capture(self, monkeypatch):
        self._patch(monkeypatch, False, True, [WIFI])

        readiness = capture.capture_readiness()

        assert readiness["ready"] is False
        codes = [p["code"] for p in readiness["problems"]]
        assert "not_elevated" in codes

    def test_unknown_elevation_does_not_block(self, monkeypatch):
        # POSIX with CAP_NET_RAW: an unprivileged uid proves nothing.
        self._patch(monkeypatch, None, True, [WIFI])

        assert capture.capture_readiness()["ready"] is True

    def test_missing_driver_blocks_capture(self, monkeypatch):
        self._patch(monkeypatch, True, False, [WIFI])

        readiness = capture.capture_readiness()

        assert readiness["ready"] is False
        assert "no_driver" in [p["code"] for p in readiness["problems"]]

    def test_no_adapters_blocks_capture(self, monkeypatch):
        self._patch(monkeypatch, True, True, [])

        readiness = capture.capture_readiness()

        assert readiness["ready"] is False
        assert "no_adapters" in [p["code"] for p in readiness["problems"]]

    def test_disconnected_adapter_warns_without_blocking(self, monkeypatch):
        self._patch(monkeypatch, True, True, [ETHERNET])

        readiness = capture.capture_readiness()

        assert readiness["ready"] is True
        problem = readiness["problems"][0]
        assert problem["code"] == "no_connection"
        assert problem["blocking"] is False

    def test_every_problem_carries_a_fix(self, monkeypatch):
        self._patch(monkeypatch, False, False, [])

        for problem in capture.capture_readiness()["problems"]:
            assert problem["fix"].strip()
            assert problem["message"].strip()

    def test_fix_text_has_no_mangled_escape_characters(self, monkeypatch):
        self._patch(monkeypatch, False, True, [WIFI])

        fix = capture.capture_readiness()["problems"][0]["fix"]

        assert "\x07" not in fix
        assert r"venv\Scripts\python.exe src\app.py" in fix
