"""
Milestone 2: capture manager.
Runs Scapy's sniffer on a background thread so the web server can start
and stop it on demand, instead of blocking the whole program.

Must run as Administrator on Windows and requires Npcap to be installed.
"""

import ctypes
import os
import re
import threading
import time

from scapy.all import (
    AsyncSniffer,
    get_working_ifaces,
    wrpcap,
    ICMP,
    IP,
    IPv6,
    TCP,
    UDP,
)

from models import PacketInfo

# Only these characters survive in a user supplied capture filename.
SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]")


# Windows reports a pile of pseudo-interfaces next to the real NICs. None
# of them carry traffic, so offering them only invites a capture that sits
# at zero packets forever.
VIRTUAL_MARKERS = (
    "wan miniport",
    "virtual adapter",
    "loopback",
    "pseudo-interface",
    "tap-windows",
    "tunnel",
)

# A link-local address means the adapter never got a lease: it is real
# hardware, but it is not on a network right now.
LINK_LOCAL_PREFIXES = ("169.254.", "127.")


def _ipv4_addresses(iface):
    ips = getattr(iface, "ips", None) or {}
    return [address for address in ips.get(4, []) if address]


def is_real_adapter(iface):
    """
    True for actual network adapters, False for the pseudo-interfaces.

    Decided on hardware facts first: an interface with no MAC at all (the
    WAN Miniports) or an all-zero MAC (loopback) is not a NIC. The name
    check is the backstop for virtual adapters that do carry a plausible
    MAC, such as Microsoft's Wi-Fi Direct ones.
    """
    mac = (getattr(iface, "mac", "") or "").strip()
    if not mac:
        return False

    if set(mac.replace(":", "").replace("-", "")) <= {"0"}:
        return False

    haystack = "%s %s" % (
        getattr(iface, "name", "") or "",
        getattr(iface, "description", "") or "",
    )
    haystack = haystack.lower()

    return not any(marker in haystack for marker in VIRTUAL_MARKERS)


def describe_interface(iface):
    """Flatten a Scapy interface into the fields the UI needs."""
    addresses = _ipv4_addresses(iface)
    routable = [
        address
        for address in addresses
        if not address.startswith(LINK_LOCAL_PREFIXES)
    ]

    return {
        "name": getattr(iface, "name", "") or "",
        "description": getattr(iface, "description", "") or "",
        "mac": (getattr(iface, "mac", "") or "").strip(),
        "ip": routable[0] if routable else (addresses[0] if addresses else ""),
        # Real hardware with only a link-local address is not on a network,
        # so it is listed but marked, rather than hidden.
        "connected": bool(routable),
    }


def list_interfaces(include_virtual=False):
    """
    Capture interfaces, real adapters only, connected ones first.

    Pass include_virtual=True to get Scapy's unfiltered list back, for
    when an adapter is wrongly filtered out.
    """
    ifaces = get_working_ifaces()

    if not include_virtual:
        ifaces = [iface for iface in ifaces if is_real_adapter(iface)]

    described = [describe_interface(iface) for iface in ifaces]
    described.sort(key=lambda d: (not d["connected"], d["name"].lower()))

    return described


def is_elevated():
    """
    Whether this process can open a raw capture socket.

    None means "cannot tell": on POSIX a plain user can still capture with
    CAP_NET_RAW granted, so an unprivileged uid is not proof of failure
    the way a non-Administrator token is on Windows.
    """
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return None

    try:
        if os.geteuid() == 0:
            return True
    except AttributeError:
        return None

    return None


def has_capture_driver():
    """Whether Scapy found a packet capture driver (Npcap or libpcap)."""
    try:
        from scapy.all import conf

        return bool(getattr(conf, "use_pcap", False))
    except Exception:
        return False


def capture_readiness():
    """
    Whether the server can actually capture, and what to fix if not.

    The browser cannot grant any of this: raw capture is an operating
    system privilege held by this process, so the page reports the state
    and tells the user what to do rather than prompting for a permission
    that does not exist.
    """
    elevated = is_elevated()
    driver = has_capture_driver()

    try:
        adapters = list_interfaces()
    except Exception:
        adapters = []

    problems = []

    if not driver:
        problems.append(
            {
                "code": "no_driver",
                "blocking": True,
                "message": "No packet capture driver found.",
                "fix": "Install Npcap from https://npcap.com/#download, "
                "leaving WinPcap API compatible Mode checked.",
            }
        )

    if elevated is False:
        problems.append(
            {
                "code": "not_elevated",
                "blocking": True,
                "message": "This server is not running with "
                "Administrator privileges.",
                "fix": "Close it and relaunch from an Administrator "
                r"terminal: venv\Scripts\python.exe src\app.py",
            }
        )

    if driver and not adapters:
        problems.append(
            {
                "code": "no_adapters",
                "blocking": True,
                "message": "No network adapters were found.",
                "fix": "Check that a Wi-Fi or Ethernet adapter is enabled.",
            }
        )
    elif adapters and not any(a["connected"] for a in adapters):
        problems.append(
            {
                "code": "no_connection",
                "blocking": False,
                "message": "No adapter has a network connection.",
                "fix": "Connect to a network, or capture anyway to see "
                "local traffic only.",
            }
        )

    return {
        "ready": not any(p["blocking"] for p in problems),
        "elevated": elevated,
        "driver": driver,
        "adapters": len(adapters),
        "problems": problems,
    }


def parse_packet(packet):
    """
    Turn one Scapy packet into a PacketInfo, or None if it has no IP layer.

    Handles IPv4 and IPv6. Anything without an IP layer (ARP, bare layer 2)
    is skipped, since PacketInfo is built around IP addresses.
    """
    if packet.haslayer(IP):
        network = packet[IP]
        unknown_protocol = f"IP proto {network.proto}"
    elif packet.haslayer(IPv6):
        network = packet[IPv6]
        unknown_protocol = f"IPv6 proto {network.nh}"
    else:
        return None

    sport = None
    dport = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = unknown_protocol

    # Prefer the sniffer's own capture time over the time this callback
    # happened to run: it is the accurate one, and it is what a packet read
    # back from a .pcap carries, so durations and rates stay correct there.
    timestamp = getattr(packet, "time", None)
    timestamp = float(timestamp) if timestamp else time.time()

    return PacketInfo(
        id=0,
        timestamp=timestamp,
        src=network.src,
        dst=network.dst,
        protocol=protocol,
        size=len(packet),
        sport=sport,
        dport=dport,
    )


def default_capture_name(now=None):
    """Timestamped .pcap filename, e.g. capture-20260314-091500.pcap."""
    return time.strftime("capture-%Y%m%d-%H%M%S.pcap", now or time.localtime())


def safe_capture_name(filename):
    """
    Reduce a requested filename to a bare, safe .pcap name.

    Strips any directory part and any character outside a conservative
    allowlist, so a name arriving over the API cannot escape the captures
    directory or land somewhere unexpected.
    """
    stem = os.path.basename(str(filename)).strip()
    stem = SAFE_FILENAME.sub("_", stem)
    stem = stem.lstrip(".")

    if not stem:
        return default_capture_name()
    if not stem.lower().endswith(".pcap"):
        stem += ".pcap"

    return stem


def save_pcap(packets, directory, filename=None):
    """
    Write raw packets to a .pcap in directory and return (path, count).

    Raises ValueError when there is nothing to write, so the caller can
    report that as a bad request rather than leaving a 0 packet file behind.
    """
    if not packets:
        raise ValueError("No packets to save")

    name = safe_capture_name(filename) if filename else default_capture_name()

    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    wrpcap(path, packets)

    return path, len(packets)


class CaptureManager:
    def __init__(self, store):
        self.store = store
        self._sniffer = None
        self._lock = threading.Lock()
        self._iface = None

    def is_running(self):
        return self._sniffer is not None and self._sniffer.running

    def current_interface(self):
        return self._iface

    def start(self, iface):
        with self._lock:
            if self.is_running():
                raise RuntimeError("Capture is already running")

            self.store.clear()
            self._iface = iface
            self._sniffer = AsyncSniffer(
                iface=iface, prn=self._on_packet, store=False
            )
            self._sniffer.start()

            # AsyncSniffer resolves the interface and opens the socket in
            # its background thread. A bad interface name fails almost
            # immediately, so a short wait is enough to catch it here
            # instead of reporting a capture as running when it has
            # already died.
            time.sleep(0.3)
            if self._sniffer.exception is not None:
                exc = self._sniffer.exception
                self._sniffer = None
                self._iface = None
                raise RuntimeError(str(exc))

    def stop(self):
        with self._lock:
            if self._sniffer is not None:
                self._sniffer.stop()
                self._sniffer = None

    def _on_packet(self, packet):
        info = parse_packet(packet)
        if info is not None:
            self.store.add(packet, info)
