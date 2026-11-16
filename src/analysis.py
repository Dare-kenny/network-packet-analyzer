"""
Milestone 3: traffic analysis.

Rolls a list of PacketInfo records up into protocol breakdowns, top
talkers and simple anomaly flags.

Everything here is a pure function over a list of PacketInfo: no capture
state, no Scapy, no Flask. That keeps the analysis directly unit testable
and means the same functions work on a live capture or on packets read
back from a .pcap file.
"""

from collections import defaultdict

DEFAULT_TOP_N = 10

# A host that contacts this many distinct peers inside one capture is the
# classic shape of a scan or a network sweep. Ordinary clients talk to a
# handful of servers, so the gap between normal and suspicious is wide and
# a blunt threshold works well enough for a first pass.
FANOUT_PEER_THRESHOLD = 20

# The same idea applied to ports: one source touching many distinct ports
# on a single target looks like a port scan.
PORTSCAN_PORT_THRESHOLD = 15


def _pct(part, whole):
    """Percentage of whole, rounded for display. 0.0 when whole is zero."""
    if not whole:
        return 0.0
    return round(part * 100.0 / whole, 1)


def protocol_breakdown(packets):
    """
    Count packets and bytes per protocol.

    Returns a list of dicts ordered by packet count descending, ties broken
    by protocol name so the output is stable for tests and for the UI.
    """
    packet_counts = defaultdict(int)
    byte_counts = defaultdict(int)

    for packet in packets:
        packet_counts[packet.protocol] += 1
        byte_counts[packet.protocol] += packet.size

    total_packets = sum(packet_counts.values())
    total_bytes = sum(byte_counts.values())

    ordered = sorted(packet_counts.items(), key=lambda kv: (-kv[1], kv[0]))

    return [
        {
            "protocol": protocol,
            "packets": count,
            "bytes": byte_counts[protocol],
            "packet_pct": _pct(count, total_packets),
            "byte_pct": _pct(byte_counts[protocol], total_bytes),
        }
        for protocol, count in ordered
    ]


def top_talkers(packets, limit=DEFAULT_TOP_N):
    """
    Rank hosts by total traffic volume, counting both directions.

    A host appears once whether it sent or received, with sent and received
    broken out, so you can tell a busy server from a busy client. Ordered by
    total bytes descending. ``limit=None`` returns every host.
    """
    sent_packets = defaultdict(int)
    sent_bytes = defaultdict(int)
    recv_packets = defaultdict(int)
    recv_bytes = defaultdict(int)
    peers = defaultdict(set)

    for packet in packets:
        sent_packets[packet.src] += 1
        sent_bytes[packet.src] += packet.size
        recv_packets[packet.dst] += 1
        recv_bytes[packet.dst] += packet.size

        # A host is not its own peer, so loopback traffic does not inflate
        # the peer count.
        if packet.src != packet.dst:
            peers[packet.src].add(packet.dst)
            peers[packet.dst].add(packet.src)

    hosts = set(sent_packets) | set(recv_packets)

    rows = []
    for host in hosts:
        rows.append(
            {
                "host": host,
                "packets_sent": sent_packets[host],
                "packets_received": recv_packets[host],
                "bytes_sent": sent_bytes[host],
                "bytes_received": recv_bytes[host],
                "total_packets": sent_packets[host] + recv_packets[host],
                "total_bytes": sent_bytes[host] + recv_bytes[host],
                "peers": len(peers[host]),
            }
        )

    rows.sort(key=lambda r: (-r["total_bytes"], -r["total_packets"], r["host"]))

    return rows[:limit]


def detect_anomalies(
    packets,
    fanout_threshold=FANOUT_PEER_THRESHOLD,
    port_threshold=PORTSCAN_PORT_THRESHOLD,
):
    """
    Flag simple suspicious patterns.

    ``host_fanout``  one source contacted an unusually large number of
                     distinct destination addresses (a sweep).
    ``port_scan``    one source contacted an unusually large number of
                     distinct ports on a single destination.

    A count at or above its threshold is flagged. Returns a list ordered
    with the strongest signal first; an empty list means nothing tripped.
    """
    destinations = defaultdict(set)
    ports_per_pair = defaultdict(set)

    for packet in packets:
        if packet.src != packet.dst:
            destinations[packet.src].add(packet.dst)
        if packet.dport is not None:
            ports_per_pair[(packet.src, packet.dst)].add(packet.dport)

    anomalies = []

    for host, dsts in destinations.items():
        if len(dsts) >= fanout_threshold:
            anomalies.append(
                {
                    "kind": "host_fanout",
                    "host": host,
                    "target": None,
                    "value": len(dsts),
                    "threshold": fanout_threshold,
                    "detail": (
                        f"{host} contacted {len(dsts)} distinct addresses "
                        f"(threshold {fanout_threshold})"
                    ),
                }
            )

    for (src, dst), ports in ports_per_pair.items():
        if len(ports) >= port_threshold:
            anomalies.append(
                {
                    "kind": "port_scan",
                    "host": src,
                    "target": dst,
                    "value": len(ports),
                    "threshold": port_threshold,
                    "detail": (
                        f"{src} contacted {len(ports)} distinct ports on "
                        f"{dst} (threshold {port_threshold})"
                    ),
                }
            )

    anomalies.sort(key=lambda a: (-a["value"], a["kind"], a["host"]))

    return anomalies


def summarize(
    packets,
    top_n=DEFAULT_TOP_N,
    fanout_threshold=FANOUT_PEER_THRESHOLD,
    port_threshold=PORTSCAN_PORT_THRESHOLD,
):
    """
    Build the whole analysis payload the API serves in one pass of inputs.

    Safe on an empty list: every count is zero and every list is empty.
    """
    total_packets = len(packets)
    total_bytes = sum(packet.size for packet in packets)

    timestamps = [packet.timestamp for packet in packets]
    first_seen = min(timestamps) if timestamps else None
    last_seen = max(timestamps) if timestamps else None

    # One packet has no span, so rate is undefined rather than infinite.
    duration = (last_seen - first_seen) if total_packets > 1 else 0.0

    hosts = set()
    for packet in packets:
        hosts.add(packet.src)
        hosts.add(packet.dst)

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "unique_hosts": len(hosts),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration_seconds": round(duration, 3),
        "packets_per_second": (
            round(total_packets / duration, 2) if duration > 0 else 0.0
        ),
        "protocols": protocol_breakdown(packets),
        "top_talkers": top_talkers(packets, top_n),
        "anomalies": detect_anomalies(packets, fanout_threshold, port_threshold),
    }
