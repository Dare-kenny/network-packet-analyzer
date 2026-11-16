# Network Packet Analyzer

A mini network forensics tool. Captures live traffic on a chosen interface,
parses packet headers, rolls them up into protocol breakdowns and top
talkers, and flags simple anomalies such as one host contacting an unusually
large number of addresses.

## Setup

1. Python 3.12 and a virtual environment are already set up in `venv/`.
2. Install dependencies (already done for you):
   ```
   venv\Scripts\pip install -r requirements.txt
   ```
3. Install Npcap (required for Scapy to capture packets on Windows):
   download from https://npcap.com/#download and run the installer as
   Administrator. Leave "WinPcap API compatible Mode" checked.
4. Run scripts from an elevated (Administrator) terminal, since raw packet
   capture needs elevated privileges on Windows.

## Project layout

```
src/models.py    PacketInfo, the structured record for one captured packet
src/store.py     thread safe in-memory store of captured packets
src/capture.py   interface listing, the background capture manager, .pcap writing
src/analysis.py  protocol breakdown, top talkers and anomaly detection
src/resolver.py  non-blocking reverse DNS lookups
src/app.py       Flask app and JSON API
templates/       HTML for the web UI
static/          CSS and JS for the web UI
tests/           pytest unit tests for parsing and analysis logic
conftest.py      puts src/ on sys.path so the tests can import it
captures/        saved .pcap files (not committed)
```

## Running the live capture UI

From an Administrator terminal:

```
venv\Scripts\python.exe src\app.py
```

Then open http://127.0.0.1:5000 in a browser, pick an interface, and click
Start. Click any row in the table to expand its full packet detail.

The page polls once a second and shows, above the packet table:

- **Capture totals** — packets, volume, distinct hosts and packets/second.
- **Protocol breakdown** — packets, bytes and share of the capture per
  protocol (TCP, UDP, ICMP, and anything else by IP protocol number).
- **Top talkers** — hosts ranked by total bytes, with sent and received
  broken out and a count of distinct peers.
- **Anomalies** — only appears when something trips a threshold.

**Save .pcap** writes everything currently retained to a timestamped file
under `captures/`, so a capture can be reopened later in Wireshark.

## Capture privileges and the adapter list

Raw packet capture is an **operating system** privilege held by the Python
process: Administrator on Windows, plus the Npcap driver. No browser
permission exists for it, and none can be requested — a web page cannot
grant a server the right to open a raw socket.

So instead of prompting, the page asks `/api/readiness` on load and reports
what is missing before you try to start a capture:

| Problem         | Blocking | Meaning                                  |
|-----------------|----------|------------------------------------------|
| `no_driver`     | yes      | Npcap/libpcap not installed              |
| `not_elevated`  | yes      | not running as Administrator             |
| `no_adapters`   | yes      | no network adapters found                |
| `no_connection` | no       | adapters exist but none has a connection |

A blocking problem disables Start, with the fix shown in the banner, rather
than letting the capture fail with an error that needs decoding.

On POSIX, elevation reports as *unknown* rather than *missing*, since an
unprivileged user can still capture with `CAP_NET_RAW` granted; unknown
never blocks.

The adapter dropdown lists **real adapters only**. Windows reports a pile of
pseudo-interfaces next to the actual NICs — WAN Miniports, Wi-Fi Direct
virtual adapters, loopback — and none of them carry traffic, so offering
them only invites a capture that sits at zero packets forever. The filter
in `is_real_adapter()` decides on hardware facts first (no MAC, or an
all-zero MAC, is not a NIC) with a name check as the backstop. Connected
adapters sort to the top; a real adapter with no connection is listed and
marked rather than hidden. `GET /api/interfaces?all=1` returns Scapy's
unfiltered list if something is wrongly excluded.

## Hostname resolution

Top talkers and anomalies carry a resolved name beside each address, so the
panel reads as a list of hosts rather than a list of numbers.

Lookups never happen on the request path. A PTR query can take seconds, or
hang on an unreachable resolver, and `/api/stats` is polled once a second.
So `HostnameResolver.lookup()` answers from cache immediately and queues
anything it has not seen; the name appears on a later poll. The payload
always carries `host_name`, which is `null` until a name is known — the
shape never changes between polls, so the UI never has to special-case it.

Addresses with no PTR record are cached as misses, so each address is
looked up exactly once. Worker threads are daemons and the queue is
bounded, so a hung resolver costs a stalled lookup rather than a stalled
process or unbounded memory.

Queries go through the **system resolver**, so they stay on the machine's
own DNS and nothing about the capture is sent anywhere else. They do tell
that resolver which addresses you are looking at, so it can be turned off:

```
set PACKET_ANALYZER_DNS=0
venv\Scripts\python.exe src\app.py
```

Reverse DNS lives in `src/resolver.py` and is attached to the payload in
`app.py`, deliberately not in `analysis.py` — that module stays pure
functions over `PacketInfo` with no I/O of any kind.

## Anomaly detection

Two patterns are flagged, both defined in `src/analysis.py`:

| Flag          | Trips when                                                        | Default |
|---------------|-------------------------------------------------------------------|---------|
| `host_fanout` | one source contacts this many distinct destination addresses      | 20      |
| `port_scan`   | one source contacts this many distinct ports on a single target   | 15      |

These are blunt thresholds, not a detection engine: ordinary clients talk to
a handful of servers, so the gap between normal and suspicious is wide enough
that a flat count is a useful first pass. Both thresholds are arguments to
`detect_anomalies()` and `summarize()`, so they can be tuned per call.

## JSON API

| Endpoint                   | Method | Purpose                                      |
|----------------------------|--------|----------------------------------------------|
| `/api/readiness`           | GET    | whether capture is possible, and what to fix |
| `/api/interfaces`          | GET    | real adapters (`?all=1` for the raw list)    |
| `/api/start`               | POST   | start capturing — body `{"iface": "..."}`    |
| `/api/stop`                | POST   | stop capturing                               |
| `/api/status`              | GET    | running flag, interface, packet count        |
| `/api/packets?since=<id>`  | GET    | packet records newer than `<id>`             |
| `/api/packets/<id>`        | GET    | full Scapy detail for one packet             |
| `/api/stats?top=<n>`       | GET    | breakdown, top talkers, anomalies, hostnames |
| `/api/save`                | POST   | write retained packets to `captures/*.pcap`  |

Starting a capture clears the store, so save before restarting if you want
to keep what you captured.

## Running the tests

From the project root (no Administrator needed — the tests never open a live
capture):

```
venv\Scripts\python.exe -m pytest tests\ -q
```

`src/analysis.py` is pure functions over a list of `PacketInfo`, with no
Scapy, Flask or capture state, which is what makes the analysis directly
testable and lets the same functions run over packets read back from a
`.pcap`.

## Known limitations

- **ARP and other non-IP traffic is skipped.** `PacketInfo` is built around
  IP addresses; IPv4 and IPv6 are both parsed, anything below that is not.
- **The store is a 5000 packet ring buffer** and the table shows the most
  recent 500. Longer captures need the `.pcap` saved and reopened elsewhere.
- **`app.py` runs the Flask development server with `debug=True`.** Fine on
  loopback, unsafe to expose — the Werkzeug debugger allows code execution.
- **Capture still needs an Administrator terminal.** The readiness banner
  reports this, but cannot escalate privileges on its own.
- **No `.pcap` import yet.** The analysis functions would work on one
  unchanged; only the loading is missing.

## Scope note

Only capture traffic on networks and machines you own or have permission to
monitor.
