"""
Milestone 2: web server.
Serves the live capture page and a small JSON API the frontend polls
for new packets.
"""

import os

from flask import Flask, jsonify, render_template, request

import analysis
from capture import (
    CaptureManager,
    capture_readiness,
    list_interfaces,
    save_pcap,
)
import resolver as dns
from store import PacketStore

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPTURES_DIR = os.path.join(BASE_DIR, "captures")

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
store = PacketStore()
manager = CaptureManager(store)

# Reverse DNS is kept out of analysis.py so that module stays pure: names
# are attached to the payload here, after the numbers are worked out.
resolver = dns.HostnameResolver(enabled=dns.enabled_by_environment())


@app.route("/")
def index():
    return render_template("index.html", interfaces=list_interfaces())


@app.route("/api/interfaces")
def api_interfaces():
    include_virtual = request.args.get("all", type=int) == 1
    return jsonify(list_interfaces(include_virtual=include_virtual))


@app.route("/api/readiness")
def api_readiness():
    """Whether this process can capture, and what to fix if it cannot."""
    return jsonify(capture_readiness())


@app.route("/api/start", methods=["POST"])
def api_start():
    data = request.get_json(silent=True) or {}
    iface = data.get("iface")

    if not iface:
        return jsonify({"error": "iface is required"}), 400

    try:
        manager.start(iface)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 409
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({"status": "started", "iface": iface})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    manager.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/status")
def api_status():
    return jsonify(
        {
            "running": manager.is_running(),
            "iface": manager.current_interface(),
            "count": len(store.all()),
        }
    )


@app.route("/api/packets")
def api_packets():
    since = request.args.get("since", 0, type=int)
    packets = store.get_since(since)
    return jsonify([p.to_dict() for p in packets])


@app.route("/api/packets/<int:packet_id>")
def api_packet_detail(packet_id):
    detail = store.get_detail(packet_id)
    if detail is None:
        return jsonify({"error": "packet not found"}), 404
    return jsonify({"detail": detail})


@app.route("/api/stats")
def api_stats():
    """Protocol breakdown, top talkers and anomaly flags for the capture."""
    top_n = request.args.get("top", analysis.DEFAULT_TOP_N, type=int)
    top_n = max(1, min(top_n, 100))

    stats = analysis.summarize(store.all(), top_n=top_n)

    # Names appear on a later poll if they are not cached yet, so this
    # never delays the response.
    dns.annotate(stats["top_talkers"], resolver)
    dns.annotate(stats["anomalies"], resolver, fields=("host", "target"))
    stats["dns_enabled"] = resolver.enabled

    return jsonify(stats)


@app.route("/api/save", methods=["POST"])
def api_save():
    """Write the retained packets to a .pcap under captures/."""
    data = request.get_json(silent=True) or {}

    try:
        path, count = save_pcap(
            store.raw_packets(), CAPTURES_DIR, data.get("filename")
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except OSError as exc:
        return jsonify({"error": f"Could not write capture file: {exc}"}), 500

    return jsonify(
        {
            "status": "saved",
            "filename": os.path.basename(path),
            "path": path,
            "packets": count,
        }
    )


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
