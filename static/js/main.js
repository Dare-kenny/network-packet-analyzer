const ifaceSelect = document.getElementById("iface-select");
const startBtn = document.getElementById("start-btn");
const stopBtn = document.getElementById("stop-btn");
const saveBtn = document.getElementById("save-btn");
const statusText = document.getElementById("status-text");
const packetBody = document.getElementById("packet-body");

const statPackets = document.getElementById("stat-packets");
const statBytes = document.getElementById("stat-bytes");
const statHosts = document.getElementById("stat-hosts");
const statRate = document.getElementById("stat-rate");

const protocolTable = document.getElementById("protocol-list");
const protocolBody = document.getElementById("protocol-body");
const protocolEmpty = document.getElementById("protocol-empty");

const talkerTable = document.getElementById("talker-list");
const talkerBody = document.getElementById("talker-body");
const talkerEmpty = document.getElementById("talker-empty");

const anomalyPanel = document.getElementById("anomaly-panel");
const anomalyList = document.getElementById("anomaly-list");

const readinessNotice = document.getElementById("readiness-notice");
const readinessTitle = document.getElementById("readiness-title");
const readinessList = document.getElementById("readiness-list");

// Raw packet capture is an operating system privilege held by the server
// process. The browser has no permission to grant for it, so instead of
// prompting for one the page asks the server what it is missing and says
// so before the user tries to start a capture that cannot work.
let captureReady = true;

// The server keeps a 5000 packet ring buffer. The table keeps fewer, so a
// busy interface cannot grow the DOM until the page stalls.
const MAX_TABLE_ROWS = 500;

const ANOMALY_LABELS = {
  host_fanout: "Fan-out",
  port_scan: "Port scan",
};

let lastId = 0;
let pollTimer = null;
let openDetailId = null;

function protoClass(protocol) {
  if (protocol === "TCP") return "proto-TCP";
  if (protocol === "UDP") return "proto-UDP";
  if (protocol === "ICMP") return "proto-ICMP";
  return "proto-other";
}

function protoFillClass(protocol) {
  if (protocol === "TCP") return "proto-fill-TCP";
  if (protocol === "UDP") return "proto-fill-UDP";
  if (protocol === "ICMP") return "proto-fill-ICMP";
  return "proto-fill-other";
}

function formatTime(epochSeconds) {
  const date = new Date(epochSeconds * 1000);
  return date.toLocaleTimeString();
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;

  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }

  const digits = unit === 0 || value >= 100 ? 0 : 1;
  return value.toFixed(digits) + " " + units[unit];
}

function formatCount(value) {
  return Number(value || 0).toLocaleString();
}

function portLabel(packet) {
  if (packet.sport && packet.dport) {
    return packet.sport + " -> " + packet.dport;
  }
  return "-";
}

/* ---------------------------------------------------------------- */
/* Packet table                                                     */
/* ---------------------------------------------------------------- */

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function buildRow(packet) {
  const row = document.createElement("tr");
  row.className = "packet-row";
  row.dataset.id = packet.id;

  row.appendChild(cell(formatTime(packet.timestamp)));
  row.appendChild(cell(packet.src));
  row.appendChild(cell(packet.dst));

  const protoCell = document.createElement("td");
  const tag = document.createElement("span");
  tag.className = "proto-tag " + protoClass(packet.protocol);
  tag.textContent = packet.protocol;
  protoCell.appendChild(tag);
  row.appendChild(protoCell);

  row.appendChild(cell(portLabel(packet)));
  row.appendChild(cell(packet.size + " B"));

  row.addEventListener("click", () => toggleDetail(packet.id, row));

  return row;
}

function trimTable() {
  while (packetBody.rows.length > MAX_TABLE_ROWS) {
    packetBody.deleteRow(packetBody.rows.length - 1);
  }
}

async function toggleDetail(packetId, row) {
  const existing = row.nextElementSibling;
  const isOpenForThisRow = existing && existing.classList.contains("detail-row");

  document.querySelectorAll("tr.detail-row").forEach((el) => el.remove());

  if (isOpenForThisRow && openDetailId === packetId) {
    openDetailId = null;
    return;
  }

  const response = await fetch("/api/packets/" + packetId);
  const data = await response.json();

  const detailRow = document.createElement("tr");
  detailRow.className = "detail-row";
  const td = document.createElement("td");
  td.colSpan = 6;
  const pre = document.createElement("pre");
  pre.textContent = data.detail || data.error || "No detail available";
  td.appendChild(pre);
  detailRow.appendChild(td);

  row.after(detailRow);
  openDetailId = packetId;
}

/* ---------------------------------------------------------------- */
/* Analysis panels                                                  */
/* ---------------------------------------------------------------- */

/**
 * A name, a bar and a figure per row. The bar grows from a single
 * baseline; the figures beside it carry the exact values, so colour is
 * never the only thing identifying a row.
 */
function meterCell(pct, fillClass, tooltip) {
  const td = document.createElement("td");
  td.className = "meter-cell";

  const wrap = document.createElement("div");
  wrap.className = "meter-row";

  const label = document.createElement("span");
  label.className = "meter-pct";
  label.textContent = pct.toFixed(1) + "%";

  const track = document.createElement("div");
  track.className = "meter-track";
  if (tooltip) track.title = tooltip;

  const fill = document.createElement("div");
  fill.className = "meter-fill " + fillClass;
  fill.style.width = Math.max(0, Math.min(100, pct)) + "%";

  track.appendChild(fill);
  wrap.appendChild(label);
  wrap.appendChild(track);
  td.appendChild(wrap);

  return td;
}

function renderProtocols(rows) {
  protocolBody.replaceChildren();

  const hasRows = rows.length > 0;
  protocolTable.hidden = !hasRows;
  protocolEmpty.hidden = hasRows;

  rows.forEach((row) => {
    const tr = document.createElement("tr");

    const name = cell(row.protocol, "name");
    tr.appendChild(name);

    tr.appendChild(
      meterCell(
        row.packet_pct,
        protoFillClass(row.protocol),
        row.protocol +
          ": " +
          formatCount(row.packets) +
          " packets (" +
          row.packet_pct.toFixed(1) +
          "% of packets, " +
          row.byte_pct.toFixed(1) +
          "% of bytes)"
      )
    );

    tr.appendChild(cell(formatCount(row.packets), "num"));
    tr.appendChild(cell(formatBytes(row.bytes), "num"));

    protocolBody.appendChild(tr);
  });
}

function renderTalkers(rows) {
  talkerBody.replaceChildren();

  const hasRows = rows.length > 0;
  talkerTable.hidden = !hasRows;
  talkerEmpty.hidden = hasRows;

  // Bars are proportional to the busiest host, so the ranking is readable
  // even when one host dominates the capture.
  const busiest = rows.reduce((max, r) => Math.max(max, r.total_bytes), 0);

  rows.forEach((row) => {
    const tr = document.createElement("tr");

    // The address stays the primary line: it is always present, and it
    // keeps the row from shifting when a name arrives on a later poll.
    const name = document.createElement("td");
    name.className = "name";

    const address = document.createElement("span");
    address.className = "host-address";
    address.textContent = row.host;
    name.appendChild(address);

    if (row.host_name) {
      const hostname = document.createElement("span");
      hostname.className = "host-name";
      hostname.textContent = row.host_name;
      hostname.title = row.host_name;
      name.appendChild(hostname);
    }

    name.title = row.host_name ? row.host + " (" + row.host_name + ")" : row.host;
    tr.appendChild(name);

    const share = busiest ? (row.total_bytes / busiest) * 100 : 0;
    tr.appendChild(
      meterCell(
        share,
        "",
        row.host +
          ": " +
          formatBytes(row.total_bytes) +
          " over " +
          formatCount(row.total_packets) +
          " packets, " +
          formatCount(row.peers) +
          " peers"
      )
    );

    tr.appendChild(cell(formatBytes(row.bytes_sent), "num"));
    tr.appendChild(cell(formatBytes(row.bytes_received), "num"));
    tr.appendChild(cell(formatCount(row.peers), "num"));

    talkerBody.appendChild(tr);
  });
}

function renderAnomalies(anomalies) {
  anomalyList.replaceChildren();
  anomalyPanel.hidden = anomalies.length === 0;

  anomalies.forEach((anomaly) => {
    const li = document.createElement("li");
    li.className = "anomaly-item";

    // Icon and label travel with the status colour, so the warning never
    // depends on colour alone.
    const icon = document.createElement("span");
    icon.className = "anomaly-icon";
    icon.textContent = "⚠";
    icon.setAttribute("aria-hidden", "true");

    const kind = document.createElement("span");
    kind.className = "anomaly-kind";
    kind.textContent = ANOMALY_LABELS[anomaly.kind] || anomaly.kind;

    const detail = document.createElement("span");
    detail.className = "anomaly-detail";
    detail.textContent = anomaly.detail;

    li.appendChild(icon);
    li.appendChild(kind);
    li.appendChild(detail);

    // Names for the addresses named in the detail line, when known.
    const named = [
      anomaly.host_name ? anomaly.host + " is " + anomaly.host_name : null,
      anomaly.target_name ? anomaly.target + " is " + anomaly.target_name : null,
    ].filter(Boolean);

    if (named.length) {
      const names = document.createElement("span");
      names.className = "anomaly-names";
      names.textContent = named.join(" · ");
      li.appendChild(names);
    }

    anomalyList.appendChild(li);
  });
}

function renderStats(stats) {
  statPackets.textContent = formatCount(stats.total_packets);
  statBytes.textContent = formatBytes(stats.total_bytes);
  statHosts.textContent = formatCount(stats.unique_hosts);
  statRate.textContent = stats.packets_per_second.toFixed(1);

  renderProtocols(stats.protocols);
  renderTalkers(stats.top_talkers);
  renderAnomalies(stats.anomalies);

  saveBtn.disabled = stats.total_packets === 0;
}

/* ---------------------------------------------------------------- */
/* Polling                                                          */
/* ---------------------------------------------------------------- */

function setRunningUI(running, iface) {
  startBtn.disabled = running || !captureReady;
  stopBtn.disabled = !running;
  ifaceSelect.disabled = running;

  if (running && iface) {
    ifaceSelect.value = iface;
  }
}

/**
 * Render what the server says is missing. A blocking problem means a
 * capture cannot succeed, so Start is disabled rather than left to fail
 * with an error the user has to decode.
 */
function renderReadiness(readiness) {
  captureReady = readiness.ready;

  if (readiness.problems.length === 0) {
    readinessNotice.hidden = true;
    return;
  }

  const blocking = readiness.problems.some((p) => p.blocking);

  readinessNotice.hidden = false;
  readinessNotice.classList.toggle("blocking", blocking);
  readinessTitle.textContent = blocking
    ? "This server cannot capture traffic yet"
    : "Capture is available, with a caveat";

  readinessList.replaceChildren();

  readiness.problems.forEach((problem) => {
    const li = document.createElement("li");

    const message = document.createElement("span");
    message.textContent = problem.message;
    li.appendChild(message);

    const fix = document.createElement("span");
    fix.className = "notice-fix";

    // Render a trailing shell command as code, so it can be copied.
    const split = problem.fix.indexOf(": venv");
    if (split === -1) {
      fix.textContent = problem.fix;
    } else {
      fix.appendChild(
        document.createTextNode(problem.fix.slice(0, split + 1) + " ")
      );
      const code = document.createElement("code");
      code.textContent = problem.fix.slice(split + 2);
      fix.appendChild(code);
    }

    li.appendChild(fix);
    readinessList.appendChild(li);
  });
}

async function refresh() {
  try {
    const [packetsResponse, statusResponse, statsResponse] = await Promise.all([
      fetch("/api/packets?since=" + lastId),
      fetch("/api/status"),
      fetch("/api/stats"),
    ]);

    const packets = await packetsResponse.json();
    const status = await statusResponse.json();
    const stats = await statsResponse.json();

    packets.forEach((packet) => {
      packetBody.prepend(buildRow(packet));
      lastId = Math.max(lastId, packet.id);
    });
    trimTable();

    renderStats(stats);

    statusText.textContent = status.running
      ? "Capturing on " + status.iface + " (" + formatCount(status.count) + " packets)"
      : "Stopped (" + formatCount(status.count) + " packets captured)";
  } catch (err) {
    statusText.textContent = "Connection error";
  }
}

function startPolling() {
  if (pollTimer === null) {
    pollTimer = setInterval(refresh, 1000);
  }
}

function stopPolling() {
  if (pollTimer !== null) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

/* ---------------------------------------------------------------- */
/* Controls                                                         */
/* ---------------------------------------------------------------- */

startBtn.addEventListener("click", async () => {
  const response = await fetch("/api/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ iface: ifaceSelect.value }),
  });

  if (!response.ok) {
    const data = await response.json();
    statusText.textContent = "Error: " + data.error;
    return;
  }

  // The server clears its store on start, so the view starts clean too.
  lastId = 0;
  packetBody.replaceChildren();
  setRunningUI(true);
  startPolling();
  refresh();
});

stopBtn.addEventListener("click", async () => {
  await fetch("/api/stop", { method: "POST" });

  setRunningUI(false);
  stopPolling();
  refresh();
});

saveBtn.addEventListener("click", async () => {
  saveBtn.disabled = true;

  try {
    const response = await fetch("/api/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const data = await response.json();

    statusText.textContent = response.ok
      ? "Saved " + formatCount(data.packets) + " packets to " + data.filename
      : "Save failed: " + data.error;
  } catch (err) {
    statusText.textContent = "Save failed";
  }

  saveBtn.disabled = false;
});

/* On load, pick up whatever the server is already doing, so a reload
   during a capture shows the live view instead of an empty page. */
(async function init() {
  try {
    const [readiness, status] = await Promise.all([
      fetch("/api/readiness").then((r) => r.json()),
      fetch("/api/status").then((r) => r.json()),
    ]);

    renderReadiness(readiness);
    setRunningUI(status.running, status.iface);

    if (status.running) {
      startPolling();
    }
  } catch (err) {
    /* refresh() reports the connection error */
  }
  refresh();
})();
