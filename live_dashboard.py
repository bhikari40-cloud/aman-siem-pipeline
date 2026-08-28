"""Continuous live-stream pipeline visualizer: real ClickHouse data -> here -> Annie's SIEMs.

Pulls a bounded slice of real DNS request history from the ITSEC ClickHouse
Data API (intellibron_aman_silver.dns_request_parsed), runs it through the
same normalize_to_ocsf -> should_deliver_event -> per-target translator.py
formatter path orchestrator.py's production code uses, then POSTs it for
real. Delivery here is not a simulation of the pipeline; it's the pipeline's
own code, driven live.

This replaced an earlier version that tailed a synthetic stream generated on
a separate Mac (Hinata) over SSH. Real data now, but proof-of-connectivity
scope only -- see ingest.iter_api_stream's docstring for what's deliberately
NOT solved here (genuine real-time freshness, continuous pagination past one
page): both are backend-side/scale concerns outside this pipeline's call.

Serves a same-origin local dashboard so the browser polls this server instead
of the SIEM backends directly: Annie's REST APIs send no CORS headers, and a
hosted/sandboxed page couldn't reach Annie's private IP anyway. The page
renders as a pipeline diagram (source -> engine -> fan-out to SIEMs) with an
animated packet per delivery, not a scrolling log -- a log of individual
domains is unreadable at a glance; a diagram of what's flowing where is not.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import requests
import urllib3

# Wazuh's bundled indexer uses a self-signed cert (verify_ssl: false in
# tenant_configs.json for that tenant) -- expected and deliberate, silence
# the per-request warning noise it'd otherwise spam into the log.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from config_store import load_tenant_configs
from ingest import iter_api_stream, normalize_to_ocsf
from orchestrator import send_syslog_udp
from translator import NDJSON_BULK_SIEMS, format_batch_for_siem, format_for_siem, format_for_syslog

# Sourced from ~/.config/clickhouse-api.env before launch (project convention
# for backend secrets -- see CLAUDE.md), not committed anywhere.
CLICKHOUSE_API_URL = os.environ.get("CLICKHOUSE_API_URL", "")
CLICKHOUSE_API_KEY = os.environ.get("CLICKHOUSE_API_KEY", "")

BACKENDS = {
    "test-annie-elk": "Elastic",
    "test-annie-graylog": "Graylog",
    "test-annie-wazuh": "Wazuh",
    # Separate tenant/transport from test-annie-wazuh above: that one is the
    # bulk-API path straight into the indexer (bypasses wazuh-manager's
    # decoder/rule engine entirely, per ARCHITECTURE.md 4.2 -- data lands in
    # aman-live-test but is never a native Wazuh alert). This one is syslog
    # into wazuh-manager, decoded by the custom aman-pipeline decoder and
    # scored by rules 100050-100054 -- the only path that actually populates
    # wazuh-alerts-* / Wazuh's own Alerts UI. deliver_one already dispatches
    # on webhook_url's scheme (syslog vs HTTP), so no other code change is
    # needed for delivery -- this key is the only thing that was missing.
    # Note: the SVG diagram below has no node for this tenant id, so it
    # won't get its own animated packet/box there (render() guards every
    # DOM lookup, so this doesn't break the other three) -- only status.json
    # and the counters reflect it. Add a diagram node if that's wanted too.
    "test-annie-wazuh-syslog": "Wazuh (syslog)",
}
PORT = 8901

STATE_LOCK = threading.Lock()
STATE = {
    "started_at": None,
    "generated": 0,
    "dropped_unblocked": 0,
    "last_event": None,
    "last_raw_event": None,
    "backends": {
        tenant_id: {
            "label": label,
            "delivered": 0,
            "failed": 0,
            "last_ok": None,
            "last_payload": None,
        }
        for tenant_id, label in BACKENDS.items()
    },
}


def record_event(tenant_id: str, alert: dict, ok: bool, error: str | None, payload: str | None = None) -> None:
    with STATE_LOCK:
        backend = STATE["backends"][tenant_id]
        backend["delivered" if ok else "failed"] += 1
        backend["last_ok"] = ok
        if not ok:
            backend["last_error"] = error
        if payload is not None:
            backend["last_payload"] = payload


def deliver_one(tenant_id: str, alert: dict, tenant_configs: dict) -> None:
    """Deliver one alert using the pipeline's own translator formatting.

    Mirrors orchestrator.deliver_batch's dispatch: scheme decides transport
    (syslog -> raw UDP, everything else -> HTTP), and within HTTP,
    elastic/wazuh's `_bulk` endpoint needs the NDJSON bulk body even for a
    single alert (a bare JSON object is a different, rejected wire shape
    there) -- everything else uses its normal single-alert envelope.
    """
    config = tenant_configs[tenant_id]
    siem_type = config["siem_type"]
    verify = config.get("verify_ssl", True)
    is_syslog = urlparse(config["webhook_url"]).scheme == "syslog"

    try:
        if is_syslog:
            payload = format_for_syslog(alert, siem_type)
            send_syslog_udp(config["webhook_url"], payload)
        elif siem_type in NDJSON_BULK_SIEMS:
            headers, _ = format_for_siem(alert, siem_type, config["auth_token"])
            _, body = format_batch_for_siem([alert], siem_type, config["auth_token"])
            headers = {**headers, "Content-Type": "application/x-ndjson"}
            payload = body
            resp = requests.post(
                config["webhook_url"], headers=headers, data=body.encode("utf-8"),
                timeout=10, verify=verify,
            )
            resp.raise_for_status()
            # A 2xx status only means the HTTP request was well-formed --
            # the Bulk API can still reject the document itself (e.g. a
            # field-type mapping conflict), visible only in the response
            # body. Hit this for real with a "time" field type conflict
            # that returned HTTP 200 while silently dropping the document.
            bulk_result = resp.json()
            if bulk_result.get("errors"):
                item_error = next(
                    (a.get("error") for item in bulk_result.get("items", []) for a in item.values() if a.get("error")),
                    "unspecified bulk item error",
                )
                raise RuntimeError(f"Bulk item error: {item_error}")
        else:
            headers, payload_dict = format_for_siem(alert, siem_type, config["auth_token"])
            headers = {**headers, "Content-Type": "application/json"}
            payload = json.dumps(payload_dict)
            resp = requests.post(
                config["webhook_url"], headers=headers, json=payload_dict,
                timeout=10, verify=verify,
            )
            resp.raise_for_status()
    except Exception as exc:
        record_event(tenant_id, alert, False, f"{exc.__class__.__name__}: {exc}")
        return

    record_event(tenant_id, alert, True, None, payload)


def process_event(raw_doc: dict, tenant_configs: dict) -> None:
    """Normalize one raw ClickHouse row and, if it's alert-worthy, deliver it.

    Unlike the old Hinata source (which shipped its own already-OCSF events,
    requiring normalize_to_ocsf to be skipped), rows from iter_api_stream are
    raw ECS-shaped docs -- this goes through the standard normalize step,
    the same path orchestrator.run_pipeline uses for the real CSV/API source.
    """
    alert = normalize_to_ocsf(raw_doc)

    with STATE_LOCK:
        STATE["generated"] += 1

    if alert.get("disposition") != "Blocked":
        with STATE_LOCK:
            STATE["dropped_unblocked"] += 1
        return

    with STATE_LOCK:
        STATE["last_event"] = {
            "at": datetime.now(UTC).strftime("%H:%M:%S"),
            "domain": alert.get("query", {}).get("hostname", "?"),
            "severity": alert.get("severity", "?"),
        }
        STATE["last_raw_event"] = json.dumps(raw_doc)

    for tenant_id in BACKENDS:
        adapted = dict(alert)
        adapted["tenant"] = {"uid": tenant_id}
        deliver_one(tenant_id, adapted, tenant_configs)


def stream_loop() -> None:
    tenant_configs = load_tenant_configs()
    with STATE_LOCK:
        STATE["started_at"] = datetime.now(UTC).strftime("%H:%M:%S")

    if not CLICKHOUSE_API_URL or not CLICKHOUSE_API_KEY:
        print(
            "CLICKHOUSE_API_URL / CLICKHOUSE_API_KEY not set -- source "
            "~/.config/clickhouse-api.env before launching. Stream will not "
            "start."
        )
        return

    # One bounded, slow-replayed pull of real historical data, not a
    # continuous tail -- see this file's module docstring and
    # ingest.iter_api_stream for why (freshness/query-performance-at-scale/
    # pagination are all backend-side concerns, deferred, not solved here).
    # limit stays small (10) deliberately: this endpoint has a real,
    # reproducible performance cliff above ~5-10 rows per query (see
    # iter_api_stream's docstring) -- this is proving connectivity works,
    # not stress-testing the data source.
    # _clickhouse_query already retries transient failures a couple of times;
    # this outer loop is the next layer up -- if the backend is down for
    # longer than that retry budget, iter_api_stream raises and this thread
    # would otherwise die silently (dashboard just stops updating with no
    # visible cause). Restart the stream after a backoff instead. Re-running
    # iter_api_stream re-queries max(dt) and replays from the top of that
    # day's slice, so a flaky backend means repeated/duplicate alerts rather
    # than gaps -- acceptable for proving connectivity, not a claim of
    # exactly-once delivery.
    while True:
        try:
            for raw_doc in iter_api_stream(CLICKHOUSE_API_URL, CLICKHOUSE_API_KEY, limit=10, rate=1.0):
                process_event(raw_doc, tenant_configs)
        except Exception as exc:
            print(f"ClickHouse stream interrupted ({exc!r}) -- backend-side issue, retrying in 10s.")
            time.sleep(10)


DASHBOARD_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Aman Pipeline -- Live Diagram</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 28px;
    background: #0b0f14; color: #d6e2e8;
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
  }
  header { display: flex; align-items: baseline; gap: 12px; margin-bottom: 4px; }
  h1 { font-size: 17px; margin: 0; font-weight: 600; letter-spacing: 0.2px; }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: #3ddc84; animation: pulse 1.2s infinite; }
  .dot.down { background: #ff5d5d; animation: none; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.25; } }
  .meta { color: #5c6b75; font-size: 12px; margin-bottom: 6px; }
  .totals { color: #7a8a94; font-size: 12px; margin-bottom: 18px; }
  .totals b { color: #d6e2e8; }
  .last-event {
    height: 18px; font-size: 12px; color: #9fb3bd; margin-bottom: 14px;
    opacity: 0; transition: opacity 0.3s;
  }
  .last-event.show { opacity: 1; }
  .last-event .arrow { color: #4a5a64; margin: 0 6px; }
  svg { width: 100%; height: auto; display: block; overflow: visible; }
  .edge { fill: none; stroke: #22303c; stroke-width: 2; }
  .node-box {
    fill: #121821; stroke: #1f2a35; stroke-width: 1.5; rx: 10;
  }
  .node-box.active { stroke: #2a4a3a; }
  .node-title { fill: #9fb3bd; font-size: 13px; font-family: inherit; font-weight: 600; }
  .node-sub { fill: #5c6b75; font-size: 10px; font-family: inherit; }
  .node-count-ok { fill: #3ddc84; font-size: 22px; font-family: inherit; font-weight: 700; }
  .node-count-fail { fill: #ff5d5d; font-size: 12px; font-family: inherit; }
  .accent { stroke-width: 4; stroke-linecap: round; }
  .packet { filter: drop-shadow(0 0 3px currentColor); }
  .format-badge-bg { stroke-width: 1; }
  .format-badge-text { font-size: 9px; font-family: inherit; font-weight: 700; letter-spacing: 0.3px; }
  .size-text { font-size: 10px; fill: #5c6b75; font-family: inherit; }
  .size-delta.shrink { fill: #3ddc84; }
  .size-delta.grow { fill: #ffb454; }

  /* Payload cards -- real HTML below the diagram, not SVG text. SVG <text>
     can't wrap on its own; cramming a truncated payload into a tiny SVG box
     forces either an unreadable one-liner or manual line-chunking that still
     doesn't read well. A normal block element wraps naturally and can just
     be sized to be legible. */
  .payload-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 14px;
    margin-top: 28px;
  }
  .payload-card {
    background: rgba(255, 255, 255, 0.03);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 14px 16px;
    transition: border-color 0.3s;
  }
  .payload-card.flash { border-color: rgba(255, 255, 255, 0.28); }
  .payload-card-head {
    display: flex; align-items: center; gap: 8px; margin-bottom: 10px;
  }
  .payload-card-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .payload-card-title { font-size: 12px; font-weight: 600; color: #d6e2e8; }
  .payload-card-size { margin-left: auto; font-size: 11px; color: #5c6b75; }
  .payload-card-size.shrink { color: #3ddc84; }
  .payload-card-size.grow { color: #ffb454; }
  .payload-card-body {
    margin: 0;
    font-family: inherit;
    font-size: 11.5px;
    line-height: 1.5;
    color: #9fb3bd;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 6.5em;
    overflow: hidden;
  }
</style>
</head>
<body>
<header>
  <div class="dot" id="livedot"></div>
  <h1>Aman Pipeline</h1>
</header>
<div class="meta" id="meta">connecting...</div>
<div class="totals" id="totals"></div>
<div class="last-event" id="lastEvent"></div>

<svg id="diagram" viewBox="0 0 920 480" preserveAspectRatio="xMidYMid meet">
  <!-- edges, drawn under nodes -->
  <path id="edge-hinata-engine" class="edge" d="M 180 245 L 280 245" />
  <path id="edge-engine-elk" class="edge" d="M 490 220 C 555 220, 555 105, 620 105" />
  <path id="edge-engine-graylog" class="edge" d="M 490 245 L 620 245" />
  <path id="edge-engine-wazuh" class="edge" d="M 490 270 C 555 270, 555 385, 620 385" />

  <!-- Hinata (source) -->
  <g id="node-hinata">
    <rect class="node-box" x="20" y="195" width="160" height="100" rx="10"/>
    <line class="accent" x1="20" y1="203" x2="20" y2="287" stroke="#4a7dff"/>
    <text class="node-title" x="38" y="222">ClickHouse</text>
    <text class="node-sub" x="38" y="242">real data (source)</text>
    <text class="node-sub" x="38" y="258" id="hinata-rate">-- ev/s</text>
  </g>

  <!-- Translation Engine (here / Air) -->
  <g id="node-engine">
    <rect class="node-box" id="engine-box" x="280" y="190" width="210" height="110" rx="10"/>
    <line class="accent" x1="280" y1="198" x2="280" y2="282" stroke="#b98bff"/>
    <text class="node-title" x="300" y="217">Translation Engine</text>
    <text class="node-sub" x="300" y="237">this machine</text>
    <text class="node-sub" x="300" y="253" id="engine-seen">0 seen</text>
    <text class="node-sub" x="300" y="269" id="engine-dropped">0 dropped (noise)</text>
  </g>

  <!-- Elastic -->
  <g id="node-test-annie-elk">
    <rect class="node-box" x="620" y="45" width="270" height="120" rx="10"/>
    <line class="accent" x1="620" y1="53" x2="620" y2="157" stroke="#f4bd42"/>
    <text class="node-title" x="638" y="72">Elastic</text>
    <text class="node-count-ok" x="638" y="102">0</text>
    <text class="node-count-fail" x="638" y="122">0 failed</text>
    <rect class="format-badge-bg" x="638" y="137" width="100" height="17" rx="8" fill="rgba(244,189,66,0.1)" stroke="rgba(244,189,66,0.4)"/>
    <text class="format-badge-text" x="646" y="149" fill="#f4bd42">NDJSON BULK</text>
    <text class="size-text" id="size-test-annie-elk" x="746" y="149">--</text>
  </g>

  <!-- Graylog -->
  <g id="node-test-annie-graylog">
    <rect class="node-box" x="620" y="185" width="270" height="120" rx="10"/>
    <line class="accent" x1="620" y1="193" x2="620" y2="297" stroke="#ff6b5e"/>
    <text class="node-title" x="638" y="212">Graylog</text>
    <text class="node-count-ok" x="638" y="242">0</text>
    <text class="node-count-fail" x="638" y="262">0 failed</text>
    <rect class="format-badge-bg" x="638" y="277" width="100" height="17" rx="8" fill="rgba(255,107,94,0.1)" stroke="rgba(255,107,94,0.4)"/>
    <text class="format-badge-text" x="646" y="289" fill="#ff6b5e">SYSLOG K=V</text>
    <text class="size-text" id="size-test-annie-graylog" x="746" y="289">--</text>
  </g>

  <!-- Wazuh -->
  <g id="node-test-annie-wazuh">
    <rect class="node-box" x="620" y="325" width="270" height="120" rx="10"/>
    <line class="accent" x1="620" y1="333" x2="620" y2="437" stroke="#3ec9c9"/>
    <text class="node-title" x="638" y="352">Wazuh</text>
    <text class="node-count-ok" x="638" y="382">0</text>
    <text class="node-count-fail" x="638" y="402">0 failed</text>
    <rect class="format-badge-bg" x="638" y="417" width="100" height="17" rx="8" fill="rgba(62,201,201,0.1)" stroke="rgba(62,201,201,0.4)"/>
    <text class="format-badge-text" x="646" y="429" fill="#3ec9c9">SYSLOG JSON</text>
    <text class="size-text" id="size-test-annie-wazuh" x="746" y="429">--</text>
  </g>
</svg>

<div class="payload-grid">
  <div class="payload-card" id="card-payload-raw">
    <div class="payload-card-head">
      <span class="payload-card-dot" style="background:#4a7dff"></span>
      <span class="payload-card-title">ClickHouse &middot; raw event</span>
      <span class="payload-card-size" id="raw-size">--</span>
    </div>
    <pre class="payload-card-body" id="payload-raw">waiting for the first event&hellip;</pre>
  </div>
  <div class="payload-card" id="card-payload-test-annie-elk">
    <div class="payload-card-head">
      <span class="payload-card-dot" style="background:#f4bd42"></span>
      <span class="payload-card-title">Elastic &middot; NDJSON bulk</span>
      <span class="payload-card-size" id="size-card-test-annie-elk">--</span>
    </div>
    <pre class="payload-card-body" id="payload-test-annie-elk">waiting for the first delivery&hellip;</pre>
  </div>
  <div class="payload-card" id="card-payload-test-annie-graylog">
    <div class="payload-card-head">
      <span class="payload-card-dot" style="background:#ff6b5e"></span>
      <span class="payload-card-title">Graylog &middot; syslog key=value</span>
      <span class="payload-card-size" id="size-card-test-annie-graylog">--</span>
    </div>
    <pre class="payload-card-body" id="payload-test-annie-graylog">waiting for the first delivery&hellip;</pre>
  </div>
  <div class="payload-card" id="card-payload-test-annie-wazuh">
    <div class="payload-card-head">
      <span class="payload-card-dot" style="background:#3ec9c9"></span>
      <span class="payload-card-title">Wazuh &middot; syslog JSON</span>
      <span class="payload-card-size" id="size-card-test-annie-wazuh">--</span>
    </div>
    <pre class="payload-card-body" id="payload-test-annie-wazuh">waiting for the first delivery&hellip;</pre>
  </div>
</div>

<script>
const EDGE_IDS = {
  hinata: 'edge-hinata-engine',
  'test-annie-elk': 'edge-engine-elk',
  'test-annie-graylog': 'edge-engine-graylog',
  'test-annie-wazuh': 'edge-engine-wazuh',
};

let prev = null;
let lastRateTick = { t: Date.now(), generated: 0 };

function fireDot(edgeId, color) {
  const path = document.getElementById(edgeId);
  if (!path) return;
  const svgns = 'http://www.w3.org/2000/svg';
  const dot = document.createElementNS(svgns, 'circle');
  dot.setAttribute('r', 5);
  dot.setAttribute('fill', color);
  dot.classList.add('packet');
  const anim = document.createElementNS(svgns, 'animateMotion');
  anim.setAttribute('dur', '0.9s');
  anim.setAttribute('fill', 'freeze');
  anim.setAttribute('path', path.getAttribute('d'));
  dot.appendChild(anim);
  document.getElementById('diagram').appendChild(dot);
  setTimeout(() => dot.remove(), 950);
}

function flashNode(nodeGroupId) {
  const box = document.querySelector(`#${nodeGroupId} .node-box, #${nodeGroupId} rect`);
  if (!box) return;
  box.classList.add('active');
  setTimeout(() => box.classList.remove('active'), 500);
}

const PAYLOAD_PREVIEW_CHARS = 320;
const svgns = 'http://www.w3.org/2000/svg';

function byteSize(str) {
  return new Blob([str || '']).size;
}

function formatBytes(n) {
  return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`;
}

// Real HTML wraps on its own -- no manual line-chunking needed here, unlike
// the SVG diagram nodes. Still truncated (these are live full OCSF/NDJSON
// payloads, some run to 800+ bytes) but at a length that reads as an actual
// legible snippet instead of a single unreadable line.
function setPayloadCard(elementId, str) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = str ? String(str) : '--';
  const isNew = el.textContent !== text;
  el.textContent = text.length > PAYLOAD_PREVIEW_CHARS
    ? text.slice(0, PAYLOAD_PREVIEW_CHARS) + ' …'
    : text;
  if (isNew) {
    const card = el.closest('.payload-card');
    if (card) {
      card.classList.add('flash');
      setTimeout(() => card.classList.remove('flash'), 500);
    }
  }
}

async function poll() {
  try {
    const res = await fetch('/status.json', {cache: 'no-store'});
    const s = await res.json();
    render(s);
    document.getElementById('livedot').classList.remove('down');
  } catch (e) {
    document.getElementById('livedot').classList.add('down');
    document.getElementById('meta').textContent = 'disconnected from local dashboard server';
  }
}

function render(s) {
  document.getElementById('meta').textContent =
    `started ${s.started_at || '--'} local time · polling every 1.5s`;
  document.getElementById('totals').innerHTML =
    `<b>${s.generated}</b> events seen · <b>${s.dropped_unblocked}</b> dropped as benign noise`;
  document.getElementById('engine-seen').textContent = `${s.generated} seen`;
  document.getElementById('engine-dropped').textContent = `${s.dropped_unblocked} dropped (noise)`;

  const now = Date.now();
  const dt = (now - lastRateTick.t) / 1000;
  if (dt > 2) {
    const rate = (s.generated - lastRateTick.generated) / dt;
    document.getElementById('hinata-rate').textContent = `${rate.toFixed(1)} ev/s`;
    lastRateTick = { t: now, generated: s.generated };
  }

  if (s.last_event) {
    const el = document.getElementById('lastEvent');
    el.innerHTML = `${s.last_event.at} <span class="arrow">→</span> blocked: <b>${s.last_event.domain}</b> (${s.last_event.severity})`;
    el.classList.add('show');
  }

  // Payload cards (below the diagram) get the full, readable, wrapped
  // snippet; the compact size badge inside each SVG node gets the same
  // number in miniature for an at-a-glance read. Alongside each size, show
  // how it changed relative to the raw event -- that comparison is the
  // point: the same event, visibly a different shape and size per target.
  function sizeLabel(payloadBytes, rawBytes) {
    let label = formatBytes(payloadBytes);
    let delta = null;
    if (rawBytes) {
      const deltaPct = Math.round((1 - payloadBytes / rawBytes) * 100);
      if (deltaPct > 0) { label += `  −${deltaPct}%`; delta = 'shrink'; }
      else if (deltaPct < 0) { label += `  +${-deltaPct}%`; delta = 'grow'; }
    }
    return { label, delta };
  }

  let rawBytes = null;
  if (s.last_raw_event) {
    rawBytes = byteSize(s.last_raw_event);
    document.getElementById('raw-size').textContent = formatBytes(rawBytes);
    setPayloadCard('payload-raw', s.last_raw_event);
  }
  for (const [tid, b] of Object.entries(s.backends)) {
    if (b.last_payload) {
      setPayloadCard(`payload-${tid}`, b.last_payload);
      const { label, delta } = sizeLabel(byteSize(b.last_payload), rawBytes);

      const badgeEl = document.getElementById(`size-${tid}`);
      if (badgeEl) {
        badgeEl.classList.remove('size-delta', 'shrink', 'grow');
        if (delta) badgeEl.classList.add('size-delta', delta);
        badgeEl.textContent = label;
      }
      const cardSizeEl = document.getElementById(`size-card-${tid}`);
      if (cardSizeEl) {
        cardSizeEl.classList.remove('shrink', 'grow');
        if (delta) cardSizeEl.classList.add(delta);
        cardSizeEl.textContent = label;
      }
    }
  }

  if (prev && s.generated !== prev.generated) {
    fireDot(EDGE_IDS.hinata, '#4a7dff');
    flashNode('node-engine');
  }

  for (const [tid, b] of Object.entries(s.backends)) {
    const g = document.getElementById(`node-${tid}`);
    if (g) {
      g.querySelector('.node-count-ok').textContent = b.delivered;
      g.querySelector('.node-count-fail').textContent = `${b.failed} failed`;
    }
    if (prev && prev.backends[tid]) {
      const prevB = prev.backends[tid];
      if (b.delivered !== prevB.delivered) {
        fireDot(EDGE_IDS[tid], '#3ddc84');
        flashNode(`node-${tid}`);
      } else if (b.failed !== prevB.failed) {
        fireDot(EDGE_IDS[tid], '#ff5d5d');
      }
    }
  }

  prev = s;
}

poll();
setInterval(poll, 1500);
</script>

<style>
  #evolution {
    --carry: #4a7dff;       /* carried over unchanged -- same blue as the source node */
    --derive: #f4bd42;      /* computed by us -- same amber as the Elastic node */
    --missing: #ff5d5d;     /* not available -- same red as a failed delivery */
    --evo-accent: #b98bff;  /* interactive chrome -- same purple as the Engine node */
    --panel: rgba(255, 255, 255, 0.03);
    --panel-2: rgba(255, 255, 255, 0.06);
    --panel-border: rgba(255, 255, 255, 0.08);
    --ink: #d6e2e8;
    --ink-soft: #9fb3bd;
    --ink-faint: #5c6b75;
    margin-top: 44px;
    padding-top: 28px;
    border-top: 1px solid #1f2a35;
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
  }
  #evolution .wrap { max-width: 62rem; margin: 0 auto; }
  #evolution header { border-bottom: 1px solid var(--panel-border); padding-bottom: 1.25rem; margin-bottom: 1.5rem; display: block; }
  #evolution .kicker { font-size: 0.67rem; letter-spacing: 0.14em;
    text-transform: uppercase; color: var(--ink-faint); margin: 0; }
  #evolution h1 { font-size: clamp(1.4rem, 3.4vw, 1.9rem); line-height: 1.2; font-weight: 600;
    letter-spacing: -0.01em; margin: 0.5rem 0 0; color: var(--ink); }
  #evolution .sub { color: var(--ink-soft); margin: 0.55rem 0 0; max-width: 44rem; font-size: 0.92rem; }

  #evolution .bar { display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem;
    margin-top: 1.35rem; }
  #evolution button { font-family: inherit; font-size: 0.8rem; font-weight: 600;
    color: var(--ink-soft); background: var(--panel); border: 1px solid var(--panel-border);
    border-radius: 6px; padding: 0.4rem 0.85rem; cursor: pointer;
    backdrop-filter: blur(12px);
    transition: background 0.15s, border-color 0.15s, color 0.15s; }
  #evolution button:hover { background: var(--panel-2); border-color: var(--ink-faint); color: var(--ink); }
  #evolution button:focus-visible { outline: 2px solid var(--evo-accent); outline-offset: 2px; }
  #evolution button[disabled] { opacity: 0.4; cursor: default; }
  #evolution .dots { display: flex; gap: 0.4rem; margin-left: auto; }
  #evolution .evo-dot { width: 1.9rem; height: 0.3rem; border-radius: 2px; background: var(--panel-border);
    border: none; padding: 0; cursor: pointer; transition: background 0.25s; }
  #evolution .evo-dot.on { background: var(--evo-accent); }
  #evolution .evo-dot:focus-visible { outline: 2px solid var(--evo-accent); outline-offset: 3px; }

  #evolution .stage { display: none; }
  #evolution .stage.live { display: block; }
  #evolution .stage-head { display: flex; align-items: baseline; gap: 0.7rem; margin-bottom: 0.3rem; }
  #evolution .stage-n { font-size: 0.72rem; color: var(--evo-accent); letter-spacing: 0.1em; }
  #evolution .stage-t { font-size: 1.12rem; font-weight: 650; letter-spacing: -0.01em; margin: 0; color: var(--ink); }
  #evolution .stage-d { color: var(--ink-soft); margin: 0 0 1.15rem; font-size: 0.9rem; max-width: 46rem; }

  #evolution .grid { display: grid; gap: 0.32rem; }
  #evolution .row { display: grid; grid-template-columns: minmax(0,1.05fr) 1.15rem minmax(0,1.35fr);
    align-items: center; gap: 0.5rem; background: var(--panel);
    backdrop-filter: blur(12px);
    border: 1px solid var(--panel-border); border-radius: 8px; padding: 0.44rem 0.75rem;
    opacity: 0; transform: translateY(5px);
    animation: evo-rise 0.42s cubic-bezier(.22,.7,.3,1) forwards; }
  @keyframes evo-rise { to { opacity: 1; transform: none; } }
  #evolution .k { font-size: 0.75rem; color: var(--ink-soft);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  #evolution .v { font-size: 0.75rem; color: var(--ink);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  #evolution .arrow { color: var(--ink-faint); font-size: 0.8rem; text-align: center; }
  #evolution .row.carry  { border-left: 3px solid var(--carry); }
  #evolution .row.derive { border-left: 3px solid var(--derive); }
  #evolution .row.missing{ border-left: 3px solid var(--missing); }
  #evolution .row.missing .v { color: var(--missing); }
  #evolution .tagline { font-size: 0.66rem; color: var(--ink-faint);
    grid-column: 1 / -1; padding-top: 0.15rem; }

  #evolution .legend { display: flex; flex-wrap: wrap; gap: 0.5rem 1.1rem; margin: 1rem 0 0;
    font-size: 0.73rem; color: var(--ink-soft); }
  #evolution .legend i { display: inline-block; width: 0.62rem; height: 0.62rem; border-radius: 2px;
    margin-right: 0.35rem; vertical-align: -0.03rem; }

  #evolution .funnel { display: flex; flex-direction: column; gap: 0.85rem; margin-top: 0.4rem; }
  #evolution .fl { display: grid; grid-template-columns: 9rem 1fr 7rem; align-items: center; gap: 0.8rem; }
  #evolution .fl .lbl { font-size: 0.8rem; color: var(--ink-soft); }
  #evolution .fl .track { height: 1.7rem; background: var(--panel-2); border: 1px solid var(--panel-border);
    border-radius: 4px; overflow: hidden; }
  /* display:block is load-bearing -- .track is not a flex/grid container, so a
     span child stays inline and silently ignores width and height. */
  #evolution .fl .fill { display: block; height: 100%; width: 0; border-radius: 4px;
    transition: width 0.95s cubic-bezier(.2,.75,.25,1); }
  #evolution .fl .num { font-size: 0.82rem; color: var(--ink); text-align: right;
    font-variant-numeric: tabular-nums; white-space: nowrap; }

  #evolution .calc { margin-top: 1.1rem; border: 1px solid var(--panel-border); border-radius: 8px;
    background: var(--panel); backdrop-filter: blur(12px); overflow: hidden; }
  #evolution .calc .step { display: grid; grid-template-columns: 1fr auto; gap: 0.5rem 1rem;
    align-items: baseline; padding: 0.52rem 0.95rem;
    border-bottom: 1px solid var(--panel-border); }
  #evolution .calc .step:last-child { border-bottom: none; }
  #evolution .calc .step.total { background: rgba(255, 93, 93, 0.08); }
  #evolution .calc .op { font-size: 0.85rem; color: var(--ink-soft); }
  #evolution .calc .res { font-size: 0.85rem; color: var(--ink); white-space: nowrap;
    font-variant-numeric: tabular-nums; }
  #evolution .calc .step.total .res { color: var(--missing); font-weight: 700; font-size: 0.95rem; }

  #evolution .two { display: grid; grid-template-columns: 1fr 1fr; gap: 0.6rem; margin-top: 1.1rem; }
  #evolution .two > div { border: 1px solid var(--panel-border); border-radius: 8px;
    padding: 0.85rem 1rem; background: var(--panel); backdrop-filter: blur(12px); }
  #evolution .two h4 { margin: 0 0 0.35rem; font-size: 0.78rem; letter-spacing: 0.04em;
    text-transform: uppercase; }
  #evolution .two p { margin: 0; font-size: 0.85rem; color: var(--ink-soft); }
  #evolution .two .a h4 { color: var(--missing); }
  #evolution .two .l h4 { color: var(--carry); }
  @media (max-width: 40rem) { #evolution .two { grid-template-columns: 1fr; } }

  #evolution .tabs { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 1rem; }
  #evolution .tab { font-family: inherit; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.03em;
    padding: 0.34rem 0.65rem; border-radius: 999px;
    border: 1px solid var(--panel-border); background: var(--panel);
    color: var(--ink-faint); cursor: pointer; }
  #evolution .tab.on { background: rgba(185, 139, 255, 0.12); border-color: rgba(185, 139, 255, 0.4); color: var(--evo-accent); }
  #evolution .tab:focus-visible { outline: 2px solid var(--evo-accent); outline-offset: 2px; }
  #evolution .note { background: var(--panel); backdrop-filter: blur(12px); border: 1px solid var(--panel-border);
    border-left: 3px solid var(--evo-accent);
    border-radius: 8px; padding: 0.85rem 1rem; margin-top: 1rem; font-size: 0.86rem;
    color: var(--ink-soft); }
  #evolution .note b { color: var(--ink); }

  #evolution pre { margin: 0.4rem 0 0; overflow-x: auto; background: var(--panel);
    backdrop-filter: blur(12px);
    border: 1px solid var(--panel-border); border-radius: 8px; padding: 0.85rem 1rem;
    font-family: inherit; font-size: 0.72rem; line-height: 1.55; color: var(--ink-soft); }

  #evolution footer { margin-top: 2.5rem; padding-top: 1.1rem; border-top: 1px solid var(--panel-border);
    font-size: 0.78rem; color: var(--ink-faint); }

  @media (prefers-reduced-motion: reduce) {
    #evolution .row { animation: none; opacity: 1; transform: none; }
    #evolution .fl .fill { transition: none; }
  }
  @media (max-width: 44rem) {
    #evolution .row { grid-template-columns: 1fr; gap: 0.15rem; }
    #evolution .arrow { text-align: left; }
    #evolution .fl { grid-template-columns: 1fr; gap: 0.3rem; }
    #evolution .fl .num { text-align: left; }
  }
</style>

<section id="evolution">
<div class="wrap">

  <header>
    <p class="kicker">IntelliBroń Aman &middot; interactive &middot; one real record, traced</p>
    <h1>One DNS block, from resolver to eight security platforms</h1>
    <p class="sub">Same pipeline as the diagram above, one record followed step by step. Use the arrows or your keyboard. Colour tells you where each value came from.</p>
    <div class="bar">
      <button id="evo-prev">&larr; Back</button>
      <button id="evo-next">Next &rarr;</button>
      <button id="evo-play">Play</button>
      <div class="dots" id="evo-dots"></div>
    </div>
  </header>

  <main id="evo-stages"></main>

  <footer>
    <p>Built from a real blocked record in an 871-event production export. Identifiers redacted; structure and non-identifying values are untouched. The source feed shown as <span style="font-family:inherit">openphish</span> is illustrative &mdash; Aman does not record it yet, which is the highest-value change on the open list.</p>
  </footer>
</div>
</section>

<script>
(function () {
  "use strict";

  const CARRY = "carry", DERIVE = "derive", MISSING = "missing";

  const RAW = [
    ["@timestamp", "Aug 21, 2026 @ 15:31:50.055", CARRY, "display-formatted, not ISO"],
    ["destination.blocked", '"true"', CARRY, "a string, not a boolean"],
    ["destination.domain", "phish-example.invalid", CARRY],
    ["destination.root.domain", "example.invalid", CARRY, "dots, not an underscore"],
    ["destination.ip", '["203.0.113.42"]', CARRY, "stringified array"],
    ["dns.question.type", '["A","A","A","A"]', MISSING, "holds the ANSWER chain — wrong field"],
    ["rule.category", "suspicious", CARRY, "one word. no threat type, no source"],
    ["source.ip", "<carrier egress ip>", CARRY, "the ISP, not the device"],
    ["user.id", "<account>-<device>", CARRY, "two identities welded into one string"],
    ["message_hash", "request-<uuid>", CARRY, "unique — our dedupe key"],
    ["event.kind", "event", MISSING, "says 'event'; a SIEM needs 'alert'"],
    ["event.hash", '""', MISSING, "present and empty in all 871 records"],
    ["ecs.version", "1.6.0", MISSING, "declares a standard it does not follow"],
    ["event.severity", "— absent —", MISSING, "no severity anywhere"],
    ["event.action / category / type / outcome", "— absent —", MISSING, "all four missing"],
    ["observer.vendor / product", "— absent —", MISSING, "nothing says who reported it"],
    ["rule.name / rule.ruleset", "— absent —", MISSING, "no way to answer 'why?'"],
    ["dns.response_code", "— absent —", MISSING, "how did we refuse? unrecorded"]
  ];

  const DERIVED = [
    ["event.kind", "alert", DERIVE, "constant — the one field Elastic's promotion rule reads"],
    ["disposition", "Blocked", DERIVE, "from destination.blocked"],
    ["action", "Denied", DERIVE, "from destination.blocked"],
    ["severity_id / severity", "4 / High", DERIVE, "looked up from rule.category"],
    ["confidence", "High", DERIVE, "OpenPhish is a confirmed feed, not a guess"],
    ["is_alert", "false", DERIVE, "suspicious is 90% of volume — log it, don't page anyone"],
    ["risk_level_id", "3", DERIVE, "looked up from rule.category"],
    ["query.hostname", "phish-example.invalid", CARRY, "renamed from destination.domain"],
    ["registered_domain", "example.invalid", CARRY, "renamed from destination.root.domain"],
    ["src_endpoint.uid", "<device>", DERIVE, "split out of the composite user.id"],
    ["metadata.tenant_uid", "<account>", DERIVE, "split out of the composite user.id — the tenant key"],
    ["observer / product", "PT ITSEC Asia · IntelliBroń Aman", DERIVE, "constants"],
    ["reputation.provider", "openphish", MISSING, "BLOCKED — Aman drops this at merge time"],
    ["rcode", "— unknown —", MISSING, "BLOCKED — nobody has asked the resolver team"],
    ["time", "1787326310055", DERIVE, "parsed to epoch millis"],
    ["dns.question.type", "dropped", MISSING, "wrong data — safer to omit than forward"]
  ];

  const FACTS = ["the domain asked for", "the verdict", "how serious",
                 "who says it's bad", "the client", "which customer"];
  const PLATFORMS = {
    "OCSF": ["query.hostname", "disposition = Blocked", "severity_id = 4",
             "observables[].reputation.provider", "src_endpoint.ip", "metadata.tenant_uid"],
    "Splunk CIM": ["dest", "signature", "urgency = high",
                   "(custom field)", "src", "tenant_id"],
    "Sentinel ASIM": ["DnsQuery", "EventResult", "EventSeverity = High",
                      "RuleName", "SrcIpAddr", "TenantId_s"],
    "CEF": ["destinationDnsDomain", "act = blocked", "severity = 7 (header)",
            "cs1 + cs1Label", "src", "cs3 + cs3Label"],
    "LEEF 2.0": ["identSrc", "(in the event ID)", "sev = 7",
                 "srcFeed", "src", "(custom key)"],
    "Google UDM": ["network.dns.questions[].name", "security_result.action = BLOCK",
                   "security_result.severity = HIGH", "security_result.rule_name",
                   "principal.ip", "additional.tenant_id"],
    "Elastic ECS": ["dns.question.name", "event.action = blocked", "event.severity = 7",
                    "rule.ruleset", "source.ip", "organization.id"],
    "Wazuh": ["aman.domain", "(the rule that matched)", "rule level = 10",
              "aman.feed", "src_ip", "aman.tenant"]
  };

  const STAGES = [
    { n: "Stage 01", t: "What we pull from the API",
      d: "The record exactly as Aman stores it. Nine facts are present and useful. Nine things are missing or wrong — and those are the ones a security platform needs most.",
      build: s => { rows(s, RAW); legend(s);
        note(s, "<b>Read the red rows.</b> Aman records what happened but never labels it as a security event, never says how serious it is, and never says which blocklist matched. Those omissions are the entire job."); } },

    { n: "Stage 02", t: "Filter to what matters",
      d: "Three questions, asked of the same 871 records. How many lookups happened? How many did Aman refuse? And how many of those refusals were actual security threats rather than ads, trackers or gambling? Only the last group is worth a security team's attention.",
      build: s => { funnel(s);
        note(s, "<b>Filtering to 8.2% solves the cost problem.</b> The customer pays their SIEM by volume, so sending a twelfth of the stream makes us cheap to ingest. But it does not solve the <i>attention</i> problem — and those are different. Here is why.");
        calc(s);
        note(s, "<b>Three per second, every second, forever.</b> An analyst working carefully gets through tens of alerts in a day, not hundreds of thousands. So this volume cannot all be alerts — not because the events are unimportant, but because a queue nobody can clear is the same as no queue at all. It gets muted in week one.");
        split(s);
        note(s, "<b>So we send everything, and mark it honestly.</b> All 71 reach the customer either way — nothing is discarded. What changes is whether an event interrupts a person or waits to be found. <span style=\\"font-family:inherit\\">malware</span> interrupts, because it occurred zero times in 9.4 hours. <span style=\\"font-family:inherit\\">suspicious</span> waits, because it was 64 of the 71."); } },

    { n: "Stage 03", t: "Enrich and normalise",
      d: "Amber rows are values we compute. Blue rows are carried across with a new name. Red rows are the two things we still cannot fill.",
      build: s => { rows(s, DERIVED); legend(s);
        note(s, "<b>This is derivation, not invention.</b> Every amber value is a constant or a lookup from data already present. The two red rows are deliberately left visible as gaps rather than guessed — guessing a DNS response code would quietly break the customer's built-in reports."); } },

    { n: "Stage 04", t: "One standard event",
      d: "The result: OCSF DNS Activity, class 4003 — the vendor-neutral industry schema. This is what we publish, and everything downstream is a mechanical conversion of it.",
      build: s => { code(s);
        note(s, "<b>The verdict is a first-class field.</b> <span style=\\"font-family:inherit\\">disposition: \\"Blocked\\"</span> is the whole point — we ship a decision, not a log line. And <span style=\\"font-family:inherit\\">reputation.provider</span> is what turns “suspicious” into “phishing, per OpenPhish.”"); } },

    { n: "Stage 05", t: "The same six facts, eight vocabularies",
      d: "Pick a platform. The facts never change — only the words each product insists on. This is the entire reason a translation layer exists.",
      build: s => { switcher(s);
        note(s, "<b>Notice the gaps.</b> Splunk has no standard field for who flagged the domain, so it needs a custom one. LEEF hides the verdict inside the event ID. Wazuh's rule level <i>is</i> the severity. Nobody agrees on anything — which is why we translate once, from one canonical form, rather than eight times from raw."); } }
  ];

  function esc(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }

  function rows(host, data) {
    const g = document.createElement("div");
    g.className = "grid";
    data.forEach((r, i) => {
      const d = document.createElement("div");
      d.className = "row " + r[2];
      d.style.animationDelay = (i * 55) + "ms";
      d.innerHTML = '<span class="k">' + esc(r[0]) + '</span>'
        + '<span class="arrow">&rarr;</span>'
        + '<span class="v">' + esc(r[1]) + '</span>'
        + (r[3] ? '<span class="tagline">' + esc(r[3]) + '</span>' : '');
      g.appendChild(d);
    });
    host.appendChild(g);
  }

  function legend(host) {
    const l = document.createElement("div");
    l.className = "legend";
    l.innerHTML =
      '<span><i style="background:var(--carry)"></i>carried across</span>' +
      '<span><i style="background:var(--derive)"></i>we compute it</span>' +
      '<span><i style="background:var(--missing)"></i>missing, wrong, or blocked</span>';
    host.appendChild(l);
  }

  function funnel(host) {
    const F = [
      ["All DNS lookups", 871, 100, "var(--ink-faint)"],
      ["Blocked", 100, 11.5, "var(--derive)"],
      ["Threat categories only", 71, 8.2, "var(--carry)"]
    ];
    const box = document.createElement("div");
    box.className = "funnel";
    F.forEach(([lbl, n, pct, col]) => {
      const r = document.createElement("div");
      r.className = "fl";
      r.innerHTML = '<span class="lbl">' + lbl + '</span>'
        + '<span class="track"><span class="fill" style="background:' + col + '"></span></span>'
        + '<span class="num">' + n + " · " + pct + "%</span>";
      box.appendChild(r);
      requestAnimationFrame(() => {
        setTimeout(() => { r.querySelector(".fill").style.width = pct + "%"; }, 120);
      });
    });
    host.appendChild(box);
  }

  function calc(host) {
    const STEPS = [
      ["Threat events in the sample", "71"],
      ["÷ 7 devices", "10.1 per device"],
      ["÷ 9.4 hours observed", "1.08 per device per hour"],
      ["× 24 hours", "25.9 per device per day"],
      ["× 10,000 devices", "259,000 per day"],
      ["÷ 86,400 seconds in a day", "3 per second", true]
    ];
    const box = document.createElement("div");
    box.className = "calc";
    STEPS.forEach(function (row) {
      const d = document.createElement("div");
      d.className = "step" + (row[2] ? " total" : "");
      d.innerHTML = '<span class="op">' + row[0] + '</span>'
                  + '<span class="res">' + row[1] + '</span>';
      box.appendChild(d);
    });
    host.appendChild(box);
  }

  function split(host) {
    const box = document.createElement("div");
    box.className = "two";
    box.innerHTML =
      '<div class="a"><h4>Alert</h4><p>Interrupts a person. Lands in a queue somebody is '
      + 'accountable for clearing. Has to stay rare enough to be trusted — if it is noisy, '
      + 'analysts learn to ignore it, and then it protects nobody.</p></div>'
      + '<div class="l"><h4>Log</h4><p>Searchable and permanent, but silent. Used when '
      + 'investigating something else: <i>this laptop is compromised — what did the same '
      + "employee's phone do last week?</i> Costs no attention until it is needed.</p></div>";
    host.appendChild(box);
  }

  function code(host) {
    const p = document.createElement("pre");
    p.textContent =
'{\\n' +
'  "class_uid": 4003,        "class_name": "DNS Activity",\\n' +
'  "activity_id": 1,         "type_uid": 400301,\\n' +
'  "time": 1787326310055,\\n\\n' +
'  "disposition": "Blocked", "action": "Denied",\\n' +
'  "severity": "High",       "confidence": "High",\\n' +
'  "is_alert": false,        "status": "Success",\\n\\n' +
'  "query":   { "hostname": "phish-example.invalid", "type": "A" },\\n' +
'  "answers": [ { "rdata": "203.0.113.42" } ],\\n\\n' +
'  "src_endpoint": { "ip": "<ip>", "uid": "<device>" },\\n\\n' +
'  "metadata": {\\n' +
'    "version": "1.9.0",\\n' +
'    "tenant_uid": "<account>",\\n' +
'    "profiles": [ "security_control" ],\\n' +
'    "product": { "vendor_name": "PT ITSEC Asia",\\n' +
'                 "name": "IntelliBroń Aman" }\\n' +
'  },\\n\\n' +
'  "observables": [\\n' +
'    { "type": "Hostname", "value": "phish-example.invalid",\\n' +
'      "reputation": { "provider": "openphish", "score": "Malicious" } }\\n' +
'  ],\\n' +
'  "enrichments": [\\n' +
'    { "name": "rule.category", "value": "suspicious" }\\n' +
'  ],\\n\\n' +
'  "message": "Phishing or fraud domain blocked: phish-example.invalid requested by device <id>, flagged by openphish"\\n' +
'}';
    host.appendChild(p);
  }

  function switcher(host) {
    const names = Object.keys(PLATFORMS);
    const tabs = document.createElement("div");
    tabs.className = "tabs";
    const body = document.createElement("div");
    body.className = "grid";

    function paint(name) {
      Array.from(tabs.children).forEach(b =>
        b.classList.toggle("on", b.textContent === name));
      body.innerHTML = "";
      PLATFORMS[name].forEach((field, i) => {
        const d = document.createElement("div");
        d.className = "row carry";
        d.style.animationDelay = (i * 65) + "ms";
        d.innerHTML = '<span class="k">' + esc(FACTS[i]) + '</span>'
          + '<span class="arrow">&rarr;</span>'
          + '<span class="v">' + esc(field) + '</span>';
        body.appendChild(d);
      });
    }

    names.forEach(n => {
      const b = document.createElement("button");
      b.className = "tab";
      b.textContent = n;
      b.addEventListener("click", () => paint(n));
      tabs.appendChild(b);
    });
    host.appendChild(tabs);
    host.appendChild(body);
    paint(names[0]);
  }

  const host = document.getElementById("evo-stages");
  const dots = document.getElementById("evo-dots");
  const prev = document.getElementById("evo-prev");
  const next = document.getElementById("evo-next");
  const play = document.getElementById("evo-play");
  let at = 0, timer = null;

  STAGES.forEach((st, i) => {
    const sec = document.createElement("section");
    sec.className = "stage";
    sec.setAttribute("aria-label", st.t);
    sec.innerHTML = '<div class="stage-head"><span class="stage-n">' + st.n
      + '</span><h2 class="stage-t">' + st.t + '</h2></div>'
      + '<p class="stage-d">' + st.d + '</p>';
    host.appendChild(sec);

    const b = document.createElement("button");
    b.className = "evo-dot";
    b.setAttribute("aria-label", "Go to " + st.n);
    b.addEventListener("click", () => go(i));
    dots.appendChild(b);
  });

  function note(hostEl, html) {
    const n = document.createElement("div");
    n.className = "note";
    n.innerHTML = html;
    hostEl.appendChild(n);
  }

  function go(i) {
    at = (i + STAGES.length) % STAGES.length;
    const secs = host.children;
    for (let k = 0; k < secs.length; k++) secs[k].classList.toggle("live", k === at);
    Array.from(dots.children).forEach((d, k) => d.classList.toggle("on", k === at));
    const sec = secs[at];
    while (sec.children.length > 2) sec.removeChild(sec.lastChild);
    STAGES[at].build(sec);
    prev.disabled = false; next.disabled = false;
  }

  next.addEventListener("click", () => { stop(); go(at + 1); });
  prev.addEventListener("click", () => { stop(); go(at - 1); });
  play.addEventListener("click", () => timer ? stop() : start());

  function start() {
    play.textContent = "Pause";
    timer = setInterval(() => go(at + 1), 7000);
  }
  function stop() {
    play.textContent = "Play";
    if (timer) { clearInterval(timer); timer = null; }
  }

  document.addEventListener("keydown", e => {
    if (e.key === "ArrowRight") { stop(); go(at + 1); }
    else if (e.key === "ArrowLeft") { stop(); go(at - 1); }
  });

  go(0);
})();
</script>

</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = DASHBOARD_HTML.encode("utf-8")
            content_type = "text/html; charset=utf-8"
        elif self.path == "/status.json":
            with STATE_LOCK:
                body = json.dumps(STATE).encode("utf-8")
            content_type = "application/json"
        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    threading.Thread(target=stream_loop, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Live dashboard: http://localhost:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
