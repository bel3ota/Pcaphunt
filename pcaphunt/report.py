"""Self-contained HTML report generation for PcapHunt."""

import base64
import html as html_module
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _escape(value: Any) -> str:
    """Safely escape a value for HTML insertion."""
    if value is None:
        return ""
    return html_module.escape(str(value), quote=True)


def _truncate(text: str, length: int = 200) -> str:
    """Truncate long text with ellipsis, preserving HTML safety."""
    if len(text) <= length:
        return text
    return text[:length] + "..."


def _json_b64_for_js(data: Any) -> str:
    """Serialize data to a base64-encoded JSON string safe for JS embedding."""
    json_str = json.dumps(data, ensure_ascii=True, default=str)
    return base64.b64encode(json_str.encode("utf-8")).decode("ascii")


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PcapHunt Report &mdash; {{PCAP_NAME}}</title>
<style>
:root {
  --bg: #0d1117;
  --panel: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --muted: #8b949e;
  --accent: #58a6ff;
  --accent2: #3fb950;
  --warn: #d29922;
  --danger: #f85149;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.5; }
a { color: var(--accent); text-decoration: none; }
header {
  background: var(--panel);
  border-bottom: 1px solid var(--border);
  padding: 24px 20px;
}
header h1 { margin: 0 0 6px 0; font-size: 22px; letter-spacing: 0.5px; }
header .meta { color: var(--muted); font-size: 12px; }
.container { max-width: 1400px; margin: 0 auto; padding: 20px; }
.dashboard {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
  text-align: center;
  cursor: default;
  transition: transform .1s ease;
}
.card:hover { transform: translateY(-2px); }
.card .count { font-size: 24px; font-weight: 700; color: var(--accent); display: block; }
.card .label { font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); margin-top: 4px; }
.card.total .count { color: var(--accent2); }
.card.flag .count { color: var(--warn); }
.toolbar {
  display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
  background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 12px 14px; margin-bottom: 14px;
}
.toolbar input[type="text"] {
  flex: 1 1 260px; min-width: 200px;
  background: var(--bg); color: var(--text); border: 1px solid var(--border);
  border-radius: 6px; padding: 8px 12px; font-size: 13px;
}
.toolbar input[type="text"]::placeholder { color: var(--muted); }
.toolbar select {
  background: var(--bg); color: var(--text); border: 1px solid var(--border);
  border-radius: 6px; padding: 8px 10px; font-size: 13px;
}
.toolbar .right { margin-left: auto; font-size: 12px; color: var(--muted); }
table {
  width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
}
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
th { background: rgba(88,166,255,0.08); font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); cursor: pointer; user-select: none; white-space: nowrap; }
th:hover { color: var(--text); }
tr:hover { background: rgba(88,166,255,0.04); }
.type-badge {
  display: inline-block; font-size: 10px; text-transform: uppercase; letter-spacing: .4px;
  padding: 2px 8px; border-radius: 12px; background: rgba(88,166,255,0.15); color: var(--accent); border: 1px solid rgba(88,166,255,0.25);
}
.type-badge.flag { background: rgba(210,153,34,0.15); color: var(--warn); border-color: rgba(210,153,34,0.3); }
.type-badge.creds { background: rgba(248,81,73,0.15); color: var(--danger); border-color: rgba(248,81,73,0.3); }
.content-cell { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; font-size: 12px; max-width: 420px; word-break: break-all; }
.content-cell .truncated { color: var(--muted); }
.packets-cell { font-size: 12px; color: var(--muted); white-space: nowrap; }
.meta-cell { font-size: 12px; color: var(--muted); white-space: nowrap; }
.confidence-cell { font-size: 12px; }
.empty-state { text-align: center; padding: 40px 20px; color: var(--muted); }
.no-results { display: none; }
.modal-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: none;
  align-items: center; justify-content: center; z-index: 1000; padding: 20px;
}
.modal-overlay.active { display: flex; }
.modal {
  background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
  max-width: 800px; width: 100%; max-height: 90vh; overflow: auto; padding: 20px;
}
.modal h3 { margin-top: 0; }
.modal pre {
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 12px; overflow: auto; font-size: 12px; line-height: 1.4; white-space: pre-wrap; word-break: break-all;
}
.modal .close-btn {
  float: right; background: transparent; border: 1px solid var(--border); color: var(--text);
  border-radius: 6px; padding: 4px 10px; cursor: pointer; font-size: 12px;
}
.modal .close-btn:hover { background: var(--border); }
@media (max-width: 900px) {
  .meta-cell, .confidence-cell { display: none; }
  .content-cell { max-width: 280px; }
}
@media (max-width: 640px) {
  th, td { padding: 8px; font-size: 12px; }
  .packets-cell { display: none; }
}
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>PcapHunt Report</h1>
    <div class="meta">
      PCAP: <strong>{{PCAP_NAME}}</strong> &nbsp;&bull;&nbsp;
      Scanned: <strong>{{SCAN_TIME}}</strong> &nbsp;&bull;&nbsp;
      Duration: <strong>{{DURATION}}</strong> &nbsp;&bull;&nbsp;
      Total Findings: <strong>{{TOTAL}}</strong>
    </div>
  </div>
</header>

<div class="container">
  <div class="dashboard" id="dashboard"></div>

  <div class="toolbar">
    <input type="text" id="searchInput" placeholder="Search findings..." autocomplete="off">
    <select id="filterType">
      <option value="">All Categories</option>
    </select>
    <div class="right" id="showingCount"></div>
  </div>

  <div id="tableContainer">
    <table id="findingsTable">
      <thead>
        <tr>
          <th onclick="sortBy('type')">Type &#x2195;</th>
          <th onclick="sortBy('content')">Content &#x2195;</th>
          <th onclick="sortBy('packets')">Packets &#x2195;</th>
          <th class="meta-cell" onclick="sortBy('source')">Source &#x2195;</th>
          <th class="meta-cell" onclick="sortBy('destination')">Destination &#x2195;</th>
          <th class="meta-cell" onclick="sortBy('protocol')">Protocol &#x2195;</th>
          <th class="confidence-cell" onclick="sortBy('confidence')">Confidence &#x2195;</th>
        </tr>
      </thead>
      <tbody id="tableBody"></tbody>
    </table>
    <div id="noResults" class="empty-state no-results">No findings match your search.</div>
  </div>
</div>

<div class="modal-overlay" id="modal" onclick="closeModal(event)">
  <div class="modal" onclick="event.stopPropagation()">
    <button class="close-btn" onclick="closeModal()">Close</button>
    <h3 id="modalTitle">Finding Details</h3>
    <div id="modalBody"></div>
  </div>
</div>

<script>
(function() {
  var findings = JSON.parse(atob('{{FINDINGS_B64}}'));
  var sortKey = 'packets';
  var sortAsc = true;
  var filterType = '';
  var searchQuery = '';

  function init() {
    buildDashboard();
    buildTypeFilter();
    render();
    document.getElementById('searchInput').addEventListener('input', function(e) {
      searchQuery = e.target.value.toLowerCase();
      render();
    });
    document.getElementById('filterType').addEventListener('change', function(e) {
      filterType = e.target.value;
      render();
    });
  }

  function buildDashboard() {
    var counts = {};
    for (var i = 0; i < findings.length; i++) {
      var t = findings[i].type || 'unknown';
      counts[t] = (counts[t] || 0) + 1;
    }
    var container = document.getElementById('dashboard');
    var order = ['plaintext','base64','hex','url_encoded','urls','ip_addresses','domains','emails','credentials','flags','hashes','jwt','files','suspicious'];
    var html = '<div class="card total"><span class="count">' + findings.length + '</span><div class="label">Total Findings</div></div>';
    for (var j = 0; j < order.length; j++) {
      var k = order[j];
      var c = counts[k] || 0;
      if (c > 0) {
        var cls = k === 'flags' ? 'card flag' : (k === 'credentials' ? 'card creds' : 'card');
        html += '<div class="' + cls + '"><span class="count">' + c + '</span><div class="label">' + k.replace(/_/g,' ').replace(/\\b\\w/g,function(l){return l.toUpperCase();}) + '</div></div>';
      }
    }
    var other = findings.length;
    for (var key in counts) { if (order.indexOf(key) === -1) other -= counts[key]; }
    if (other > 0) {
      html += '<div class="card"><span class="count">' + other + '</span><div class="label">Other</div></div>';
    }
    container.innerHTML = html;
  }

  function buildTypeFilter() {
    var sel = document.getElementById('filterType');
    var types = {};
    for (var i = 0; i < findings.length; i++) { types[findings[i].type] = true; }
    var keys = Object.keys(types).sort();
    for (var j = 0; j < keys.length; j++) {
      var opt = document.createElement('option');
      opt.value = keys[j];
      opt.textContent = keys[j].replace(/_/g,' ').replace(/\\b\\w/g,function(l){return l.toUpperCase();});
      sel.appendChild(opt);
    }
  }

  function sortFindings() {
    findings.sort(function(a, b) {
      var av, bv;
      if (sortKey === 'packets') {
        av = Math.min.apply(null, a.packet_numbers || [0]);
        bv = Math.min.apply(null, b.packet_numbers || [0]);
      } else if (sortKey === 'content') {
        av = (a.decoded || a.original || '').toLowerCase();
        bv = (b.decoded || b.original || '').toLowerCase();
      } else if (sortKey === 'confidence') {
        av = a.confidence !== undefined ? a.confidence : -1;
        bv = b.confidence !== undefined ? b.confidence : -1;
      } else {
        av = (a[sortKey] || '').toLowerCase();
        bv = (b[sortKey] || '').toLowerCase();
      }
      if (av < bv) return sortAsc ? -1 : 1;
      if (av > bv) return sortAsc ? 1 : -1;
      return 0;
    });
  }

  function render() {
    sortFindings();
    var tbody = document.getElementById('tableBody');
    var html = '';
    var visible = 0;
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      if (filterType && f.type !== filterType) continue;
      var content = (f.decoded || f.original || '');
      if (searchQuery && content.toLowerCase().indexOf(searchQuery) === -1) continue;
      visible++;
      var pktNums = (f.packet_numbers || []).join(', ');
      var firstPkt = f.first_seen_packet !== undefined ? f.first_seen_packet : (f.packet_numbers && f.packet_numbers[0] ? f.packet_numbers[0] : '-');
      var badgeClass = f.type === 'flags' ? 'type-badge flag' : (f.type === 'credentials' ? 'type-badge creds' : 'type-badge');
      var displayContent = content.length > 180 ? _htmlEscape(content.substring(0,180)) + '<span class="truncated">...</span>' : _htmlEscape(content);
      var source = (f.source || '').replace(/:/g, '\u200B:'); // zero-width space for wrapping
      var dest = (f.destination || '').replace(/:/g, '\u200B:');
      html += '<tr onclick="openModal(' + i + ')">' +
        '<td><span class="' + badgeClass + '">' + _htmlEscape(f.type || 'unknown') + '</span></td>' +
        '<td class="content-cell">' + displayContent + '</td>' +
        '<td class="packets-cell">' + _htmlEscape(firstPkt) + (f.packet_numbers && f.packet_numbers.length > 1 ? ' <span style=\"color:var(--muted)\">(' + f.packet_numbers.length + ')</span>' : '') + '</td>' +
        '<td class="meta-cell">' + _htmlEscape(source) + '</td>' +
        '<td class="meta-cell">' + _htmlEscape(dest) + '</td>' +
        '<td class="meta-cell">' + _htmlEscape(f.protocol || '') + '</td>' +
        '<td class="confidence-cell">' + (f.confidence !== undefined ? (f.confidence*100).toFixed(0) + '%' : '-') + '</td>' +
      '</tr>';
    }
    tbody.innerHTML = html;
    document.getElementById('noResults').style.display = visible === 0 ? 'block' : 'none';
    document.getElementById('showingCount').textContent = 'Showing ' + visible + ' of ' + findings.length;
  }

  function _htmlEscape(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  window.sortBy = function(key) {
    if (sortKey === key) { sortAsc = !sortAsc; } else { sortKey = key; sortAsc = true; }
    render();
  };

  window.openModal = function(index) {
    var f = findings[index];
    if (!f) return;
    var title = (f.type || 'Finding').replace(/_/g,' ').replace(/\\b\\w/g,function(l){return l.toUpperCase();});
    document.getElementById('modalTitle').textContent = title;
    var body = '';
    var fields = [
      ['Type', f.type],
      ['Packet Numbers', (f.packet_numbers || []).join(', ')],
      ['First Seen Packet', f.first_seen_packet],
      ['Protocol', f.protocol],
      ['Source', f.source],
      ['Destination', f.destination],
      ['Offset', f.offset],
      ['Confidence', f.confidence !== undefined ? (f.confidence*100).toFixed(0) + '%' : '-'],
      ['File Type', f.file_type],
      ['Entropy', f.entropy],
      ['Notes', f.notes],
    ];
    for (var i = 0; i < fields.length; i++) {
      if (fields[i][1] !== undefined && fields[i][1] !== null && fields[i][1] !== '') {
        body += '<p><strong>' + _htmlEscape(fields[i][0]) + ':</strong> ' + _htmlEscape(fields[i][1]) + '</p>';
      }
    }
    body += '<h4>Original</h4><pre>' + _htmlEscape(f.original || '') + '</pre>';
    if (f.decoded && f.decoded !== f.original) {
      body += '<h4>Decoded</h4><pre>' + _htmlEscape(f.decoded) + '</pre>';
    }
    if (f.decoding_steps && f.decoding_steps.length) {
      body += '<h4>Decoding Steps</h4><pre>';
      for (var j = 0; j < f.decoding_steps.length; j++) {
        body += _htmlEscape(f.decoding_steps[j].method) + ': ' + _htmlEscape(f.decoding_steps[j].result) + '\\n';
      }
      body += '</pre>';
    }
    document.getElementById('modalBody').innerHTML = body;
    document.getElementById('modal').classList.add('active');
  };

  window.closeModal = function(e) {
    if (!e || e.target.id === 'modal') {
      document.getElementById('modal').classList.remove('active');
    }
  };

  document.addEventListener('keydown', function(e) { if (e.key === 'Escape') window.closeModal(); });

  init();
})();
</script>
</body>
</html>
"""


def generate_html_report(
    findings: list[dict[str, Any]],
    pcap_name: str,
    output_path: str,
    duration_seconds: float = 0.0,
) -> None:
    """Generate a self-contained HTML report.

    The report contains embedded CSS and JavaScript and works
    when opened directly in a browser without a web server.
    All extracted content is HTML-escaped to prevent XSS.

    Args:
        findings: List of finding dictionaries.
        pcap_name: Name of the scanned PCAP file.
        output_path: Path where the HTML report will be written.
        duration_seconds: Scan duration for display.
    """
    if not findings:
        # Still generate a valid report for empty results
        pass

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration_str = f"{duration_seconds:.2f}s" if duration_seconds > 0 else "< 0.01s"

    # Serialize findings to base64-encoded JSON for safe JavaScript embedding
    findings_b64 = _json_b64_for_js(findings)

    html_content = _HTML_TEMPLATE
    html_content = html_content.replace("{{PCAP_NAME}}", _escape(pcap_name))
    html_content = html_content.replace("{{SCAN_TIME}}", _escape(scan_time))
    html_content = html_content.replace("{{DURATION}}", _escape(duration_str))
    html_content = html_content.replace("{{TOTAL}}", _escape(str(len(findings))))
    html_content = html_content.replace("{{FINDINGS_B64}}", findings_b64)

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    except Exception as exc:
        logger.warning("Failed to write HTML report to %s: %s", output_path, exc)
