"""Self-contained HTML report generation for PcapHunt."""

from __future__ import annotations

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


def _severity_color(severity: str) -> str:
    colors = {
        "critical": "#f85149",
        "high": "#d29922",
        "medium": "#58a6ff",
        "low": "#8b949e",
        "info": "#6e7681",
    }
    return colors.get(severity.lower(), "#8b949e")


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

/* Tabs */
.tabs {
  display: flex;
  gap: 4px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 6px;
  margin-bottom: 16px;
  overflow-x: auto;
}
.tab {
  padding: 8px 14px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  white-space: nowrap;
  color: var(--muted);
  border: none;
  background: transparent;
}
.tab:hover { color: var(--text); }
.tab.active { background: rgba(88,166,255,0.15); color: var(--accent); }

.tab-content { display: none; }
.tab-content.active { display: block; }

/* Dashboard cards */
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
.card.critical .count { color: var(--danger); }

/* Toolbar */
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

/* Tables */
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
.severity-badge {
  display: inline-block; font-size: 10px; text-transform: uppercase; letter-spacing: .4px;
  padding: 2px 8px; border-radius: 12px; border: 1px solid;
}
.content-cell { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; font-size: 12px; max-width: 420px; word-break: break-all; }
.content-cell .truncated { color: var(--muted); }
.packets-cell { font-size: 12px; color: var(--muted); white-space: nowrap; }
.meta-cell { font-size: 12px; color: var(--muted); white-space: nowrap; }
.confidence-cell { font-size: 12px; }
.score-cell { font-size: 12px; font-weight: 600; }
.empty-state { text-align: center; padding: 40px 20px; color: var(--muted); }
.no-results { display: none; }

/* Modal */
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

/* Network graph placeholder */
.network-container {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
  min-height: 400px;
}
.network-node {
  display: inline-block;
  background: rgba(88,166,255,0.15);
  border: 1px solid rgba(88,166,255,0.3);
  border-radius: 8px;
  padding: 8px 12px;
  margin: 4px;
  font-size: 12px;
}
.network-node.suspicious {
  background: rgba(248,81,73,0.15);
  border-color: rgba(248,81,73,0.3);
  color: var(--danger);
}
.network-edge {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
}
.network-edge:last-child { border-bottom: none; }

/* Timeline */
.timeline-event {
  display: flex;
  gap: 12px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}
.timeline-event:last-child { border-bottom: none; }
.timeline-time { min-width: 80px; color: var(--muted); font-size: 11px; white-space: nowrap; }
.timeline-type { min-width: 100px; font-size: 11px; text-transform: uppercase; }
.timeline-desc { flex: 1; }

/* Profile stats grid */
.profile-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}
.profile-stat {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
}
.profile-stat .value { font-size: 20px; font-weight: 700; color: var(--accent); }
.profile-stat .label { font-size: 11px; color: var(--muted); margin-top: 2px; }

/* Files table */
.file-complete { color: var(--accent2); }
.file-incomplete { color: var(--warn); }

/* Responsive */
@media (max-width: 900px) {
  .meta-cell, .confidence-cell, .score-cell { display: none; }
  .content-cell { max-width: 280px; }
}
@media (max-width: 640px) {
  th, td { padding: 8px; font-size: 12px; }
  .packets-cell { display: none; }
  .tabs { flex-wrap: wrap; }
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
  <div class="tabs" id="tabs">
    <button class="tab active" data-tab="overview">Overview</button>
    <button class="tab" data-tab="findings">Findings</button>
    <button class="tab" data-tab="files">Files</button>
    <button class="tab" data-tab="timeline">Timeline</button>
    <button class="tab" data-tab="network">Network</button>
    <button class="tab" data-tab="streams">Streams</button>
  </div>

  <!-- Overview Tab -->
  <div class="tab-content active" id="overview">
    <div class="dashboard" id="overviewDashboard"></div>
    <div id="profileSection"></div>
  </div>

  <!-- Findings Tab -->
  <div class="tab-content" id="findings">
    <div class="toolbar">
      <input type="text" id="searchInput" placeholder="Search findings..." autocomplete="off">
      <select id="filterType"><option value="">All Categories</option></select>
      <select id="filterSeverity"><option value="">All Severities</option></select>
      <select id="filterProtocol"><option value="">All Protocols</option></select>
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
            <th class="meta-cell" onclick="sortBy('severity')">Severity &#x2195;</th>
            <th class="score-cell" onclick="sortBy('score')">Score &#x2195;</th>
          </tr>
        </thead>
        <tbody id="tableBody"></tbody>
      </table>
      <div id="noResults" class="empty-state no-results">No findings match your search.</div>
    </div>
  </div>

  <!-- Files Tab -->
  <div class="tab-content" id="files">
    <div class="toolbar">
      <input type="text" id="fileSearchInput" placeholder="Search files..." autocomplete="off">
      <div class="right" id="fileCount"></div>
    </div>
    <div id="filesTableContainer">
      <table id="filesTable">
        <thead>
          <tr>
            <th>Filename</th>
            <th>Type</th>
            <th>Size</th>
            <th>MD5</th>
            <th>SHA256</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Complete</th>
          </tr>
        </thead>
        <tbody id="filesTableBody"></tbody>
      </table>
      <div id="noFiles" class="empty-state no-results">No files extracted.</div>
    </div>
  </div>

  <!-- Timeline Tab -->
  <div class="tab-content" id="timeline">
    <div class="toolbar">
      <input type="text" id="timelineSearchInput" placeholder="Search timeline..." autocomplete="off">
      <div class="right" id="timelineCount"></div>
    </div>
    <div id="timelineContainer"></div>
  </div>

  <!-- Network Tab -->
  <div class="tab-content" id="network">
    <div class="network-container" id="networkContainer"></div>
  </div>

  <!-- Streams Tab -->
  <div class="tab-content" id="streams">
    <div class="toolbar">
      <input type="text" id="streamSearchInput" placeholder="Search streams..." autocomplete="off">
      <div class="right" id="streamCount"></div>
    </div>
    <div id="streamsContainer"></div>
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
  var artifacts = JSON.parse(atob('{{ARTIFACTS_B64}}'));
  var timeline = JSON.parse(atob('{{TIMELINE_B64}}'));
  var network = JSON.parse(atob('{{NETWORK_B64}}'));
  var profile = JSON.parse(atob('{{PROFILE_B64}}'));

  var sortKey = 'packets';
  var sortAsc = true;
  var filterType = '';
  var filterSeverity = '';
  var filterProtocol = '';
  var searchQuery = '';

  // Tab switching
  document.getElementById('tabs').addEventListener('click', function(e) {
    if (e.target.classList.contains('tab')) {
      var tabs = document.querySelectorAll('.tab');
      var contents = document.querySelectorAll('.tab-content');
      for (var i = 0; i < tabs.length; i++) tabs[i].classList.remove('active');
      for (var i = 0; i < contents.length; i++) contents[i].classList.remove('active');
      e.target.classList.add('active');
      var target = e.target.getAttribute('data-tab');
      document.getElementById(target).classList.add('active');
    }
  });

  function init() {
    buildOverview();
    buildDashboard();
    buildTypeFilter();
    buildSeverityFilter();
    buildProtocolFilter();
    renderFindings();
    renderFiles();
    renderTimeline();
    renderNetwork();
    renderStreams();

    document.getElementById('searchInput').addEventListener('input', function(e) {
      searchQuery = e.target.value.toLowerCase();
      renderFindings();
    });
    document.getElementById('filterType').addEventListener('change', function(e) {
      filterType = e.target.value;
      renderFindings();
    });
    document.getElementById('filterSeverity').addEventListener('change', function(e) {
      filterSeverity = e.target.value;
      renderFindings();
    });
    document.getElementById('filterProtocol').addEventListener('change', function(e) {
      filterProtocol = e.target.value;
      renderFindings();
    });
  }

  function buildOverview() {
    var container = document.getElementById('overviewDashboard');
    var html = '<div class="card total"><span class="count">' + findings.length + '</span><div class="label">Total Findings</div></div>';
    if (profile && profile.total_packets) {
      html += '<div class="card"><span class="count">' + profile.total_packets.toLocaleString() + '</span><div class="label">Packets</div></div>';
    }
    if (profile && profile.unique_ips_count) {
      html += '<div class="card"><span class="count">' + profile.unique_ips_count + '</span><div class="label">Unique IPs</div></div>';
    }
    if (artifacts && artifacts.length) {
      html += '<div class="card"><span class="count">' + artifacts.length + '</span><div class="label">Files Extracted</div></div>';
    }
    var flags = findings.filter(function(f){ return f.type === 'flags'; }).length;
    if (flags) {
      html += '<div class="card flag"><span class="count">' + flags + '</span><div class="label">Flags</div></div>';
    }
    var creds = findings.filter(function(f){ return f.type === 'credentials'; }).length;
    if (creds) {
      html += '<div class="card critical"><span class="count">' + creds + '</span><div class="label">Credentials</div></div>';
    }
    var critical = findings.filter(function(f){ return f.severity === 'critical'; }).length;
    if (critical) {
      html += '<div class="card critical"><span class="count">' + critical + '</span><div class="label">Critical</div></div>';
    }
    container.innerHTML = html;

    // Profile stats
    var profileSection = document.getElementById('profileSection');
    if (profile) {
      var phtml = '<h3 style="margin-top:20px">Capture Profile</h3><div class="profile-grid">';
      if (profile.capture_duration_seconds) {
        phtml += '<div class="profile-stat"><div class="value">' + _formatDuration(profile.capture_duration_seconds) + '</div><div class="label">Duration</div></div>';
      }
      if (profile.total_bytes) {
        phtml += '<div class="profile-stat"><div class="value">' + _formatBytes(profile.total_bytes) + '</div><div class="label">Total Bytes</div></div>';
      }
      if (profile.tcp_streams) {
        phtml += '<div class="profile-stat"><div class="value">' + profile.tcp_streams + '</div><div class="label">TCP Streams</div></div>';
      }
      if (profile.udp_conversations) {
        phtml += '<div class="profile-stat"><div class="value">' + profile.udp_conversations + '</div><div class="label">UDP Conversations</div></div>';
      }
      if (profile.http_requests) {
        phtml += '<div class="profile-stat"><div class="value">' + profile.http_requests + '</div><div class="label">HTTP Requests</div></div>';
      }
      if (profile.dns_queries) {
        phtml += '<div class="profile-stat"><div class="value">' + profile.dns_queries + '</div><div class="label">DNS Queries</div></div>';
      }
      phtml += '</div>';
      profileSection.innerHTML = phtml;
    }
  }

  function buildDashboard() {
    // Already covered in buildOverview for the findings tab
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

  function buildSeverityFilter() {
    var sel = document.getElementById('filterSeverity');
    var sevs = {};
    for (var i = 0; i < findings.length; i++) { if (findings[i].severity) sevs[findings[i].severity] = true; }
    var keys = Object.keys(sevs).sort();
    for (var j = 0; j < keys.length; j++) {
      var opt = document.createElement('option');
      opt.value = keys[j];
      opt.textContent = keys[j].toUpperCase();
      sel.appendChild(opt);
    }
  }

  function buildProtocolFilter() {
    var sel = document.getElementById('filterProtocol');
    var protos = {};
    for (var i = 0; i < findings.length; i++) { if (findings[i].protocol) protos[findings[i].protocol] = true; }
    var keys = Object.keys(protos).sort();
    for (var j = 0; j < keys.length; j++) {
      var opt = document.createElement('option');
      opt.value = keys[j];
      opt.textContent = keys[j].toUpperCase();
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
      } else if (sortKey === 'score') {
        av = a.score !== undefined ? a.score : -1;
        bv = b.score !== undefined ? b.score : -1;
      } else {
        av = (a[sortKey] || '').toLowerCase();
        bv = (b[sortKey] || '').toLowerCase();
      }
      if (av < bv) return sortAsc ? -1 : 1;
      if (av > bv) return sortAsc ? 1 : -1;
      return 0;
    });
  }

  function renderFindings() {
    sortFindings();
    var tbody = document.getElementById('tableBody');
    var html = '';
    var visible = 0;
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      if (filterType && f.type !== filterType) continue;
      if (filterSeverity && f.severity !== filterSeverity) continue;
      if (filterProtocol && f.protocol !== filterProtocol) continue;
      var content = (f.decoded || f.original || '');
      if (searchQuery && content.toLowerCase().indexOf(searchQuery) === -1) continue;
      visible++;
      var pktNums = (f.packet_numbers || []).join(', ');
      var firstPkt = f.first_seen_packet !== undefined ? f.first_seen_packet : (f.packet_numbers && f.packet_numbers[0] ? f.packet_numbers[0] : '-');
      var badgeClass = f.type === 'flags' ? 'type-badge flag' : (f.type === 'credentials' ? 'type-badge creds' : 'type-badge');
      var displayContent = content.length > 180 ? _htmlEscape(content.substring(0,180)) + '<span class="truncated">...</span>' : _htmlEscape(content);
      var source = (f.source || '').replace(/:/g, '\\u200B:');
      var dest = (f.destination || '').replace(/:/g, '\\u200B:');
      var sevColor = _severityColor(f.severity || 'info');
      var scoreDisplay = f.score !== undefined ? f.score : '-';
      html += '<tr onclick="openModal(' + i + ')">' +
        '<td><span class="' + badgeClass + '">' + _htmlEscape(f.type || 'unknown') + '</span></td>' +
        '<td class="content-cell">' + displayContent + '</td>' +
        '<td class="packets-cell">' + _htmlEscape(firstPkt) + (f.packet_numbers && f.packet_numbers.length > 1 ? ' <span style="color:var(--muted)">(' + f.packet_numbers.length + ')</span>' : '') + '</td>' +
        '<td class="meta-cell">' + _htmlEscape(source) + '</td>' +
        '<td class="meta-cell">' + _htmlEscape(dest) + '</td>' +
        '<td class="meta-cell">' + _htmlEscape(f.protocol || '') + '</td>' +
        '<td class="confidence-cell">' + (f.confidence !== undefined ? (f.confidence*100).toFixed(0) + '%' : '-') + '</td>' +
        '<td class="meta-cell"><span class="severity-badge" style="color:' + sevColor + ';border-color:' + sevColor + '">' + _htmlEscape(f.severity || '-') + '</span></td>' +
        '<td class="score-cell">' + scoreDisplay + '</td>' +
      '</tr>';
    }
    tbody.innerHTML = html;
    document.getElementById('noResults').style.display = visible === 0 ? 'block' : 'none';
    document.getElementById('showingCount').textContent = 'Showing ' + visible + ' of ' + findings.length;
  }

  function renderFiles() {
    var tbody = document.getElementById('filesTableBody');
    var container = document.getElementById('filesTableContainer');
    if (!artifacts || artifacts.length === 0) {
      document.getElementById('noFiles').style.display = 'block';
      document.getElementById('fileCount').textContent = '0 files';
      return;
    }
    document.getElementById('noFiles').style.display = 'none';
    var html = '';
    for (var i = 0; i < artifacts.length; i++) {
      var a = artifacts[i];
      var completeClass = a.complete ? 'file-complete' : 'file-incomplete';
      var completeText = a.complete ? 'Yes' : 'No';
      html += '<tr>' +
        '<td>' + _htmlEscape(a.filename) + '</td>' +
        '<td>' + _htmlEscape(a.file_type) + '</td>' +
        '<td>' + _formatBytes(a.size) + '</td>' +
        '<td class="content-cell">' + _htmlEscape(a.md5 || '-') + '</td>' +
        '<td class="content-cell">' + _htmlEscape(a.sha256 || '-') + '</td>' +
        '<td class="meta-cell">' + _htmlEscape(a.source_ip + (a.source_port ? ':' + a.source_port : '')) + '</td>' +
        '<td class="meta-cell">' + _htmlEscape(a.destination_ip + (a.destination_port ? ':' + a.destination_port : '')) + '</td>' +
        '<td class="' + completeClass + '">' + completeText + '</td>' +
      '</tr>';
    }
    tbody.innerHTML = html;
    document.getElementById('fileCount').textContent = artifacts.length + ' files';
  }

  function renderTimeline() {
    var container = document.getElementById('timelineContainer');
    if (!timeline || timeline.length === 0) {
      container.innerHTML = '<div class="empty-state">No timeline events.</div>';
      document.getElementById('timelineCount').textContent = '0 events';
      return;
    }
    var html = '';
    for (var i = 0; i < timeline.length; i++) {
      var e = timeline[i];
      var ts = e.timestamp ? new Date(e.timestamp * 1000).toLocaleString() : 'Unknown';
      var sevColor = _severityColor(e.severity || 'info');
      html += '<div class="timeline-event">' +
        '<div class="timeline-time">' + _htmlEscape(ts) + '</div>' +
        '<div class="timeline-type" style="color:' + sevColor + '">' + _htmlEscape(e.event_type) + '</div>' +
        '<div class="timeline-desc">' + _htmlEscape(e.description) + '</div>' +
      '</div>';
    }
    container.innerHTML = html;
    document.getElementById('timelineCount').textContent = timeline.length + ' events';
  }

  function renderNetwork() {
    var container = document.getElementById('networkContainer');
    if (!network || (!network.nodes.length && !network.edges.length)) {
      container.innerHTML = '<div class="empty-state">No network topology data.</div>';
      return;
    }
    var html = '<h3>Nodes</h3>';
    for (var i = 0; i < network.nodes.length; i++) {
      var n = network.nodes[i];
      var cls = n.is_suspicious ? 'network-node suspicious' : 'network-node';
      html += '<span class="' + cls + '">' + _htmlEscape(n.ip);
      if (n.hostname) html += '<br><small>' + _htmlEscape(n.hostname) + '</small>';
      html += '<br><small>' + n.packet_count + ' pkts, ' + _formatBytes(n.byte_count) + '</small>';
      html += '</span>';
    }
    html += '<h3 style="margin-top:20px">Communication Edges</h3>';
    html += '<table><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Port</th><th>Packets</th><th>Bytes</th></tr></thead><tbody>';
    var edgeCount = Math.min(network.edges.length, 200);
    for (var j = 0; j < edgeCount; j++) {
      var e = network.edges[j];
      html += '<tr>' +
        '<td>' + _htmlEscape(e.source_ip) + '</td>' +
        '<td>' + _htmlEscape(e.destination_ip) + '</td>' +
        '<td>' + _htmlEscape(e.protocol || '-') + '</td>' +
        '<td>' + (e.port || '-') + '</td>' +
        '<td>' + e.packet_count + '</td>' +
        '<td>' + _formatBytes(e.byte_count) + '</td>' +
      '</tr>';
    }
    html += '</tbody></table>';
    if (network.edges.length > 200) {
      html += '<p style="color:var(--muted);font-size:12px">Showing top 200 of ' + network.edges.length + ' edges.</p>';
    }
    container.innerHTML = html;
  }

  function renderStreams() {
    var container = document.getElementById('streamsContainer');
    var streams = {};
    for (var i = 0; i < findings.length; i++) {
      var sid = findings[i].stream_id;
      if (sid) {
        if (!streams[sid]) streams[sid] = [];
        streams[sid].push(findings[i]);
      }
    }
    if (Object.keys(streams).length === 0) {
      container.innerHTML = '<div class="empty-state">No stream data available.</div>';
      document.getElementById('streamCount').textContent = '0 streams';
      return;
    }
    var html = '<table><thead><tr><th>Stream ID</th><th>Protocol</th><th>Findings</th></tr></thead><tbody>';
    var keys = Object.keys(streams).sort();
    for (var j = 0; j < keys.length; j++) {
      var sid = keys[j];
      var sfindings = streams[sid];
      var proto = sfindings[0].protocol || 'Unknown';
      html += '<tr>' +
        '<td class="content-cell">' + _htmlEscape(sid) + '</td>' +
        '<td>' + _htmlEscape(proto) + '</td>' +
        '<td>' + sfindings.length + '</td>' +
      '</tr>';
    }
    html += '</tbody></table>';
    container.innerHTML = html;
    document.getElementById('streamCount').textContent = keys.length + ' streams';
  }

  function _htmlEscape(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function _severityColor(sev) {
    var colors = {critical:'#f85149', high:'#d29922', medium:'#58a6ff', low:'#8b949e', info:'#6e7681'};
    return colors[sev] || '#8b949e';
  }

  function _formatBytes(b) {
    if (b === 0) return '0 B';
    var units = ['B','KB','MB','GB'];
    var i = 0;
    while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
    return b.toFixed(2) + ' ' + units[i];
  }

  function _formatDuration(s) {
    var m = Math.floor(s / 60);
    var sec = Math.floor(s % 60);
    return (m < 10 ? '0' : '') + m + ':' + (sec < 10 ? '0' : '') + sec;
  }

  window.sortBy = function(key) {
    if (sortKey === key) { sortAsc = !sortAsc; } else { sortKey = key; sortAsc = true; }
    renderFindings();
  };

  window.openModal = function(index) {
    var f = findings[index];
    if (!f) return;
    var title = (f.type || 'Finding').replace(/_/g,' ').replace(/\\b\\w/g,function(l){return l.toUpperCase();});
    document.getElementById('modalTitle').textContent = title;
    var body = '';
    var ts = f.timestamp ? new Date(f.timestamp * 1000).toLocaleString() : null;
    var fields = [
      ['Type', f.type],
      ['Packet Numbers', (f.packet_numbers || []).join(', ')],
      ['First Seen Packet', f.first_seen_packet],
      ['Stream ID', f.stream_id],
      ['Timestamp', ts],
      ['Protocol', f.protocol],
      ['Source', f.source],
      ['Destination', f.destination],
      ['Offset', f.offset],
      ['Confidence', f.confidence !== undefined ? (f.confidence*100).toFixed(0) + '%' : '-'],
      ['Severity', f.severity],
      ['Score', f.score],
      ['File Type', f.file_type],
      ['Entropy', f.entropy],
      ['Notes', f.notes],
    ];
    for (var i = 0; i < fields.length; i++) {
      if (fields[i][1] !== undefined && fields[i][1] !== null && fields[i][1] !== '') {
        body += '<p><strong>' + _htmlEscape(fields[i][0]) + ':</strong> ' + _htmlEscape(fields[i][1]) + '</p>';
      }
    }
    if (f.score_reasons && f.score_reasons.length) {
      body += '<h4>Score Reasons</h4><ul>';
      for (var j = 0; j < f.score_reasons.length; j++) {
        body += '<li>' + _htmlEscape(f.score_reasons[j]) + '</li>';
      }
      body += '</ul>';
    }
    body += '<h4>Original</h4><pre>' + _htmlEscape(f.original || '') + '</pre>';
    if (f.decoded && f.decoded !== f.original) {
      body += '<h4>Decoded</h4><pre>' + _htmlEscape(f.decoded) + '</pre>';
    }
    if (f.decoding_steps && f.decoding_steps.length) {
      body += '<h4>Decoding Steps</h4><pre>';
      for (var k = 0; k < f.decoding_steps.length; k++) {
        body += _htmlEscape(f.decoding_steps[k].method) + ': ' + _htmlEscape(f.decoding_steps[k].result) + '\\n';
      }
      body += '</pre>';
    }
    if (f.metadata && Object.keys(f.metadata).length) {
      body += '<h4>Metadata</h4><pre>';
      for (var mk in f.metadata) {
        body += _htmlEscape(mk) + ': ' + _htmlEscape(f.metadata[mk]) + '\\n';
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
    result=None,
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
        result: Optional AnalysisResult with all Phase 2 data.
    """
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration_str = f"{duration_seconds:.2f}s" if duration_seconds > 0 else "< 0.01s"

    # Serialize findings to base64-encoded JSON for safe JavaScript embedding
    findings_b64 = _json_b64_for_js(findings)

    # Serialize additional Phase 2 data
    artifacts_b64 = _json_b64_for_js(
        [a.to_dict() for a in result.artifacts] if result and result.artifacts else []
    )
    timeline_b64 = _json_b64_for_js(
        [e.to_dict() for e in result.timeline] if result and result.timeline else []
    )
    network_b64 = _json_b64_for_js(
        {
            "nodes": [n.to_dict() for n in result.nodes] if result and result.nodes else [],
            "edges": [e.to_dict() for e in result.edges] if result and result.edges else [],
        }
    )
    profile_b64 = _json_b64_for_js(
        result.profile.to_dict() if result and result.profile else {}
    )

    html_content = _HTML_TEMPLATE
    html_content = html_content.replace("{{PCAP_NAME}}", _escape(pcap_name))
    html_content = html_content.replace("{{SCAN_TIME}}", _escape(scan_time))
    html_content = html_content.replace("{{DURATION}}", _escape(duration_str))
    html_content = html_content.replace("{{TOTAL}}", _escape(str(len(findings))))
    html_content = html_content.replace("{{FINDINGS_B64}}", findings_b64)
    html_content = html_content.replace("{{ARTIFACTS_B64}}", artifacts_b64)
    html_content = html_content.replace("{{TIMELINE_B64}}", timeline_b64)
    html_content = html_content.replace("{{NETWORK_B64}}", network_b64)
    html_content = html_content.replace("{{PROFILE_B64}}", profile_b64)

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    except Exception as exc:
        logger.warning("Failed to write HTML report to %s: %s", output_path, exc)
