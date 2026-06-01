'use strict';

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
  packets: [],
  alerts: [],
  filteredPackets: [],
  selectedPacket: null,
  filter: '',
  autoScroll: true,
  sortCol: 'id',
  sortAsc: true,
  running: false,
  paused: false,
  protocolStats: {},
  trafficHistory: [],
  threatCounts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
  charts: {},
  totalBytes: 0,
  lastBps: 0,
  datasetReportLoaded: false,
};

// ─── Socket ───────────────────────────────────────────────────────────────────
const socket = io();

socket.on('connect', () => {
  console.log('[WS] Connected');
  toast('info', '🔌 Connected', 'Dashboard connected to IDS server');
});

socket.on('disconnect', () => {
  toast('high', '⚠ Disconnected', 'Lost connection to IDS server');
  setCaptureBtns(false, false);
});

socket.on('init', (data) => {
  state.protocolStats = data.protocol_stats || {};
  state.trafficHistory = data.traffic_history || [];
  updateStatus(data.status);
  renderSidebarRules(data.rules || []);
  
  if (data.detectors) {
    renderDetectors(data.detectors);
  }
  
  if (data.rules_files) {
    populateRulesDropdown(data.rules_files, data.selected_rules_file);
  }
  
  if (data.recent_packets) {
    data.recent_packets.forEach(p => addPacket(p, false));
    renderPackets();
  }
  if (data.recent_alerts) {
    data.recent_alerts.forEach(a => addAlert(a));
    updateAlertCount();
  }
  initCharts();
  updateCharts();
});

socket.on('detector_status_changed', (data) => {
  if (data.detectors) {
    renderDetectors(data.detectors);
  }
  if (data.status) {
    updateStatus(data.status);
  }
  toast('info', '🛡 Detector Updated', `${data.id} is now ${data.enabled ? 'Enabled' : 'Disabled'}`);
});

socket.on('packet', (pkt) => {
  addPacket(pkt, true);
});

socket.on('alert', (alert) => {
  addAlert(alert);
  showAlertToast(alert);
  updateAlertCount();
  updateThreatLevel();
});

socket.on('traffic_update', (data) => {
  if (data.protocol_stats) state.protocolStats = data.protocol_stats;
  if (data.traffic) {
    state.trafficHistory.push(data.traffic);
    if (state.trafficHistory.length > 60) state.trafficHistory.shift();
    if (data.traffic.bps !== undefined) state.lastBps = data.traffic.bps;
    if (data.traffic.total !== undefined) {
      const avgSize = data.traffic.total > 0 ? Math.round(state.totalBytes / data.traffic.total) : 0;
      state.avgPacketSize = avgSize;
    }
  }
  if (data.total_bytes !== undefined) state.totalBytes = data.total_bytes;
  if (data.threat_stats) state.threatCounts = data.threat_stats;
  if (data.status) updateStatus(data.status);
  updateCharts();
  updateCounters();
});

socket.on('status_update', (status) => {
  updateStatus(status);
});

socket.on('cleared', () => {
  state.packets = [];
  state.filteredPackets = [];
  state.alerts = [];
  state.threatCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  state.trafficHistory = [];
  state.totalBytes = 0;
  state.lastBps = 0;
  renderPackets();
  el('alert-tbody').innerHTML = '';
  el('sb-alerts-list').innerHTML = '<div class="empty-state">No alerts detected</div>';
  updateAlertCount();
  updateThreatLevel();
  updateCharts();
});

socket.on('pcap_loaded', (data) => {
  // A .pcap was opened server-side — refresh the whole view from the API.
  Promise.all([
    fetch('/api/packets?limit=2000').then(r => r.json()),
    fetch('/api/alerts').then(r => r.json()),
  ]).then(([packets, alerts]) => {
    // reset client-side view
    state.packets = [];
    state.filteredPackets = [];
    state.alerts = [];
    state.threatCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    el('alert-tbody').innerHTML = '';
    const sb = el('sb-alerts-list');
    if (sb) sb.innerHTML = '';

    (packets || []).forEach(p => addPacket(p, false));
    renderPackets();
    (alerts || []).forEach(a => addAlert(a));
    updateAlertCount();
    updateThreatLevel();
    updateCounters();
    updateCharts();
    if (sb && !sb.innerHTML.trim()) sb.innerHTML = '<div class="empty-state">No alerts detected</div>';
  }).catch(() => {});
});

socket.on('rules_loaded', (data) => {
  renderSidebarRules(data.rules || []);
  if (data.rules_files) {
    populateRulesDropdown(data.rules_files, data.selected_rules_file);
  }
  if (data.selected_rules_file) {
    const sbr = el('sb-selected-rules');
    if (sbr) sbr.textContent = data.selected_rules_file;
    const rfd = el('rules-file-dropdown');
    if (rfd) rfd.value = data.selected_rules_file;
  }
  toast('info', '📜 Rules Loaded', `${data.count} rules loaded`);
  if (el('tab-rules').classList.contains('active')) {
    loadRulesTab();
  }
});

socket.on('capture_error', (data) => {
  toast('high', '⚠ Capture Error', data.error || 'Failed to capture packets');
  setCaptureBtns(false, false);
});

// ─── Packet Management ────────────────────────────────────────────────────────
function addPacket(pkt, live) {
  state.packets.push(pkt);
  if (state.packets.length > 2000) state.packets.shift();

  if (pkt.threat) {
    state.threatCounts[pkt.threat] = (state.threatCounts[pkt.threat] || 0) + 1;
  }

  if (matchesFilter(pkt, state.filter)) {
    state.filteredPackets.push(pkt);
    if (live) {
      appendPacketRow(pkt);
      if (state.autoScroll) scrollBottom();
    }
  }
}

function matchesFilter(pkt, filter) {
  if (!filter) return true;
  const f = filter.toLowerCase();
  return (
    pkt.src_ip.includes(f) ||
    pkt.dst_ip.includes(f) ||
    pkt.proto.toLowerCase().includes(f) ||
    (pkt.info || '').toLowerCase().includes(f) ||
    String(pkt.id).includes(f) ||
    (pkt.threat || '').toLowerCase().includes(f) ||
    f.startsWith('port ') && (
      String(pkt.src_port || '').includes(f.slice(5)) ||
      String(pkt.dst_port || '').includes(f.slice(5))
    ) ||
    f === 'tcp' && pkt.proto === 'TCP' ||
    f === 'udp' && pkt.proto === 'UDP' ||
    f === 'icmp' && pkt.proto === 'ICMP' ||
    f === 'http' && pkt.proto === 'HTTP' ||
    f === 'dns' && pkt.proto === 'DNS' ||
    f === 'alert' && pkt.is_alert ||
    f === 'critical' && pkt.threat === 'CRITICAL'
  );
}

// ─── Rendering ────────────────────────────────────────────────────────────────
function renderPackets() {
  const tbody = el('packet-tbody');
  tbody.innerHTML = '';
  const sorted = getSortedPackets();
  sorted.forEach(p => appendPacketRow(p, false));
  if (state.autoScroll) scrollBottom();
}

function getSortedPackets() {
  const col = state.sortCol;
  const asc = state.sortAsc ? 1 : -1;
  return [...state.filteredPackets].sort((a, b) => {
    let va = a[col], vb = b[col];
    if (col === 'id' || col === 'length') { va = +va; vb = +vb; }
    return va < vb ? -asc : va > vb ? asc : 0;
  });
}

function appendPacketRow(pkt, scrollLast = true) {
  const tbody = el('packet-tbody');
  const tr = document.createElement('tr');

  const rowClass = pkt.threat === 'CRITICAL' ? 'row-critical' :
                   pkt.threat === 'HIGH'     ? 'row-high' :
                   pkt.threat === 'MEDIUM'   ? 'row-medium' : '';
  if (rowClass) tr.className = rowClass;
  tr.dataset.id = pkt.id;
  tr.onclick = () => selectPacket(pkt, tr);

  tr.innerHTML = `
    <td class="col-no">${pkt.id}</td>
    <td class="col-ts" style="font-family:monospace">${pkt.ts}</td>
    <td class="col-src">${pkt.src_ip}</td>
    <td class="col-dst">${pkt.dst_ip}</td>
    <td class="col-proto"><span class="proto-${pkt.proto}">${pkt.proto}</span></td>
    <td class="col-len" style="text-align:right">${pkt.length}</td>
    <td class="col-threat"><span class="threat-badge threat-${pkt.threat}">${pkt.threat}</span></td>
    <td class="col-info" title="${escHtml(pkt.info || '')}">${escHtml(pkt.info || '')}</td>
  `;
  tbody.appendChild(tr);
}

function selectPacket(pkt, tr) {
  document.querySelectorAll('#packet-tbody tr.selected').forEach(r => r.classList.remove('selected'));
  if (tr) tr.classList.add('selected');
  state.selectedPacket = pkt;
  renderDetailTree(pkt);
  renderHex(pkt);
  el('detail-hint').textContent = `Packet #${pkt.id} — ${pkt.proto} ${pkt.src_ip} → ${pkt.dst_ip}`;
}

function renderDetailTree(pkt) {
  const tree = el('detail-tree');
  if (!pkt.layers || pkt.layers.length === 0) {
    tree.innerHTML = '<div class="empty-state">No layer data</div>';
    return;
  }
  tree.innerHTML = pkt.layers.map((layer, i) => `
    <div class="tree-node">
      <div class="tree-header" onclick="toggleTree('tree-body-${pkt.id}-${i}')">
        <span class="tree-toggle" id="tree-arrow-${pkt.id}-${i}">▶</span>
        <span>${escHtml(layer.name)}</span>
      </div>
      <div class="tree-body" id="tree-body-${pkt.id}-${i}">
        ${(layer.fields || []).map(f => `
          <div class="tree-field">
            <span class="tree-field-key">${escHtml(f.key)}:</span>
            <span class="tree-field-val">${escHtml(f.value)}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');
  // Open first layer by default
  const firstBody = el(`tree-body-${pkt.id}-0`);
  if (firstBody) { firstBody.classList.add('open'); }
  const firstArrow = el(`tree-arrow-${pkt.id}-0`);
  if (firstArrow) firstArrow.textContent = '▼';
}

function toggleTree(id) {
  const body = el(id);
  if (!body) return;
  const arrowId = id.replace('tree-body-', 'tree-arrow-');
  const arrow = el(arrowId);
  body.classList.toggle('open');
  if (arrow) arrow.textContent = body.classList.contains('open') ? '▼' : '▶';
}

function renderHex(pkt) {
  const hb = el('hex-body');
  if (!pkt.hex || pkt.hex.length === 0) {
    hb.innerHTML = '<div class="empty-state">No hex data</div>';
    return;
  }
  hb.innerHTML = pkt.hex.map(row => `
    <div class="hex-row">
      <span class="hex-offset">${row.offset}</span>
      <span class="hex-data">${escHtml(row.hex)}</span>
      <span class="hex-ascii">${escHtml(row.ascii)}</span>
    </div>
  `).join('');
}

// ─── Alerts ───────────────────────────────────────────────────────────────────
function addAlert(alert) {
  state.alerts.push(alert);
  if (state.alerts.length > 500) state.alerts.shift();

  const tbody = el('alert-tbody');
  const tr = document.createElement('tr');
  const rowClass = alert.threat === 'CRITICAL' ? 'row-critical' :
                   alert.threat === 'HIGH' ? 'row-high' : 'row-medium';
  tr.className = rowClass;
  tr.innerHTML = `
    <td>${alert.id}</td>
    <td style="font-family:monospace">${alert.ts}</td>
    <td><strong>${escHtml(alert.type || '')}</strong></td>
    <td><span class="threat-badge threat-${alert.threat}">${alert.threat}</span></td>
    <td>${escHtml(alert.src || '')}</td>
    <td>${escHtml(alert.dst || '')}</td>
    <td><span class="proto-${alert.proto}">${alert.proto || ''}</span></td>
    <td style="font-size:11px;color:var(--text2)">${escHtml(alert.rule || alert.detail || alert.info || '')}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);

  // Sidebar alert item
  const list = el('sb-alerts-list');
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  const item = document.createElement('div');
  item.className = `sb-alert-item ${alert.threat}`;
  item.innerHTML = `
    <div class="sb-alert-top">
      <span class="sai-type">${escHtml(alert.type || 'Intrusion')}</span>
      <span class="sai-time">${alert.ts}</span>
    </div>
    <div class="sai-detail">${escHtml(alert.src || '')} → ${escHtml(alert.dst || '')} | ${escHtml(alert.rule || alert.info || '')}</div>
  `;
  list.insertBefore(item, list.firstChild);
  while (list.children.length > 15) list.removeChild(list.lastChild);
}

function showAlertToast(alert) {
  const level = (alert.threat || 'MEDIUM').toLowerCase();
  const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
  toast(level, `${icons[level] || '⚠'} ${alert.type || 'Alert'}`,
    `${alert.src} → ${alert.dst} | ${alert.rule || alert.info || ''}`);
}

function updateAlertCount() {
  const n = state.alerts.length;
  el('badge-alerts').textContent = n > 0 ? n : '';
  el('sb-alert-count').textContent = n;
  el('sb-alerts').textContent = n;
  el('alerts-count-label').textContent = `${n} alerts`;
}

function updateThreatLevel() {
  const d = el('threat-level-display');
  const recent = state.alerts.slice(-30);
  let level = 'LOW';
  if (recent.some(a => a.threat === 'CRITICAL')) level = 'CRITICAL';
  else if (recent.some(a => a.threat === 'HIGH')) level = 'HIGH';
  else if (recent.some(a => a.threat === 'MEDIUM')) level = 'MEDIUM';

  d.textContent = level;
  d.className = `threat-level ${level}`;
  document.body.dataset.threat = level.toLowerCase();

  document.querySelectorAll('.tm-seg').forEach(s => s.classList.remove('active'));
  const map = { LOW: 'tm-low', MEDIUM: 'tm-med', HIGH: 'tm-high', CRITICAL: 'tm-crit' };
  const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const idx = order.indexOf(level);
  order.slice(0, idx + 1).forEach(l => {
    const segs = document.querySelectorAll(`.${map[l]}`);
    segs.forEach(s => s.classList.add('active'));
  });
}

function clearAlerts() {
  state.alerts = [];
  el('alert-tbody').innerHTML = '';
  el('sb-alerts-list').innerHTML = '<div class="empty-state">No alerts detected</div>';
  updateAlertCount();
  updateThreatLevel();
}

// ─── Status & Controls ────────────────────────────────────────────────────────
function updateStatus(status) {
  if (!status) return;
  state.running = status.running;
  state.paused = status.paused;

  el('sb-packets').textContent = status.packet_count || 0;
  el('sb-filtered').textContent = status.filtered_count || 0;
  el('sb-alerts').textContent = status.alert_count || 0;
  el('sb-interface').textContent = status.live_capture_mode ? `${status.interface} (live)` : `${status.interface} (simulated)`;
  el('uptime-display').textContent = status.uptime || '00:00:00';

  if (status.live_capture_mode !== undefined) {
    const isLive = status.live_capture_mode;
    const simBtn = el('mode-btn-sim');
    const liveBtn = el('mode-btn-live');
    if (simBtn) simBtn.classList.toggle('active', !isLive);
    if (liveBtn) liveBtn.classList.toggle('active', isLive);
  }
  
  if (status.active_detectors_count !== undefined) {
    const ad = el('sb-active-detectors');
    if (ad) ad.textContent = status.active_detectors_count;
    const sdc = el('sb-detectors-count');
    if (sdc) sdc.textContent = status.active_detectors_count;
  }
  
  if (status.selected_rules_file !== undefined) {
    const sr = el('sb-selected-rules');
    if (sr) sr.textContent = status.selected_rules_file;
    const rfd = el('rules-file-dropdown');
    if (rfd) rfd.value = status.selected_rules_file;
  }

  const dot = el('ci-dot');
  const label = el('ci-label');
  if (status.running && !status.paused) {
    dot.className = 'ci-dot running';
    label.textContent = 'Capturing';
    el('sb-status').textContent = 'Live capture in progress…';
  } else if (status.paused) {
    dot.className = 'ci-dot paused';
    label.textContent = 'Paused';
    el('sb-status').textContent = 'Capture paused';
  } else {
    dot.className = 'ci-dot';
    label.textContent = 'Idle';
    el('sb-status').textContent = 'Idle — press Start to begin capture';
  }

  setCaptureBtns(status.running, status.paused);
  updateCounters();
}

function setCaptureBtns(running, paused) {
  el('btn-start').disabled  = running && !paused;
  el('btn-stop').disabled   = !running;
  el('btn-pause').disabled  = !running;
  el('btn-pause').textContent = paused ? 'Resume' : 'Pause';
  const pauseIcon = el('btn-pause').querySelector('svg');
  if (pauseIcon && paused) {
    pauseIcon.innerHTML = '<polygon points="5,3 19,12 5,21"/>';
  } else if (pauseIcon) {
    pauseIcon.innerHTML = '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>';
  }
}

function startCapture()   { socket.emit('start_capture'); }
function stopCapture()    { socket.emit('stop_capture'); }
function pauseCapture()   { socket.emit('pause_capture'); }
function restartCapture() { socket.emit('restart_capture'); }

// ─── Filter ───────────────────────────────────────────────────────────────────
function onFilterInput(val) {
  const wrap = el('filter-wrap');
  const hint = el('filter-hint');
  if (!val) {
    wrap.className = 'filter-input-wrap';
    hint.textContent = '';
    return;
  }
  // Simple validation
  const valid = /^[\w\s\.\*:!\[\]\-\>\<"'\/]+$/i.test(val);
  wrap.className = 'filter-input-wrap ' + (valid ? 'valid' : 'invalid');
  hint.textContent = valid ? '✓ Valid filter' : '✗ Invalid expression';
  hint.style.color = valid ? 'var(--green)' : 'var(--red)';
}

function applyFilter() {
  const val = el('filter-input').value.trim();
  state.filter = val.toLowerCase();
  state.filteredPackets = state.packets.filter(p => matchesFilter(p, state.filter));
  renderPackets();
  el('sb-filtered').textContent = state.filteredPackets.length;
  el('sb-filter-active').textContent = val ? `Filter: ${val}` : '';
  socket.emit('set_filter', { filter: val });
}

function clearFilter() {
  el('filter-input').value = '';
  state.filter = '';
  state.filteredPackets = [...state.packets];
  renderPackets();
  el('filter-wrap').className = 'filter-input-wrap';
  el('filter-hint').textContent = '';
  el('sb-filter-active').textContent = '';
  el('sb-filtered').textContent = state.filteredPackets.length;
}

// ─── Sorting ──────────────────────────────────────────────────────────────────
function sortTable(col) {
  if (state.sortCol === col) state.sortAsc = !state.sortAsc;
  else { state.sortCol = col; state.sortAsc = true; }

  document.querySelectorAll('.sort-arrow').forEach(s => s.textContent = '');
  const arrow = el(`sort-${col}`);
  if (arrow) arrow.textContent = state.sortAsc ? ' ▲' : ' ▼';

  renderPackets();
}

// ─── Tab Switching ────────────────────────────────────────────────────────────
function showTab(tab) {
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  const content = el(`tab-${tab}`);
  if (content) content.classList.add('active');

  if (tab === 'stats') { updateCharts(); loadDatasetReport(); }
}

// ─── Charts ───────────────────────────────────────────────────────────────────
const PROTO_COLORS = {
  TCP: '#388bfd', UDP: '#3fb950', ICMP: '#f0883e',
  HTTP: '#a371f7', DNS: '#39d353', OTHER: '#6e7681',
};

function initCharts() {
  Chart.defaults.color = '#8b949e';
  Chart.defaults.borderColor = '#30363d';

  // Proto donut
  const cp = el('chart-proto');
  if (cp && !state.charts.proto) {
    state.charts.proto = new Chart(cp, {
      type: 'doughnut',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 1, borderColor: '#0d1117' }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { boxWidth: 12, font: { size: 11 } } } },
      },
    });
  }

  // Traffic line
  const ct = el('chart-traffic');
  if (ct && !state.charts.traffic) {
    state.charts.traffic = new Chart(ct, {
      type: 'line',
      data: { labels: [], datasets: [{
        label: 'pkt/s', data: [],
        borderColor: '#388bfd', backgroundColor: 'rgba(56,139,253,0.1)',
        borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4,
      }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { ticks: { maxTicksLimit: 6 } }, y: { min: 0 } },
      },
    });
  }

  // Threat bar
  const cth = el('chart-threat');
  if (cth && !state.charts.threat) {
    state.charts.threat = new Chart(cth, {
      type: 'bar',
      data: {
        labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        datasets: [{
          label: 'Packets',
          data: [0, 0, 0, 0],
          backgroundColor: ['rgba(63,185,80,0.7)', 'rgba(210,153,34,0.7)', 'rgba(219,109,40,0.7)', 'rgba(248,81,73,0.7)'],
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { }, y: { min: 0 } },
      },
    });
  }

  // Bandwidth line
  const cb = el('chart-bw');
  if (cb && !state.charts.bw) {
    state.charts.bw = new Chart(cb, {
      type: 'line',
      data: { labels: [], datasets: [{
        label: 'bytes/s', data: [],
        borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.08)',
        borderWidth: 2, pointRadius: 0, fill: true, tension: 0.4,
      }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { maxTicksLimit: 6 } },
          y: { min: 0, ticks: { callback: v => fmtBytes(v) + '/s' } },
        },
      },
    });
  }

  // Mini traffic
  const mt = el('mini-chart-traffic');
  if (mt && !state.charts.mini) {
    state.charts.mini = new Chart(mt, {
      type: 'line',
      data: { labels: [], datasets: [{
        data: [], borderColor: '#388bfd', backgroundColor: 'rgba(56,139,253,0.15)',
        borderWidth: 1.5, pointRadius: 0, fill: true, tension: 0.4,
      }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { display: false },
          y: { display: false, min: 0 },
        },
      },
    });
  }
}

function updateCharts() {
  const ps = state.protocolStats || {};

  // Proto donut
  if (state.charts.proto) {
    const labels = Object.keys(ps);
    const data   = Object.values(ps);
    const colors = labels.map(l => PROTO_COLORS[l] || '#6e7681');
    state.charts.proto.data.labels = labels;
    state.charts.proto.data.datasets[0].data = data;
    state.charts.proto.data.datasets[0].backgroundColor = colors;
    state.charts.proto.update('none');
  }

  // Traffic line
  if (state.charts.traffic && state.trafficHistory.length) {
    const labels = state.trafficHistory.map(t => t.ts);
    const data   = state.trafficHistory.map(t => t.pps);
    state.charts.traffic.data.labels = labels;
    state.charts.traffic.data.datasets[0].data = data;
    state.charts.traffic.update('none');
  }

  // Threat bar
  if (state.charts.threat) {
    const tc = state.threatCounts;
    state.charts.threat.data.datasets[0].data = [tc.LOW||0, tc.MEDIUM||0, tc.HIGH||0, tc.CRITICAL||0];
    state.charts.threat.update('none');
  }

  // Bandwidth line
  if (state.charts.bw && state.trafficHistory.length) {
    const labels = state.trafficHistory.slice(-60).map(t => t.ts);
    const data   = state.trafficHistory.slice(-60).map(t => t.bps || 0);
    state.charts.bw.data.labels = labels;
    state.charts.bw.data.datasets[0].data = data;
    state.charts.bw.update('none');
  }

  // Mini traffic
  if (state.charts.mini && state.trafficHistory.length) {
    const data = state.trafficHistory.slice(-20).map(t => t.pps);
    state.charts.mini.data.labels = data.map((_, i) => i);
    state.charts.mini.data.datasets[0].data = data;
    state.charts.mini.update('none');
  }

  // Mini proto list
  const mpl = el('mini-proto-list');
  if (mpl) {
    mpl.innerHTML = Object.entries(ps).map(([proto, cnt]) => `
      <div class="mpl-item">
        <div class="mpl-dot" style="background:${PROTO_COLORS[proto]||'#6e7681'}"></div>
        <span class="mpl-label">${proto}</span>
        <span class="mpl-count">${cnt}</span>
      </div>
    `).join('');
  }
}

function fmtBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function updateCounters() {
  const ps = state.protocolStats || {};
  const tc = state.threatCounts || {};
  setEl('cnt-total', state.packets.length);
  setEl('cnt-alerts', state.alerts.length);
  setEl('cnt-bytes', fmtBytes(state.totalBytes || 0));
  const pktTotal = state.packets.length;
  const avgBps = state.trafficHistory.length
    ? Math.round(state.trafficHistory.slice(-5).reduce((s, t) => s + (t.bps || 0), 0) / Math.min(state.trafficHistory.length, 5))
    : 0;
  setEl('cnt-bps', fmtBytes(avgBps) + '/s');
  setEl('cnt-threat-low',  tc.LOW      || 0);
  setEl('cnt-threat-med',  tc.MEDIUM   || 0);
  setEl('cnt-threat-high', tc.HIGH     || 0);
  setEl('cnt-threat-crit', tc.CRITICAL || 0);
  setEl('cnt-tcp',  ps.TCP   || 0);
  setEl('cnt-udp',  ps.UDP   || 0);
  setEl('cnt-http', ps.HTTP  || 0);
  setEl('cnt-dns',  ps.DNS   || 0);
  setEl('cnt-tls',  ps.TLS   || 0);
  setEl('cnt-ssh',  ps.SSH   || 0);
  setEl('cnt-icmp', ps.ICMP  || 0);
  setEl('cnt-arp',  ps.ARP   || 0);
}

// ─── Dataset Report ───────────────────────────────────────────────────────────
async function loadDatasetReport() {
  if (state.datasetReportLoaded) return;
  try {
    const r = await fetch('/api/dataset-report');
    const d = await r.json();
    if (!d.success) return;
    state.datasetReportLoaded = true;
    _renderDatasetTable(d.classes);
    _renderDatasetChart(d.classes);
  } catch (e) { console.error('dataset-report error', e); }
}

function _renderDatasetTable(classes) {
  const tbody = el('rpt-tbody');
  if (!tbody) return;
  tbody.innerHTML = classes.map((c, i) => `
    <tr class="${c.is_benign ? 'rpt-row-benign' : ''}">
      <td class="rpt-td-num">${i + 1}</td>
      <td class="rpt-td-name">${escHtml(c.name)}</td>
      <td class="rpt-td-cnt">${c.count.toLocaleString()}</td>
      <td class="rpt-td-pct">
        <div class="rpt-bar-wrap">
          <div class="rpt-bar ${c.is_benign ? 'rpt-bar-benign' : 'rpt-bar-attack'}" style="width:${Math.min(c.pct / 40 * 100, 100)}%"></div>
          <span class="rpt-bar-lbl">${c.pct >= 0.001 ? c.pct.toFixed(c.pct >= 1 ? 2 : 4) : '<0.001'}%</span>
        </div>
      </td>
    </tr>
  `).join('');
}

function _renderDatasetChart(classes) {
  const canvas = el('chart-dataset');
  if (!canvas || state.charts.dataset) return;
  const top12 = classes.slice(0, 12);
  const colors = top12.map(c => c.is_benign
    ? 'rgba(63,185,80,0.82)'
    : 'rgba(248,81,73,0.75)'
  );
  state.charts.dataset = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: top12.map(c => c.name),
      datasets: [{
        label: 'Samples',
        data: top12.map(c => c.count),
        backgroundColor: colors,
        borderWidth: 0,
        borderRadius: 4,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.parsed.x.toLocaleString()} samples (${top12[ctx.dataIndex].pct.toFixed(2)}%)`,
          },
        },
      },
      scales: {
        x: { min: 0, ticks: { callback: v => v >= 1000 ? (v / 1000).toFixed(0) + 'k' : v } },
        y: { ticks: { font: { size: 10 }, maxRotation: 0 } },
      },
    },
  });
}

// ─── Rules ────────────────────────────────────────────────────────────────────
function renderSidebarRules(rules) {
  const list = el('sb-rules-list');
  const count = el('sb-rules-count');
  if (!rules || rules.length === 0) {
    list.innerHTML = '<div class="empty-state">No rules loaded</div>';
    count.textContent = 0;
    return;
  }
  count.textContent = rules.length;
  list.innerHTML = rules.map(r => `<div class="sb-rule-item" title="${escHtml(r)}">${escHtml(r)}</div>`).join('');
}

async function loadRulesTab() {
  const resp = await fetch('/api/rules');
  const rules = await resp.json();
  const container = el('rules-list');
  if (!rules.length) { container.innerHTML = '<div class="empty-state">No rules found</div>'; return; }

  let html = '';
  let lastFile = null;
  rules.forEach(r => {
    if (r.file !== lastFile) {
      html += `<div class="rule-file-header">${escHtml(r.file)}</div>`;
      lastFile = r.file;
    }
    if (r.is_empty) return;
    const cls = r.is_comment ? 'rule-comment' : 'rule-text';
    html += `<div class="rule-row">
      <span class="rule-num">${r.line}</span>
      <span class="${cls}">${escHtml(r.text)}</span>
    </div>`;
  });
  container.innerHTML = html;
}

async function validateRuleInline() {
  const input = el('rule-validate-input');
  const result = el('rule-validate-result');
  const val = input.value.trim();
  if (!val) { result.textContent = 'Enter a rule'; result.className = 'err'; return; }
  const resp = await fetch('/api/rules/validate', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ rule: val }),
  });
  const data = await resp.json();
  if (data.valid) {
    result.textContent = `✓ Valid — ${data.parsed}`;
    result.className = 'ok';
  } else {
    result.textContent = `✗ ${data.error}`;
    result.className = 'err';
  }
}

// ─── Modal ────────────────────────────────────────────────────────────────────
function showModal(id) { el(id).classList.add('open'); }
function closeModal(id) { el(id).classList.remove('open'); }

async function validateRule() {
  const input = el('modal-rule-input');
  const result = el('modal-rule-result');
  const val = input.value.trim();
  if (!val) { result.textContent = 'Please enter a rule.'; result.className = 'modal-result err'; return; }
  const resp = await fetch('/api/rules/validate', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ rule: val }),
  });
  const data = await resp.json();
  result.className = 'modal-result ' + (data.valid ? 'ok' : 'err');
  result.textContent = data.valid ? `✓ Valid  — Parsed: ${data.parsed}` : `✗ Invalid: ${data.error}`;
}

function useExample(el_) {
  el('modal-rule-input').value = el_.textContent.replace(/→/g, '->').replace(/&gt;/g, '>').replace(/&lt;/g, '<');
  el('modal-rule-result').textContent = '';
  el('modal-rule-result').className = 'modal-result';
}

// ─── Panel toggles ────────────────────────────────────────────────────────────
function togglePanel(id) {
  const panel = el(id);
  if (panel) panel.style.display = panel.style.display === 'none' ? '' : 'none';
}

function toggleTheme() {
  document.documentElement.classList.toggle('light');
}

// ─── Interface picker (Wireshark-style) ──────────────────────────────────────
let _interfaces = [];
let _selectedIface = null;

async function loadInterfaces(showToast = false) {
  try {
    const resp = await fetch('/api/interfaces');
    _interfaces = await resp.json();
    const label = el('iface-current-label');
    const active = _interfaces.find(i => i.active);
    if (active) {
      const displayName = active.friendly_name || active.name;
      label.textContent = active.ip ? `${displayName} (${active.ip})` : displayName;
    } else if (_interfaces.length) {
      const displayName = _interfaces[0].friendly_name || _interfaces[0].name;
      label.textContent = displayName;
    } else {
      label.textContent = 'no interfaces';
    }
    renderInterfaceList(_interfaces);
    updateSandboxBanner();
    if (showToast) toast('info', '↻ Refreshed', `${_interfaces.length} interfaces found`);
  } catch (e) {
    console.warn('Could not load interfaces:', e);
    el('iface-current-label').textContent = 'no interfaces';
  }
}

function updateSandboxBanner() {
  const banner = el('iface-banner');
  if (!banner) return;
  // "Looks like a sandbox" = no recognizably-physical adapter names.
  // Real machines almost always expose at least one Wi-Fi or Ethernet-style
  // name (en0, wlan0, Wi-Fi, Ethernet, eth1+, wlp*, enp*, Local Area Connection).
  const physicalRe = /^(wl|wlan|wlp|wifi|wi-fi|ethernet|eth[1-9]|en[0-9]|enp|eno|ens|local area connection)/i;
  const hasPhysical = _interfaces.some(i => !i.loopback && physicalRe.test(i.name));
  banner.style.display = hasPhysical ? 'none' : 'flex';
}

function ifaceIcon(iface) {
  if (iface.loopback) {
    return '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zm0 14a6 6 0 1 1 0-12 6 6 0 0 1 0 12zm-1-9h2v2h-2zm0 4h2v4h-2z"/></svg>';
  }
  const n = (iface.name || '').toLowerCase();
  if (n.includes('wl') || n.includes('wifi') || n.includes('wlan')) {
    return '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z"/></svg>';
  }
  return '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M3 5h18v10H3zm0 12h18v2H3zm6-3h6v-2H9z"/></svg>';
}

function drawSparkline(canvas, isLoopback, isActive) {
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  
  const points = [];
  const steps = 14;
  const mid = h / 2;
  
  // Initialize points
  for (let i = 0; i <= steps; i++) {
    points.push(mid);
  }
  
  function animate() {
    if (!document.body.contains(canvas)) return; // Stop animation if canvas was removed
    
    ctx.clearRect(0, 0, w, h);
    ctx.beginPath();
    
    // Wireshark look: active gets a crisp glowing line, inactive is a soft line
    ctx.strokeStyle = isActive ? 'rgba(25, 199, 242, 0.9)' : 'rgba(167, 183, 206, 0.4)';
    ctx.lineWidth = 1.25;
    ctx.lineJoin = 'round';
    
    const stepW = w / steps;
    ctx.moveTo(0, points[0]);
    for (let i = 1; i <= steps; i++) {
      ctx.lineTo(i * stepW, points[i]);
    }
    ctx.stroke();
    
    // Slide points to left and calculate next point
    points.shift();
    let nextPoint;
    if (isActive) {
      // Active interface gets beautiful, realistic jagged fluctuations (live activity)
      nextPoint = Math.random() * (h - 2) + 1;
    } else if (isLoopback) {
      // Loopback gets minor, occasional spikes
      nextPoint = Math.random() > 0.85 ? Math.random() * (h - 2) + 1 : mid + (Math.random() - 0.5) * 2;
    } else {
      // Idle interface has very minor, steady fluctuations
      nextPoint = mid + (Math.random() - 0.5) * 2.5;
    }
    points.push(nextPoint);
    
    setTimeout(() => {
      if (document.body.contains(canvas)) {
        requestAnimationFrame(animate);
      }
    }, 140);
  }
  
  animate();
}

function renderInterfaceList(list) {
  const container = el('iface-list');
  if (!list.length) {
    container.innerHTML = '<div class="iface-empty">No interfaces found.</div>';
    el('iface-count').textContent = '0 interfaces';
    return;
  }
  // Build rows as DOM nodes so interface names never touch innerHTML interpolation.
  container.innerHTML = '';
  for (const i of list) {
    const row = document.createElement('div');
    row.className = 'iface-row' + (_selectedIface === i.name ? ' selected' : '');
    row.dataset.iface = i.name;

    const nameCell = document.createElement('div');
    nameCell.className = 'iface-name-cell';
    const iconSpan = document.createElement('span');
    iconSpan.className = 'ifr-icon';
    iconSpan.innerHTML = ifaceIcon(i);
    const nameSpan = document.createElement('span');
    nameSpan.className = 'ifr-name';
    nameSpan.textContent = i.friendly_name || i.name;
    nameCell.append(iconSpan, nameSpan);
    if (i.active) {
      const b = document.createElement('span');
      b.className = 'ifr-badge active';
      b.textContent = 'Active';
      nameCell.appendChild(b);
    }
    if (i.loopback) {
      const b = document.createElement('span');
      b.className = 'ifr-badge loop';
      b.textContent = 'Loopback';
      nameCell.appendChild(b);
    }

    const trafficCell = document.createElement('div');
    trafficCell.className = 'ifr-traffic';
    const spark = document.createElement('canvas');
    spark.className = 'ifr-spark';
    spark.width = 80;
    spark.height = 16;
    trafficCell.appendChild(spark);
    
    // Draw the sparkline on canvas
    const hasIP = i.ip && i.ip.length > 0;
    const isActive = hasIP && !i.loopback;
    setTimeout(() => drawSparkline(spark, i.loopback, isActive), 10);

    const addrCell = document.createElement('div');
    addrCell.className = 'ifr-addrs';
    const v4 = (i.ipv4 || []);
    const v6 = (i.ipv6 || []).slice(0, 1);
    if (!v4.length && !v6.length) {
      const s = document.createElement('span');
      s.className = 'addr-none';
      s.textContent = 'No address';
      addrCell.appendChild(s);
    } else {
      for (const a of v4) {
        const s = document.createElement('span');
        s.className = 'addr-v4';
        s.textContent = a;
        addrCell.appendChild(s);
      }
      for (const a of v6) {
        const s = document.createElement('span');
        s.className = 'addr-v6';
        s.textContent = a;
        addrCell.appendChild(s);
      }
    }

    row.append(nameCell, trafficCell, addrCell);
    container.appendChild(row);
  }
  el('iface-count').textContent = `${list.length} interface${list.length === 1 ? '' : 's'}`;
}

// Event delegation — works no matter what characters are in interface names.
document.addEventListener('DOMContentLoaded', () => {
  const list = el('iface-list');
  if (!list) return;
  list.addEventListener('click', (e) => {
    const row = e.target.closest('.iface-row');
    if (row && row.dataset.iface) selectInterfaceRow(row.dataset.iface);
  });
  list.addEventListener('dblclick', (e) => {
    const row = e.target.closest('.iface-row');
    if (row && row.dataset.iface) {
      selectInterfaceRow(row.dataset.iface);
      confirmInterfaceSelection(true);
    }
  });
});

function selectInterfaceRow(name) {
  _selectedIface = name;
  document.querySelectorAll('.iface-row').forEach(r => {
    r.classList.toggle('selected', r.dataset.iface === name);
  });
  const btn = el('iface-start-btn');
  if (btn) btn.disabled = false;
}

function filterInterfaceList(q) {
  const needle = (q || '').trim().toLowerCase();
  if (!needle) return renderInterfaceList(_interfaces);
  const filtered = _interfaces.filter(i => {
    if (i.name.toLowerCase().includes(needle)) return true;
    if ((i.ipv4 || []).some(a => a.toLowerCase().includes(needle))) return true;
    if ((i.ipv6 || []).some(a => a.toLowerCase().includes(needle))) return true;
    return false;
  });
  renderInterfaceList(filtered);
}

function openInterfacePicker() {
  const active = _interfaces.find(i => i.active);
  _selectedIface = active ? active.name : (_interfaces[0] && _interfaces[0].name) || null;
  renderInterfaceList(_interfaces);
  el('iface-start-btn').disabled = !_selectedIface;
  const fi = el('iface-filter');
  if (fi) fi.value = '';
  showModal('modal-iface');
}

function confirmInterfaceSelection(autoStart = true) {
  if (!_selectedIface) return;
  setInterface(_selectedIface);
  closeModal('modal-iface');
  if (autoStart) startCapture();
}

function setInterface(name) {
  if (!name) return;
  socket.emit('set_interface', { interface: name });
  const i = _interfaces.find(x => x.name === name);
  if (i) {
    _interfaces.forEach(x => x.active = (x.name === name));
    const displayName = i.friendly_name || i.name;
    el('iface-current-label').textContent = i.ip ? `${displayName} (${i.ip})` : displayName;
    toast('info', '📡 Interface Changed', `Now monitoring: ${displayName}`);
  }
}

// ─── File ops (mock) ──────────────────────────────────────────────────────────

// Open a .pcap capture file. The local server pops a native Open dialog, reads the
// file with scapy, classifies each packet against the loaded rules, and loads the
// results into the view (freezing the background simulation).
function openFile() {
  toast('info', '📂 Open Capture', 'Pick a .pcap file when the dialog appears…');
  fetch('/api/capture/open-pcap', { method: 'POST' })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        const extra = data.truncated ? ' (first ' + data.count + ' of ' + data.total_in_file + ')' : '';
        toast('success', '📂 Capture Loaded',
              data.filename + ' — ' + data.count + ' packets, ' + data.alerts + ' alerts' + extra);
        // packets are reloaded by the 'pcap_loaded' socket handler
      } else if (data.cancelled) {
        toast('info', '📂 Open Capture', 'Open cancelled.');
      } else {
        toast('error', '📂 Open Capture', data.error || 'Could not open capture');
      }
    })
    .catch(() => toast('error', '📂 Open Capture', 'Request failed'));
}

let classifierFeatures = null;
let classifierLoaded = false;
let classifierCSVFile = null;   // the CSV most recently loaded, reused for the Word report

function loadClassifierTab() {
  if (classifierLoaded) return;
  const statusDot  = document.getElementById('clf2-status-dot');
  const statusText = document.getElementById('clf2-status-text');
  if (statusDot)  statusDot.className  = 'clf2-status-dot clf2-dot-loading';
  if (statusText) statusText.textContent = 'Loading model metadata\u2026';
  fetch('/api/classifier/features')
    .then(r => r.json())
    .then(data => {
      if (!data.success) {
        toast('error', 'Classifier', data.error);
        if (statusText) statusText.textContent = 'Error loading model';
        return;
      }
      classifierFeatures = data.features;
      classifierLoaded = true;
      renderClassifierForm(data.features);
      if (data.model_meta) {
        updateClassesList(data.model_meta.classes || []);
        if (statusDot)  statusDot.className  = 'clf2-status-dot clf2-dot-ready';
        if (statusText) statusText.textContent = 'Random Forest \u00b7 78 features \u00b7 27 classes';
      }
    })
    .catch(e => {
      toast('error', 'Classifier', 'Failed to load features');
      if (statusText) statusText.textContent = 'Connection error';
    });
}

function updateClassesList(classes) {
  const el = document.getElementById('clf2-classes-list');
  if (!el) return;
  el.innerHTML = '';
  classes.forEach(cls => {
    const tag = document.createElement('span');
    const isBenign = cls.toLowerCase() === 'benign';
    tag.className = 'clf2-class-tag ' + (isBenign ? 'clf2-tag-benign' : 'clf2-tag-attack');
    tag.textContent = cls;
    el.appendChild(tag);
  });
}

function renderClassifierForm(features) {
  const wrap = document.getElementById('classifier-form-wrap');
  wrap.innerHTML = '';
  Object.keys(features).forEach(name => {
    const meta = features[name];
    const row = document.createElement('div');
    row.className = 'clf2-feat-row';
    const lbl  = meta.label || name;
    const desc = meta.description || '';
    const med  = meta.median !== undefined ? meta.median : '';
    row.innerHTML =
      `<div class="clf2-feat-meta">` +
        `<span class="clf2-feat-name">${lbl}</span>` +
        `<span class="clf2-feat-key">${name}</span>` +
        (desc ? `<span class="clf2-feat-desc">${desc}</span>` : '') +
      `</div>` +
      `<input type="text" class="clf-input clf2-feat-input" ` +
             `data-field="${name}" data-type="numeric" ` +
             `placeholder="${med}">`;
    wrap.appendChild(row);
  });
}

function classifierPredict() {
  if (!classifierFeatures) { toast('error', 'Classifier', 'Features not loaded yet'); return; }

  const inputs = document.querySelectorAll('#classifier-form-wrap .clf-input');
  const row = {};
  inputs.forEach(inp => {
    const val = inp.value.trim();
    if (val !== '') row[inp.dataset.field] = val;
  });

  const idle    = document.getElementById('clf2-result-idle');
  const content = document.getElementById('clf2-result-content');
  const box     = document.getElementById('clf2-result-box');
  if (idle)    idle.style.display    = 'none';
  if (content) content.style.display = 'none';
  if (box)     box.className         = 'clf2-result-box clf2-result-working';

  fetch('/api/classifier/predict', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(row)
  })
    .then(r => r.json())
    .then(data => {
      if (box) box.className = 'clf2-result-box';
      if (!data.success) {
        if (idle) { idle.style.display = 'flex'; idle.querySelector('.clf2-idle-text').textContent = 'Error: ' + data.error; }
        toast('error', 'Prediction Failed', data.error);
        return;
      }
      const pred     = data.prediction;
      const isBenign = String(pred).toLowerCase() === 'benign';
      const flowsSec = document.getElementById('clf2-flows-section');
      if (flowsSec) flowsSec.style.display = 'none';
      const ptitle = document.getElementById('clf2-prob-title');
      if (ptitle) ptitle.textContent = 'Top Probabilities';
      const labelEl  = document.getElementById('clf2-pred-label');
      const classEl  = document.getElementById('clf2-pred-class');
      if (labelEl) { labelEl.textContent = isBenign ? 'BENIGN' : 'THREAT DETECTED'; labelEl.className = 'clf2-pred-label ' + (isBenign ? 'clf2-label-benign' : 'clf2-label-threat'); }
      if (classEl) classEl.textContent = pred;

      if (data.probabilities) {
        const probSec  = document.getElementById('clf2-prob-section');
        const barsDiv  = document.getElementById('prob-bars');
        if (probSec) probSec.style.display = 'block';
        if (barsDiv) {
          barsDiv.innerHTML = '';
          data.probabilities.forEach(p => {
            const pBenign = String(p.class).toLowerCase() === 'benign';
            const bar = document.createElement('div');
            bar.className = 'prob-row';
            bar.innerHTML =
              `<span class="prob-label">${p.class}</span>` +
              `<div class="prob-track"><div class="prob-fill ${pBenign ? 'fill-benign' : 'fill-threat'}" style="width:${Math.max(p.prob, 0.5)}%"></div></div>` +
              `<span class="prob-val">${p.prob}%</span>`;
            barsDiv.appendChild(bar);
          });
        }
      }
      if (content) content.style.display = 'flex';
      toast('success', 'Classification', 'Predicted: ' + pred);

      // If a CSV is loaded, generate the Word report (a native Save dialog will appear).
      if (classifierCSVFile) {
        toast('info', 'Word Report', 'Generating report — choose where to save it when prompted.');
        generateReportFromFile(classifierCSVFile);
      }
    })
    .catch(() => {
      if (box) box.className = 'clf2-result-box';
      if (idle) idle.style.display = 'flex';
      toast('error', 'Prediction', 'Request failed');
    });
}

// Classify the REAL captured traffic: ask the server to reassemble flows from the
// live / simulated / opened-pcap packets and run them through the ML model.
function classifierAnalyzeTraffic() {
  const idle    = document.getElementById('clf2-result-idle');
  const content = document.getElementById('clf2-result-content');
  const box     = document.getElementById('clf2-result-box');
  const btn     = document.querySelector('.clf2-livebtn');
  if (idle)    idle.style.display    = 'none';
  if (content) content.style.display = 'none';
  if (box)     box.className         = 'clf2-result-box clf2-result-working';
  if (btn)     btn.classList.add('btn-disabled');

  fetch('/api/classifier/analyze-traffic', { method: 'POST' })
    .then(r => r.json())
    .then(data => {
      if (box) box.className = 'clf2-result-box';
      if (btn) btn.classList.remove('btn-disabled');
      if (!data.success) {
        if (idle) { idle.style.display = 'flex'; idle.querySelector('.clf2-idle-text').textContent = data.error; }
        toast('info', 'Classify Traffic', data.error);
        return;
      }

      const hasAttacks = data.attack_flows > 0;
      const labelEl = document.getElementById('clf2-pred-label');
      const classEl = document.getElementById('clf2-pred-class');
      if (labelEl) {
        labelEl.textContent = hasAttacks ? 'THREATS DETECTED' : 'ALL BENIGN';
        labelEl.className = 'clf2-pred-label ' + (hasAttacks ? 'clf2-label-threat' : 'clf2-label-benign');
      }
      if (classEl) classEl.textContent =
        data.total_flows + ' flows • ' + data.attack_flows + ' attack, ' + data.benign_flows + ' benign';

      // Class distribution bars (reuse the prob-bars UI)
      const probSec = document.getElementById('clf2-prob-section');
      const ptitle  = document.getElementById('clf2-prob-title');
      const barsDiv = document.getElementById('prob-bars');
      if (ptitle) ptitle.textContent = 'Class Distribution';
      if (probSec) probSec.style.display = 'block';
      if (barsDiv) {
        barsDiv.innerHTML = '';
        (data.distribution || []).forEach(d => {
          const isBenign = String(d.class).toLowerCase() === 'benign';
          const row = document.createElement('div');
          row.className = 'prob-row';
          row.innerHTML =
            '<span class="prob-label">' + escHtml(d.class) + ' (' + d.count + ')</span>' +
            '<div class="prob-track"><div class="prob-fill ' + (isBenign ? 'fill-benign' : 'fill-threat') +
              '" style="width:' + Math.max(d.pct, 0.5) + '%"></div></div>' +
            '<span class="prob-val">' + d.pct + '%</span>';
          barsDiv.appendChild(row);
        });
      }

      // Per-flow list (attacks first)
      const flowsSec = document.getElementById('clf2-flows-section');
      const flowsDiv = document.getElementById('clf2-flows');
      if (flowsDiv) {
        flowsDiv.innerHTML = '';
        (data.flows || []).forEach(f => {
          const row = document.createElement('div');
          row.className = 'clf2-flow-row ' + (f.is_attack ? 'flow-attack' : 'flow-benign');
          const conf = (f.confidence != null) ? f.confidence + '%' : '';
          row.innerHTML =
            '<span class="flow-ep">' + escHtml(f.src) + ':' + f.src_port + ' → :' + f.dst_port + '</span>' +
            '<span class="flow-proto">' + escHtml(f.proto) + '</span>' +
            '<span class="flow-pkts">' + f.packets + ' pkt</span>' +
            '<span class="flow-pred">' + escHtml(f.prediction) + '</span>' +
            '<span class="flow-conf">' + conf + '</span>';
          flowsDiv.appendChild(row);
        });
      }
      if (flowsSec) flowsSec.style.display = (data.flows && data.flows.length) ? 'block' : 'none';

      if (content) content.style.display = 'flex';
      toast(hasAttacks ? 'high' : 'success', 'Traffic Classified',
            data.total_flows + ' flows analyzed — ' + data.attack_flows + ' flagged as attacks');
    })
    .catch(() => {
      if (box) box.className = 'clf2-result-box';
      if (btn) btn.classList.remove('btn-disabled');
      if (idle) idle.style.display = 'flex';
      toast('error', 'Classify Traffic', 'Request failed');
    });
}

function classifierClear() {
  document.querySelectorAll('#classifier-form-wrap .clf-input').forEach(inp => { inp.value = ''; });
  const idle    = document.getElementById('clf2-result-idle');
  const content = document.getElementById('clf2-result-content');
  const box     = document.getElementById('clf2-result-box');
  if (idle)    { idle.style.display = 'flex'; idle.querySelector && (idle.querySelector('.clf2-idle-text') || {}).textContent !== undefined && (idle.querySelector('.clf2-idle-text').textContent = 'Fill features & click Analyze'); }
  if (content) content.style.display = 'none';
  if (box)     box.className = 'clf2-result-box';
}

function classifierFillDefaults() {
  if (!classifierFeatures) return;
  document.querySelectorAll('#classifier-form-wrap .clf-input').forEach(inp => {
    const meta = classifierFeatures[inp.dataset.field];
    if (meta && meta.type === 'numeric' && meta.median !== undefined) inp.value = meta.median;
  });
}

function classifierLoadCSV(input) {
  const file = input.files[0];
  if (!file) return;
  input.value = '';

  const totalBytes = file.size;
  const totalGB = totalBytes / (1024 ** 3);
  const AVG_BYTES_PER_ROW = 220;

  const nameEl    = document.getElementById('clf-csv-name');
  const progWrap  = document.getElementById('clf-upload-progress');
  const progBar   = document.getElementById('clf-prog-bar');
  const progFile  = document.getElementById('clf-prog-filename');
  const progStat  = document.getElementById('clf-prog-status');
  const progXfer  = document.getElementById('clf-prog-transferred');
  const progRows  = document.getElementById('clf-prog-rows');
  const progLeft  = document.getElementById('clf-prog-remaining');

  function fmtBytes(b) {
    if (b >= 1024 ** 3) return (b / 1024 ** 3).toFixed(2) + ' GB';
    if (b >= 1024 ** 2) return (b / 1024 ** 2).toFixed(1) + ' MB';
    return (b / 1024).toFixed(0) + ' KB';
  }
  function fmtRows(b) {
    const r = Math.floor(b / AVG_BYTES_PER_ROW);
    return r >= 1000 ? (r / 1000).toFixed(1) + 'k' : r;
  }

  nameEl.textContent = 'Uploading…';
  progFile.textContent = file.name;
  progStat.textContent = 'Uploading…';
  progBar.style.width = '0%';
  progBar.classList.remove('prog-done', 'prog-analyzing');
  progWrap.style.display = 'block';

  const xhr = new XMLHttpRequest();

  xhr.upload.addEventListener('progress', e => {
    if (!e.lengthComputable) return;
    const pct = (e.loaded / e.total) * 100;
    const remaining = e.total - e.loaded;
    progBar.style.width = pct.toFixed(1) + '%';
    progStat.textContent = pct.toFixed(1) + '%';
    progXfer.textContent = fmtBytes(e.loaded) + ' / ' + fmtBytes(e.total);
    progRows.textContent = '~' + fmtRows(e.loaded) + ' rows sent';
    progLeft.textContent = fmtBytes(remaining) + ' remaining';
  });

  xhr.upload.addEventListener('load', () => {
    progBar.style.width = '100%';
    progBar.classList.add('prog-analyzing');
    progStat.textContent = 'Analyzing…';
    progXfer.textContent = fmtBytes(totalBytes) + ' uploaded';
    progRows.textContent = 'Reading rows…';
    progLeft.textContent = '';
  });

  xhr.addEventListener('load', () => {
    let data;
    try { data = JSON.parse(xhr.responseText); } catch { data = { success: false, error: 'Invalid response' }; }
    if (!data.success) {
      progStat.textContent = 'Error';
      progBar.classList.remove('prog-analyzing');
      progBar.classList.add('prog-error');
      nameEl.textContent = 'Load failed';
      toast('error', 'Load CSV', data.error);
      return;
    }
    progBar.style.width = '100%';
    progBar.classList.remove('prog-analyzing');
    progBar.classList.add('prog-done');
    progStat.textContent = 'Done';
    progXfer.textContent = fmtBytes(totalBytes);
    progRows.textContent = data.count + ' features loaded';
    progLeft.textContent = '';
    nameEl.textContent = file.name + ' (' + data.count + ' features)';
    classifierFeatures = data.features;
    classifierLoaded = true;
    classifierCSVFile = file;   // remember it so "Analyze Traffic" can auto-build the report
    const hintBar = document.getElementById('clf-report-hint-bar');
    if (hintBar) hintBar.style.display = 'flex';
    renderClassifierForm(data.features);
    classifierFillDefaults();
    toast('success', 'CSV Loaded', file.name + ' — ' + data.count + ' features. Click Analyze Traffic to generate the report.');
    setTimeout(() => { progWrap.style.display = 'none'; }, 4000);
  });

  xhr.addEventListener('error', () => {
    progStat.textContent = 'Upload failed';
    progBar.classList.add('prog-error');
    nameEl.textContent = 'Upload failed';
    toast('error', 'Load CSV', 'Network error during upload');
  });

  const formData = new FormData();
  formData.append('file', file);
  xhr.open('POST', '/api/classifier/upload-csv');
  xhr.send(formData);
}

// Bulk-classify a CSV and save a Gemini-authored Word (.docx) security report.
// The local server pops a native OS "Save As" dialog, so this works in any browser.
// Triggered after "Analyze Traffic" when a CSV has been loaded.
function generateReportFromFile(file) {
  if (!file) return;

  const progWrap  = document.getElementById('clf-upload-progress');
  const progBar   = document.getElementById('clf-prog-bar');
  const progFile  = document.getElementById('clf-prog-filename');
  const progStat  = document.getElementById('clf-prog-status');
  const progXfer  = document.getElementById('clf-prog-transferred');
  const progRows  = document.getElementById('clf-prog-rows');
  const progLeft  = document.getElementById('clf-prog-remaining');
  const analyzeBtn = document.querySelector('.clf2-analyze-btn');

  function fmtBytes(b) {
    if (b >= 1024 ** 3) return (b / 1024 ** 3).toFixed(2) + ' GB';
    if (b >= 1024 ** 2) return (b / 1024 ** 2).toFixed(1) + ' MB';
    return (b / 1024).toFixed(0) + ' KB';
  }
  function done() { if (analyzeBtn) analyzeBtn.classList.remove('btn-disabled'); }
  if (analyzeBtn) analyzeBtn.classList.add('btn-disabled');

  progFile.textContent = file.name;
  progStat.textContent = 'Uploading…';
  progBar.style.width = '0%';
  progBar.className = 'clf-prog-bar';
  progWrap.style.display = 'block';
  progRows.textContent = ''; progLeft.textContent = '';

  const xhr = new XMLHttpRequest();

  xhr.upload.addEventListener('progress', e => {
    if (!e.lengthComputable) return;
    const pct = (e.loaded / e.total) * 100;
    progBar.style.width = pct.toFixed(1) + '%';
    progStat.textContent = pct.toFixed(1) + '%';
    progXfer.textContent = fmtBytes(e.loaded) + ' / ' + fmtBytes(e.total);
    progLeft.textContent = fmtBytes(e.total - e.loaded) + ' remaining';
  });

  xhr.upload.addEventListener('load', () => {
    progBar.style.width = '100%';
    progBar.classList.add('prog-analyzing');
    progStat.textContent = 'Waiting for save location…';
    progXfer.textContent = fmtBytes(file.size) + ' uploaded';
    progLeft.textContent = '';
    progRows.textContent = '📁 A "Save As" dialog should appear — pick a location, then it generates (10–60s).';
  });

  xhr.addEventListener('load', () => {
    let data;
    try { data = JSON.parse(xhr.responseText); } catch { data = { success: false, error: 'Invalid server response' }; }

    if (data.success) {
      const st = data.stats || {};
      const total = st.total_rows != null ? st.total_rows : '?';
      const atk   = st.attack_count != null ? st.attack_count : '?';
      const trunc = st.truncated ? ' (truncated)' : '';
      progBar.classList.remove('prog-analyzing');
      progBar.classList.add('prog-done');
      progStat.textContent = 'Report saved';
      progRows.textContent = total + ' rows • ' + atk + ' attacks' + trunc;
      progLeft.textContent = '';
      progFile.textContent = data.filename || file.name;
      toast('success', 'Word Report', 'Saved to ' + (data.saved_path || data.filename));
      setTimeout(() => { progWrap.style.display = 'none'; }, 6000);
      done();
    } else if (data.cancelled) {
      progBar.classList.remove('prog-analyzing');
      progStat.textContent = 'Save cancelled';
      progRows.textContent = ''; progLeft.textContent = '';
      toast('info', 'Word Report', 'Save cancelled — no report was created.');
      setTimeout(() => { progWrap.style.display = 'none'; }, 3500);
      done();
    } else {
      progBar.classList.remove('prog-analyzing');
      progBar.classList.add('prog-error');
      progStat.textContent = 'Error'; progRows.textContent = ''; progLeft.textContent = '';
      toast('error', 'Word Report', data.error || 'Report generation failed');
      done();
    }
  });

  xhr.addEventListener('error', () => {
    progBar.classList.add('prog-error');
    progStat.textContent = 'Upload failed';
    toast('error', 'Word Report', 'Network error during upload');
    done();
  });

  const fd = new FormData();
  fd.append('file', file);
  xhr.open('POST', '/api/classifier/report');
  xhr.send(fd);
}
// Save the current traffic as a .pcap file. The local server pops a native Save
// dialog and writes the file with scapy — works in any browser.
function saveCapture() {
  if (!state.packets.length) { toast('info', '💾 Save', 'No packets to save yet.'); return; }
  toast('info', '💾 Save Capture', 'Choose where to save the .pcap when prompted…');
  fetch('/api/capture/save-pcap', { method: 'POST' })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        toast('success', '💾 Saved', data.count + ' packets → ' + (data.saved_path || data.filename));
      } else if (data.cancelled) {
        toast('info', '💾 Save', 'Save cancelled.');
      } else {
        toast('error', '💾 Save', data.error || 'Could not save capture');
      }
    })
    .catch(() => toast('error', '💾 Save', 'Request failed'));
}

// ─── Toast ────────────────────────────────────────────────────────────────────
let toastQueue = 0;
function toast(level, title, msg) {
  if (toastQueue > 4) return;
  toastQueue++;
  const c = el('toast-container');
  const t = document.createElement('div');
  t.className = `toast ${level}`;
  t.innerHTML = `<div class="toast-body"><div class="toast-title">${escHtml(title)}</div><div class="toast-msg">${escHtml(msg)}</div></div>`;
  c.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0'; t.style.transform = 'translateX(40px)';
    t.style.transition = 'all 0.3s';
    setTimeout(() => { t.remove(); toastQueue--; }, 300);
  }, 3500);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function el(id)         { return document.getElementById(id); }
function setEl(id, val) { const e = el(id); if (e) e.textContent = val; }
function escHtml(str)   { return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function scrollBottom() {
  const wrap = el('packet-table-wrap');
  if (wrap) wrap.scrollTop = wrap.scrollHeight;
}

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  loadInterfaces();

  // Close dropdowns on outside click
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.menu-item')) {
      document.querySelectorAll('.dropdown').forEach(d => d.style.display = '');
    }
  });

  // Uptime ticker
  setInterval(() => {
    if (state.running && !state.paused) {
      updateThreatLevel();
    }
  }, 5000);

  // Auto-scroll toggle on manual scroll
  const wrap = el('packet-table-wrap');
  if (wrap) {
    wrap.addEventListener('scroll', () => {
      const atBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 40;
      state.autoScroll = atBottom;
    });
  }

  // Enter key in modal input
  const mi = el('modal-rule-input');
  if (mi) mi.addEventListener('keydown', e => { if (e.key === 'Enter') validateRule(); });

  // Enter key in rule validate inline
  const ri = el('rule-validate-input');
  if (ri) ri.addEventListener('keydown', e => { if (e.key === 'Enter') validateRuleInline(); });
});

// ─── Dynamic Security Detectors & Rules File Toggles ──────────────────────────

function renderDetectors(detectors) {
  const container = el('sb-detectors-list');
  const countEl = el('sb-detectors-count');
  
  if (!detectors || detectors.length === 0) {
    container.innerHTML = '<div class="empty-state">No detectors found</div>';
    if (countEl) countEl.textContent = '0';
    return;
  }
  
  // Count active/enabled detectors
  const activeCount = detectors.filter(d => d.enabled).length;
  if (countEl) countEl.textContent = activeCount;
  const sbc = el('sb-active-detectors');
  if (sbc) sbc.textContent = activeCount;

  container.innerHTML = detectors.map(d => `
    <div class="detector-item">
      <div class="detector-info" title="${escHtml(d.description)}">
        <span class="detector-name">${escHtml(d.name)}</span>
        <span class="detector-desc">${escHtml(d.description)}</span>
      </div>
      <label class="switch-container">
        <input type="checkbox" ${d.enabled ? 'checked' : ''} 
               onchange="toggleDetector('${d.id}', this.checked)" />
      </label>
    </div>
  `).join('');
}

function toggleDetector(id, enabled) {
  socket.emit('toggle_detector', { id: id, enabled: enabled });
}

function populateRulesDropdown(files, selected) {
  const dropdown = el('rules-file-dropdown');
  if (!dropdown) return;
  
  dropdown.innerHTML = files.map(file => `
    <option value="${escHtml(file)}" ${file === selected ? 'selected' : ''}>
      ${escHtml(file)}
    </option>
  `).join('');
}

function changeRulesFile(val) {
  socket.emit('load_rules', { path: val });
}

function uploadRulesFile(input) {
  const file = input.files[0];
  if (!file) return;
  input.value = '';

  if (!file.name.toLowerCase().endsWith('.rules')) {
    toast('high', '❌ Invalid File', 'Please select a file ending in .rules');
    return;
  }

  const formData = new FormData();
  formData.append('file', file);

  toast('info', '📤 Uploading Rules', `Uploading ${file.name}...`);

  fetch('/api/rules/upload', {
    method: 'POST',
    body: formData
  })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        toast('info', '📜 Rules Imported', `Successfully loaded ${data.rules_count} rules from ${data.filename}`);
      } else {
        toast('high', '❌ Import Failed', data.error);
      }
    })
    .catch(e => {
      toast('high', '❌ Import Error', 'Failed to upload rules file');
    });
}

function setCaptureMode(live) {
  socket.emit('toggle_capture_mode', { live: live });
  toast('info', '⚙ Mode Changed', `Switched to ${live ? 'Live Sniffer' : 'Simulation Mode'}`);
}
