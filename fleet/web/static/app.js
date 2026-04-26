// xtop fleet dashboard — live view driven by /v1/stream SSE.
//
// Rendering strategy: this file never uses innerHTML with dynamic content.
// All text coming from the hub (hostnames, culprits, bottleneck names, error
// messages, etc.) flows through textContent, and all nodes are built via
// document.createElement. This removes the XSS surface entirely — even if an
// agent pushes a malicious hostname, it renders as plain text.
(() => {
  'use strict';

  const state = {
    hosts: new Map(),
    filter: '',
    onlyUnhealthy: false,
    lastUpdate: null,
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  // Small DOM builder: el('div', {class:'x', onclick:f}, child1, child2, 'text')
  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === 'class') n.className = v;
        else if (k === 'dataset') { for (const [dk, dv] of Object.entries(v)) n.dataset[dk] = dv; }
        else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
        else n.setAttribute(k, v);
      }
    }
    for (const c of children) {
      if (c == null || c === false) continue;
      if (typeof c === 'string' || typeof c === 'number') n.appendChild(document.createTextNode(String(c)));
      else if (Array.isArray(c)) c.forEach(ci => ci && n.appendChild(ci));
      else n.appendChild(c);
    }
    return n;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  // ── Formatting helpers ─────────────────────────────────────
  function healthClass(h) {
    switch (h) {
      case 3: return { cls: 'h-critical', badge: 'badge-critical', label: 'critical' };
      case 2: return { cls: 'h-degraded', badge: 'badge-degraded', label: 'degraded' };
      case 1: return { cls: 'h-inc', badge: 'badge-inc', label: 'inconclusive' };
      default: return { cls: 'h-ok', badge: 'badge-ok', label: 'ok' };
    }
  }

  function timeAgo(iso) {
    if (!iso) return '—';
    const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  // Format a UTC ISO timestamp in the browser's local timezone. Returns "—"
  // for missing values so callers can drop the result into UI cells
  // without null-guarding each one.
  function fmtLocalTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function fmtLocalDateTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString([], {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  }

  // seenWithExact renders "HH:MM:SS (3s ago)" so the card shows both the
  // absolute browser-local time AND the relative freshness indicator.
  function seenWithExact(iso) {
    if (!iso) return '—';
    return fmtLocalTime(iso) + ' (' + timeAgo(iso) + ')';
  }

  function metricClass(v, warn, crit) {
    if (v == null || v === 0) return 'm-mute';
    if (v >= crit) return 'm-crit';
    if (v >= warn) return 'm-warn';
    return 'm-ok';
  }

  function loadClass(load, cpus) {
    if (!cpus || !load) return 'm-mute';
    const r = load / cpus;
    if (r >= 1.5) return 'm-crit';
    if (r >= 1.0) return 'm-warn';
    return 'm-ok';
  }

  function fmtPct(v) {
    if (v == null) return '—';
    if (v < 0.5) return '0%';
    return Math.round(v) + '%';
  }

  // ── Host cards ─────────────────────────────────────────────
  function hostsSortedForView() {
    const list = [...state.hosts.values()];
    const q = state.filter.trim().toLowerCase();
    const filtered = list.filter(h => {
      if (state.onlyUnhealthy && (h.health | 0) <= 1) return false;
      if (!q) return true;
      const hay = [
        h.hostname, h.primary_bottleneck, h.culprit_process, h.culprit_app,
        ...(h.tags || []),
      ].filter(Boolean).join(' ').toLowerCase();
      return hay.includes(q);
    });
    filtered.sort((a, b) => {
      if (a.health !== b.health) return (b.health | 0) - (a.health | 0);
      if ((b.primary_score | 0) !== (a.primary_score | 0)) return (b.primary_score | 0) - (a.primary_score | 0);
      return (a.hostname || '').localeCompare(b.hostname || '');
    });
    return filtered;
  }

  function renderHosts() {
    const container = $('#hosts');
    clear(container);
    $('#host-count').textContent =
      `${state.hosts.size} host${state.hosts.size === 1 ? '' : 's'}`;
    const list = hostsSortedForView();
    if (list.length === 0) {
      container.appendChild(el('div', { class: 'empty' }, 'No hosts match your filter.'));
      return;
    }
    for (const h of list) container.appendChild(buildCard(h));
  }

  function buildCard(h) {
    const hc = healthClass(h.health);
    const expired = h.status === 'expired';
    const cls = expired ? 'h-expired' : (h.active_incident_id ? 'h-inc' : hc.cls);
    const badgeCls = expired ? 'badge-expired' : (h.active_incident_id ? 'badge-inc' : hc.badge);
    const label = expired ? 'stale' : (h.active_incident_id ? 'incident' : hc.label);

    // Bottleneck + culprit line — the "why am I looking at this card" row.
    const metaChildren = [];
    if (h.primary_bottleneck) {
      metaChildren.push(el('span', { class: 'host-bottleneck' }, h.primary_bottleneck));
      metaChildren.push(` · ${h.primary_score | 0}% (${h.confidence | 0}% conf)`);
    } else {
      metaChildren.push(el('span', { class: 'm-mute' }, 'no bottleneck'));
    }
    const culpritName = h.culprit_app || h.culprit_process;
    if (culpritName) {
      metaChildren.push(' → ');
      metaChildren.push(el('span', { class: 'host-culprit' }, culpritName));
    }

    // Primary 4 metrics stay prominent.
    const metric = (val, label, klass) =>
      el('div', { class: 'metric' },
        el('div', { class: 'metric-val ' + klass }, val),
        el('div', { class: 'metric-label' }, label),
      );

    // Hardware + identity facts — shown as small chips so the card stops
    // looking anemic on healthy hosts. Only render chips that have data.
    const factsChildren = [];
    const chip = (label, value, mute) =>
      el('span', { class: 'chip' + (mute ? ' chip-mute' : '') },
        el('span', { class: 'chip-k' }, label),
        el('span', { class: 'chip-v' }, value));

    if (h.num_cpus)       factsChildren.push(chip('cpus', String(h.num_cpus)));
    if (h.mem_total_bytes) factsChildren.push(chip('ram', fmtBytes(h.mem_total_bytes)));
    if (h.agent_version)  factsChildren.push(chip('ver', 'v' + h.agent_version, true));
    if (h.os)             factsChildren.push(chip('os', truncChip(h.os, 18), true));
    if (Array.isArray(h.tags)) {
      for (const t of h.tags) factsChildren.push(chip('tag', t));
    }

    // Self-resource chips — operator can see at a glance whether the
    // observability tool is competing with the workload it's observing.
    // We render even when CPU% / RSS look fine, so absence of the chips
    // is meaningful (= guardian disabled or older agent).
    const selfFactsChildren = [];
    const selfChip = (label, value, danger) =>
      el('span', { class: 'chip ' + (danger ? 'chip-danger' : 'chip-self') },
        el('span', { class: 'chip-k' }, label),
        el('span', { class: 'chip-v' }, value));
    if (h.xtop_cpu_pct != null && h.xtop_cpu_pct > 0) {
      selfFactsChildren.push(selfChip('xtop cpu',
        h.xtop_cpu_pct.toFixed(1) + '%',
        h.xtop_cpu_pct >= 5));
    }
    if (h.xtop_rss_mb != null && h.xtop_rss_mb > 0) {
      selfFactsChildren.push(selfChip('xtop rss',
        Math.round(h.xtop_rss_mb) + ' MB',
        h.xtop_rss_mb >= 200));
    }
    if (h.xtop_guard_level != null && h.xtop_guard_level > 0) {
      selfFactsChildren.push(selfChip('guard',
        'L' + h.xtop_guard_level,
        h.xtop_guard_level >= 2));
    }
    if (h.xtop_mode) selfFactsChildren.push(chip('mode', h.xtop_mode, true));

    const card = el('div', {
      class: 'host-card ' + cls,
      dataset: { host: h.hostname || '' },
      onclick: () => openDrawer(h.hostname),
    },
      el('div', { class: 'host-head' },
        el('div', { class: 'host-name' }, h.hostname || '—'),
        el('span', { class: 'host-badge ' + badgeCls }, label),
      ),
      el('div', { class: 'host-meta' }, ...metaChildren),
      el('div', { class: 'metrics' },
        metric(fmtPct(h.cpu_busy_pct), 'cpu', metricClass(h.cpu_busy_pct, 70, 90)),
        metric(fmtPct(h.mem_used_pct), 'mem', metricClass(h.mem_used_pct, 80, 95)),
        metric(fmtPct(h.io_worst_util), 'io', metricClass(h.io_worst_util, 60, 85)),
        metric((h.load_avg_1 || 0).toFixed(1), 'load', loadClass(h.load_avg_1, h.num_cpus)),
      ),
      factsChildren.length ? el('div', { class: 'host-facts' }, ...factsChildren) : null,
      selfFactsChildren.length ? el('div', { class: 'host-facts host-facts-self' }, ...selfFactsChildren) : null,
      el('div', {
          class: 'host-meta',
          style: 'margin-top:6px',
          title: 'last heartbeat: ' + fmtLocalDateTime(h.last_seen),
        },
        'seen ' + seenWithExact(h.last_seen) +
        (h.active_incident_id ? ' · incident ' + shortID(h.active_incident_id) : '')),
    );
    return card;
  }

  function truncChip(s, n) {
    if (!s) return '';
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  function shortID(id) {
    if (!id) return '';
    return id.length > 12 ? id.slice(-12) : id;
  }

  function fmtBytes(b) {
    if (!b || b <= 0) return '—';
    const kb = 1024, mb = 1024 * kb, gb = 1024 * mb, tb = 1024 * gb;
    if (b >= tb) return (b / tb).toFixed(1) + ' TB';
    if (b >= gb) return (b / gb).toFixed(1) + ' GB';
    if (b >= mb) return (b / mb).toFixed(1) + ' MB';
    return (b / kb).toFixed(0) + ' KB';
  }

  // ── Incidents table ────────────────────────────────────────
  async function loadIncidents() {
    const hours = $('#inc-window').value;
    const tbody = $('#incidents tbody');
    try {
      const r = await fetch(`/v1/incidents?hours=${encodeURIComponent(hours)}&limit=200`);
      if (!r.ok) throw new Error('hub ' + r.status);
      const body = await r.json();
      renderIncidents(Array.isArray(body) ? body : []);
    } catch (e) {
      clear(tbody);
      tbody.appendChild(el('tr', null,
        el('td', { colspan: '7', class: 'empty' }, "Couldn't load incidents: " + e.message),
      ));
    }
  }

  function renderIncidents(list) {
    const tbody = $('#incidents tbody');
    clear(tbody);
    if (!list.length) {
      tbody.appendChild(el('tr', null,
        el('td', { colspan: '7', class: 'empty' }, 'No incidents in this window.'),
      ));
      return;
    }
    const byId = new Map();
    for (const inc of list) {
      const prev = byId.get(inc.incident_id);
      if (!prev || new Date(inc.timestamp) > new Date(prev.timestamp)) byId.set(inc.incident_id, inc);
    }
    const rows = [...byId.values()].sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
    for (const i of rows) {
      tbody.appendChild(el('tr',
        { class: 'clickable', dataset: { host: i.hostname || '' }, onclick: () => openDrawer(i.hostname) },
        el('td', null, i.hostname || '—'),
        el('td', null, i.bottleneck || '—'),
        el('td', null, (i.peak_score | 0) + '%'),
        el('td', null, (i.confidence | 0) + '%'),
        el('td', null, i.culprit_app || i.culprit || '—'),
        el('td', { title: fmtLocalDateTime(i.started_at) },
           fmtLocalTime(i.started_at) + ' · ' + timeAgo(i.started_at)),
        el('td', { class: 'state-' + (i.update_type || '') }, i.update_type || ''),
      ));
    }
  }

  // ── Drawer ─────────────────────────────────────────────────
  async function openDrawer(hostname) {
    if (!hostname) return;
    $('#host-drawer').classList.remove('hidden');
    $('#drawer-title').textContent = hostname;
    const body = $('#drawer-body');
    clear(body);
    body.appendChild(el('div', { class: 'empty' }, 'loading…'));
    try {
      const [hostR, incR] = await Promise.all([
        fetch(`/v1/host/${encodeURIComponent(hostname)}`),
        fetch(`/v1/incidents?host=${encodeURIComponent(hostname)}&hours=168&limit=30`),
      ]);
      const host = hostR.ok ? await hostR.json() : null;
      // The hub returns `null` (not `[]`) when no incidents exist — guard
      // so downstream .length / iteration never blows up.
      const incRaw = incR.ok ? await incR.json() : null;
      const incidents = Array.isArray(incRaw) ? incRaw : [];
      clear(body);
      buildDrawer(body, host, incidents);
    } catch (e) {
      clear(body);
      body.appendChild(el('div', { class: 'empty' }, 'error: ' + e.message));
    }
  }

  function buildDrawer(body, h, incidents) {
    if (!h) {
      body.appendChild(el('div', { class: 'empty' }, 'host not found'));
      return;
    }
    const hc = healthClass(h.health);

    const kv = (label, valueNode) => [
      el('dt', null, label),
      el('dd', null, valueNode == null ? '—' : valueNode),
    ];

    const bottleneckNode = h.primary_bottleneck
      ? el('span', null,
          el('span', { class: 'host-bottleneck' }, h.primary_bottleneck),
          ` (score ${h.primary_score | 0}%, conf ${h.confidence | 0}%)`)
      : el('span', { class: 'm-mute' }, 'none');

    const dl = el('dl', { class: 'kv' },
      ...kv('health', el('span', { class: 'host-badge ' + hc.badge }, hc.label)),
      ...kv('bottleneck', bottleneckNode),
      ...kv('culprit', h.culprit_app || h.culprit_process || '—'),
      ...kv('agent', `${h.agent_version || '?'} · ${h.agent_id || ''}`),
      ...kv('os', `${h.os || ''} · ${h.kernel || ''}`),
      ...kv('cpu', `${fmtPct(h.cpu_busy_pct)} on ${h.num_cpus | 0} CPUs`),
      ...kv('memory', fmtPct(h.mem_used_pct)),
      ...kv('io worst', fmtPct(h.io_worst_util)),
      ...kv('load 1m', (h.load_avg_1 || 0).toFixed(2)),
      ...kv('last seen', fmtLocalDateTime(h.last_seen) + '  (' + timeAgo(h.last_seen) + ')'),
      ...kv('first seen', fmtLocalDateTime(h.first_seen)),
      ...kv('tags', (h.tags || []).join(', ') || '—'),
    );

    const table = el('table', { class: 'incidents' },
      el('thead', null,
        el('tr', null,
          el('th', null, 'bottleneck'),
          el('th', null, 'peak'),
          el('th', null, 'culprit'),
          el('th', null, 'when'),
          el('th', null, 'state'),
        ),
      ),
      el('tbody', null, ...buildIncidentRows(incidents)),
    );

    body.appendChild(dl);

    // "vs history" panel — populated from the most recent incident that
    // carries a Diff payload. Silent when we've never seen this signature.
    const diff = findLatestDiff(incidents);
    if (diff) body.appendChild(buildDiffPanel(diff));

    body.appendChild(el('h4', { style: 'color:var(--cyan);margin:0 0 8px' }, 'Recent incidents'));
    body.appendChild(table);
  }

  function findLatestDiff(incidents) {
    if (!Array.isArray(incidents)) return null;
    for (const i of incidents) if (i && i.diff) return i.diff;
    return null;
  }

  function buildDiffPanel(d) {
    const rows = [];
    const delta = d.score_delta_from_median | 0;
    if (delta !== 0) {
      const tone = delta >= 15 ? 'm-crit' : (delta <= -15 ? 'm-ok' : 'm-mute');
      rows.push(el('div', null,
        el('strong', null, delta > 0 ? 'worse than usual ' : 'milder than usual '),
        el('span', { class: tone },
          `${delta > 0 ? '+' : ''}${delta} pts (median ${d.median_peak_score | 0}%)`),
      ));
    }
    if (d.culprit_is_repeat) {
      rows.push(el('div', null,
        el('strong', null, 'repeat culprit: '),
        el('span', { class: 'host-culprit' }, d.top_culprit),
        ` (${d.top_culprit_count}/${d.match_count} prior incidents)`,
      ));
    }
    if (d.new_evidence && d.new_evidence.length) {
      rows.push(el('div', null,
        el('strong', null, 'new signals: '),
        el('span', { class: 'm-warn' }, d.new_evidence.slice(0, 4).join(', ')),
      ));
    }
    if (d.missing_evidence && d.missing_evidence.length) {
      rows.push(el('div', null,
        el('strong', null, 'usually firing but absent: '),
        el('span', { class: 'm-mute' }, d.missing_evidence.slice(0, 4).join(', ')),
      ));
    }
    if ((d.same_hour_of_day | 0) >= 2 && (d.match_count | 0) >= 3) {
      rows.push(el('div', null,
        el('strong', null, 'time-of-day pattern: '),
        `${d.same_hour_of_day}/${d.match_count} prior matches at this hour — check cron/scheduled jobs`,
      ));
    }
    if (!rows.length) return document.createDocumentFragment();
    return el('section', { style: 'margin:0 0 20px' },
      el('h4', { style: 'color:var(--orange);margin:0 0 8px' }, 'vs history'),
      el('div', { style: 'background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:10px 14px;font-size:13px;line-height:1.7' },
        ...rows,
      ),
    );
  }

  function buildIncidentRows(incidents) {
    if (!Array.isArray(incidents) || !incidents.length) {
      return [el('tr', null, el('td', { colspan: '5', class: 'empty' }, 'none'))];
    }
    return incidents.slice(0, 20).map(inc =>
      el('tr', null,
        el('td', null, inc.bottleneck || '—'),
        el('td', null, (inc.peak_score | 0) + '%'),
        el('td', null, inc.culprit_app || inc.culprit || '—'),
        el('td', { title: fmtLocalDateTime(inc.started_at) },
           fmtLocalTime(inc.started_at) + ' · ' + timeAgo(inc.started_at)),
        el('td', { class: 'state-' + (inc.update_type || '') }, inc.update_type || ''),
      ),
    );
  }

  // ── SSE stream ─────────────────────────────────────────────
  function connectStream() {
    const es = new EventSource('/v1/stream');
    es.addEventListener('snapshot', (ev) => {
      try {
        const hosts = JSON.parse(ev.data) || [];
        state.hosts.clear();
        for (const h of hosts) state.hosts.set(h.agent_id, h);
        markConnected();
        renderHosts();
      } catch (e) { console.error(e); }
    });
    es.addEventListener('heartbeat', (ev) => {
      try {
        const hb = JSON.parse(ev.data);
        applyHeartbeat(hb);
        markConnected();
        renderHosts();
      } catch (e) { console.error(e); }
    });
    es.addEventListener('incident', () => {
      clearTimeout(connectStream._incT);
      connectStream._incT = setTimeout(loadIncidents, 1500);
    });
    es.onerror = () => markDisconnected();
  }

  function applyHeartbeat(hb) {
    const existing = state.hosts.get(hb.agent_id);
    const merged = Object.assign(
      { first_seen: hb.timestamp, status: 'live' },
      existing || {},
      {
        hostname: hb.hostname,
        agent_id: hb.agent_id,
        agent_version: hb.agent_version,
        tags: hb.tags,
        kernel: hb.kernel,
        os: hb.os,
        last_seen: hb.timestamp,
        health: hb.health,
        primary_bottleneck: hb.primary_bottleneck,
        primary_score: hb.primary_score,
        confidence: hb.confidence,
        culprit_process: hb.culprit_process,
        culprit_app: hb.culprit_app,
        cpu_busy_pct: hb.cpu_busy_pct,
        mem_used_pct: hb.mem_used_pct,
        io_worst_util: hb.io_worst_util,
        load_avg_1: hb.load_avg_1,
        num_cpus: hb.num_cpus,
        active_incident_id: hb.active_incident_id,
        status: 'live',
      },
    );
    state.hosts.set(hb.agent_id, merged);
    state.lastUpdate = new Date();
    $('#last-update').textContent = 'updated ' + state.lastUpdate.toLocaleTimeString();
  }

  function markConnected() {
    $('#conn-indicator').className = 'dot dot-green';
    $('#conn-text').textContent = 'streaming live';
  }
  function markDisconnected() {
    $('#conn-indicator').className = 'dot dot-red';
    $('#conn-text').textContent = 'disconnected (reconnecting…)';
  }

  // ── Wire-up ────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    $('#filter').addEventListener('input', (e) => {
      state.filter = e.target.value;
      renderHosts();
    });
    $('#only-unhealthy').addEventListener('change', (e) => {
      state.onlyUnhealthy = e.target.checked;
      renderHosts();
    });
    $('#inc-window').addEventListener('change', loadIncidents);
    $('#drawer-close').addEventListener('click', () => $('#host-drawer').classList.add('hidden'));
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') $('#host-drawer').classList.add('hidden');
    });

    loadIncidents();
    connectStream();
    setInterval(renderHosts, 5000);
  });
})();
