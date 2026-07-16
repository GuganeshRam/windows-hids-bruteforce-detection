const POLL_MS = 3000;

const el = {
  statusDot: document.getElementById('status-dot'),
  statusText: document.getElementById('status-text'),
  threshold: document.getElementById('stat-threshold'),
  window: document.getElementById('stat-window'),
  tracked: document.getElementById('stat-tracked'),
  alerts: document.getElementById('stat-alerts'),
  updated: document.getElementById('stat-updated'),
  since: document.getElementById('stat-since'),
  banner: document.getElementById('banner'),
  trackedGrid: document.getElementById('tracked-grid'),
  trackedEmpty: document.getElementById('tracked-empty'),
  logBody: document.getElementById('log-body'),
  logCount: document.getElementById('log-count'),
  footerStarted: document.getElementById('footer-started'),
};

let knownAlertKeys = new Set();

function fmtTime(iso) {
  if (!iso) return '\u2014';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  return d.toLocaleTimeString('en-GB', { hour12: false });
}

function fmtAgo(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  const secs = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
}

function setStatus(state, label) {
  el.statusDot.className = 'status-dot';
  el.statusText.className = 'status-text';
  el.statusDot.classList.add(`is-${state}`);
  el.statusText.classList.add(`state-${state}`);
  el.statusText.textContent = label;
}

function renderTracked(active, threshold) {
  const entries = Object.values(active || {});
  el.trackedGrid.innerHTML = '';

  if (entries.length === 0) {
    el.trackedGrid.appendChild(el.trackedEmpty);
    return;
  }

  entries.sort((a, b) => b.attempts - a.attempts);

  for (const item of entries) {
    const pct = Math.min(100, Math.round((item.attempts / threshold) * 100));
    const card = document.createElement('div');
    card.className = 'tracked-card' + (item.alert ? ' is-alert' : '');
    card.innerHTML = `
      ${item.alert ? '<span class="tracked-badge">ALERT</span>' : ''}
      <div class="tracked-row1">
        <span class="tracked-user" title="${item.username}">${item.username || 'unknown'}</span>
        <span class="tracked-count"><strong>${item.attempts}</strong> / ${threshold}</span>
      </div>
      <div class="tracked-meta">
        <span>${item.ip || 'unknown ip'}</span>
        <span>${fmtAgo(item.last_seen)}</span>
      </div>
      <div class="gauge"><div class="gauge-fill" style="width:${pct}%"></div></div>
    `;
    el.trackedGrid.appendChild(card);
  }
}

function renderLog(events) {
  el.logCount.textContent = `${events.length} event${events.length === 1 ? '' : 's'}`;
  el.logBody.innerHTML = '';

  if (!events.length) {
    const row = document.createElement('tr');
    row.className = 'empty-row';
    row.innerHTML = '<td colspan="6">Waiting for events&hellip;</td>';
    el.logBody.appendChild(row);
    return;
  }

  for (const ev of events) {
    const row = document.createElement('tr');
    if (ev.alert) row.className = 'is-alert';
    row.innerHTML = `
      <td>${fmtTime(ev.timestamp)}</td>
      <td>${ev.username || ''}</td>
      <td>${ev.ip || ''}</td>
      <td>${ev.logon_type || ''}</td>
      <td>${ev.attempts}</td>
      <td>${ev.alert
        ? '<span class="pill pill--alert">BRUTE-FORCE</span>'
        : '<span class="pill pill--ok">tracking</span>'}</td>
    `;
    el.logBody.appendChild(row);
  }
}

function maybeFlash(active) {
  const newlyAlerting = Object.values(active || {}).filter(
    (item) => item.alert && !knownAlertKeys.has(`${item.username}@${item.ip}`)
  );
  newlyAlerting.forEach((item) =>
    knownAlertKeys.add(`${item.username}@${item.ip}`)
  );
}

async function poll() {
  let data;
  try {
    const res = await fetch('/api/logs');
    data = await res.json();
  } catch (err) {
    setStatus('error', 'UNREACHABLE');
    return;
  }

  const status = data.status || 'starting';
  const activeAlerts = Object.values(data.active || {}).filter((a) => a.alert).length;

  if (status === 'error') {
    setStatus('error', 'ERROR');
    el.banner.textContent = data.message || 'The detector reported an error.';
    el.banner.classList.remove('hidden');
  } else if (status === 'running' && activeAlerts > 0) {
    setStatus('alert', `ALERT (${activeAlerts})`);
    el.banner.classList.add('hidden');
  } else if (status === 'running') {
    setStatus('running', 'MONITORING');
    el.banner.classList.add('hidden');
  } else {
    setStatus('idle', status.toUpperCase());
    el.banner.classList.add('hidden');
  }

  el.threshold.textContent = data.threshold ?? '\u2014';
  el.window.textContent = data.window_seconds ?? '\u2014';
  el.tracked.textContent = Object.keys(data.active || {}).length;
  el.alerts.textContent = activeAlerts;
  el.updated.textContent = fmtTime(data.last_updated);
  el.since.textContent = data.last_updated ? fmtAgo(data.last_updated) : '';
  el.footerStarted.textContent = data.started_at
    ? `started ${fmtTime(data.started_at)}`
    : '';

  maybeFlash(data.active);
  renderTracked(data.active, data.threshold || 5);
  renderLog(data.events || []);
}

poll();
setInterval(poll, POLL_MS);
