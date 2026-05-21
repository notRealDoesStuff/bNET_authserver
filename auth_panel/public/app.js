'use strict';

// ================================================================
// bNET Auth Panel — Frontend Application
// ================================================================

const api = {
    async call(method, url, body) {
        const opts = { method, credentials: 'include', headers: {} };
        if (body !== undefined) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        const res = await fetch(url, opts);
        const data = await res.json().catch(() => ({}));
        return { ok: res.ok, status: res.status, data };
    },
    get:    (url)       => api.call('GET',    url),
    post:   (url, body) => api.call('POST',   url, body),
    put:    (url, body) => api.call('PUT',    url, body),
    patch:  (url, body) => api.call('PATCH',  url, body),
    delete: (url)       => api.call('DELETE', url),
};

// ================================================================
// State
// ================================================================
let autoRefreshTimer = null;
let wsConnection     = null;

// ================================================================
// Utilities
// ================================================================
function show(el)  { if (el) el.hidden = false; }
function hide(el)  { if (el) el.hidden = true;  }
function el(id)    { return document.getElementById(id); }
function text(id, v) { const e = el(id); if (e) e.textContent = v; }

function showError(elId, msg) {
    const e = el(elId);
    if (!e) return;
    e.textContent = msg;
    show(e);
}
function clearMsg(elId) {
    const e = el(elId);
    if (!e) return;
    e.textContent = '';
    hide(e);
}

function fmtDuration(seconds) {
    if (!seconds && seconds !== 0) return '—';
    const s = Math.floor(seconds);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (h) return `${h}h ${m}m ${sec}s`;
    if (m) return `${m}m ${sec}s`;
    return `${sec}s`;
}

function fmtAge(ts) {
    if (!ts) return '—';
    const diff = Date.now() / 1000 - ts;
    return fmtDuration(diff) + ' ago';
}

// ================================================================
// Login
// ================================================================
el('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearMsg('login-error');
    const btn = el('login-btn');
    btn.disabled = true;
    btn.textContent = 'Signing in...';

    const password = el('login-password').value;
    const { ok, data } = await api.post('/api/login', { password });

    if (ok) {
        showApp();
    } else {
        showError('login-error', data.error || 'Login failed');
        btn.disabled = false;
        btn.textContent = 'Sign In';
    }
});

el('logout-btn').addEventListener('submit', null);
el('logout-btn').addEventListener('click', async () => {
    await api.post('/api/logout');
    location.reload();
});

// ================================================================
// App init
// ================================================================
async function init() {
    const { ok, data } = await api.get('/api/me');
    if (ok && data.authenticated) {
        showApp();
    } else {
        show(el('login-screen'));
    }
}

function showApp() {
    hide(el('login-screen'));
    show(el('app'));
    switchTab('dashboard');
    startAutoRefresh();
}

// ================================================================
// Tab navigation
// ================================================================
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

function switchTab(name) {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === `tab-${name}`));

    if (name === 'logs') connectLogs();
    else disconnectLogs();

    if (name === 'users')    loadUsers();
    if (name === 'settings') loadSettings();
    if (name === 'sessions') loadSessions();
}

// ================================================================
// Auto-refresh (Dashboard + Sessions)
// ================================================================
function startAutoRefresh() {
    loadStatus();
    autoRefreshTimer = setInterval(() => {
        const activeTab = document.querySelector('.nav-btn.active')?.dataset.tab;
        if (activeTab === 'dashboard' || activeTab === 'sessions') loadStatus();
    }, 5000);
}

// ================================================================
// Dashboard
// ================================================================
async function loadStatus() {
    const badge = el('svc-badge');
    badge.textContent = 'Checking...';
    badge.className = 'status-badge checking';

    const { ok, data } = await api.get('/api/status');
    if (!ok) {
        badge.textContent = 'Error';
        return;
    }

    const svc = data.service_status;
    badge.textContent = svc.charAt(0).toUpperCase() + svc.slice(1);
    badge.className = 'status-badge ' + (svc === 'active' ? 'running' : 'stopped');

    const admin = data.admin;
    if (admin) {
        const uptime = admin.server_start_ts ? fmtDuration(Date.now() / 1000 - admin.server_start_ts) : '—';
        text('uptime-label', 'Uptime: ' + uptime);
        text('stat-clients',  admin.tcp_client_count ?? '—');
        text('stat-sessions', Object.keys(admin.active_sessions || {}).length);

        const ns = admin.network_state || {};
        const ep = admin.active_sessions
            ? null
            : null;
        const pubEp = admin.server_config
            ? '—'
            : '—';

        // Build public endpoint display from network state
        let epText = '—';
        if (ns.upnp_external_ip) {
            epText = `${ns.upnp_external_ip}:${ns.bound_port}`;
        } else if (ns.bound_port) {
            epText = `(local) :${ns.bound_port}`;
        }
        text('stat-endpoint', epText);
        text('stat-upnp',  ns.upnp_active ? 'On' : 'Off');
        text('stat-port',  ns.bound_port || '—');
        text('stat-mode',  admin.server_config?.local_mode ? 'Local' : 'Public');

        // Also refresh sessions panel if visible
        renderSessions(admin.active_sessions || {}, admin.relay_sessions || {});
    } else {
        text('uptime-label', '');
        ['stat-clients','stat-sessions','stat-endpoint','stat-upnp','stat-port','stat-mode']
            .forEach(id => text(id, data.admin_error ? 'N/A' : '—'));
    }
}

function serverAction(action) {
    return async () => {
        clearMsg('dashboard-msg');
        clearMsg('dashboard-err');
        const { ok, data } = await api.post(`/api/server/${action}`);
        if (ok) {
            const msg = el('dashboard-msg');
            msg.textContent = `${action.charAt(0).toUpperCase() + action.slice(1)} command sent.`;
            show(msg);
            setTimeout(() => { hide(msg); loadStatus(); }, 1500);
        } else {
            showError('dashboard-err', data.error || `${action} failed`);
        }
    };
}

el('btn-start').addEventListener('click',   serverAction('start'));
el('btn-stop').addEventListener('click',    serverAction('stop'));
el('btn-restart').addEventListener('click', serverAction('restart'));

// ================================================================
// Sessions
// ================================================================
async function loadSessions() {
    const { ok, data } = await api.get('/api/status');
    if (!ok || !data.admin) {
        el('sessions-tbody').innerHTML = `<tr><td colspan="5" class="empty-row">${data.admin_error || 'Server unreachable'}</td></tr>`;
        el('relay-tbody').innerHTML    = `<tr><td colspan="6" class="empty-row">${data.admin_error || 'Server unreachable'}</td></tr>`;
        return;
    }
    renderSessions(data.admin.active_sessions || {}, data.admin.relay_sessions || {});
}

function renderSessions(sessions, relays) {
    const tbody = el('sessions-tbody');
    const entries = Object.entries(sessions);
    if (!entries.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No active sessions</td></tr>';
    } else {
        tbody.innerHTML = entries.map(([bid, s]) => `
            <tr>
                <td style="font-family:monospace;font-size:.8rem">${escHtml(bid)}</td>
                <td>${s.is_online ? '<span style="color:var(--green)">●</span> Yes' : '<span style="color:var(--text-muted)">○</span> No'}</td>
                <td>${escHtml((s.public_ip || '?') + ':' + (s.public_port || '?'))}</td>
                <td>${escHtml((s.private_ip || '?') + ':' + (s.private_port || '?'))}</td>
                <td>${escHtml(s.last_seen_iso ? s.last_seen_iso.replace('T', ' ').slice(0, 19) + ' UTC' : '—')}</td>
            </tr>
        `).join('');
    }

    const rtbody = el('relay-tbody');
    const rEntries = Object.entries(relays);
    if (!rEntries.length) {
        rtbody.innerHTML = '<tr><td colspan="6" class="empty-row">No relay sessions</td></tr>';
    } else {
        rtbody.innerHTML = rEntries.map(([tok, r]) => `
            <tr>
                <td style="font-family:monospace;font-size:.75rem">${escHtml(tok.slice(0,12))}…</td>
                <td style="font-family:monospace;font-size:.8rem">${escHtml(r.from_bid || '?')}</td>
                <td style="font-family:monospace;font-size:.8rem">${escHtml(r.to_bid   || '?')}</td>
                <td>${r.from_connected ? '✓' : '○'}</td>
                <td>${r.to_connected   ? '✓' : '○'}</td>
                <td>${escHtml(fmtAge(r.created_ts))}</td>
            </tr>
        `).join('');
    }
}

// ================================================================
// Logs WebSocket
// ================================================================
function connectLogs() {
    if (wsConnection && wsConnection.readyState < 2) return;
    const wsUrl = `ws://${location.host}/ws/logs`;
    wsConnection = new WebSocket(wsUrl);
    const dot = el('ws-status');

    wsConnection.onopen = () => {
        dot.className = 'ws-status connected';
        dot.title = 'Connected';
    };

    wsConnection.onmessage = (ev) => {
        const box = el('log-box');
        box.textContent += ev.data + '\n';
        if (el('autoscroll-chk').checked) {
            box.scrollTop = box.scrollHeight;
        }
    };

    wsConnection.onclose = () => {
        dot.className = 'ws-status';
        dot.title = 'Disconnected';
    };

    wsConnection.onerror = () => {
        dot.className = 'ws-status';
        dot.title = 'Error';
    };
}

function disconnectLogs() {
    if (wsConnection) {
        wsConnection.close();
        wsConnection = null;
    }
    el('ws-status').className = 'ws-status';
}

el('clear-logs-btn').addEventListener('click', () => {
    el('log-box').textContent = '';
});

// ================================================================
// Users
// ================================================================
async function loadUsers() {
    const { ok, data } = await api.get('/api/users');
    const tbody = el('users-tbody');
    if (!ok) {
        tbody.innerHTML = `<tr><td colspan="3" class="empty-row">${escHtml(data.error || 'Failed to load')}</td></tr>`;
        return;
    }
    const users = data.users || [];
    if (!users.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty-row">No users registered</td></tr>';
        return;
    }
    tbody.innerHTML = users.map(u => `
        <tr>
            <td style="font-family:monospace;font-size:.8rem">${escHtml(u.bid)}</td>
            <td>${u.status === 'online'
                ? '<span style="color:var(--green)">● Online</span>'
                : '<span style="color:var(--text-muted)">○ Offline</span>'}</td>
            <td>
                <button class="btn btn-sm" onclick="openChpassModal('${escAttr(u.bid)}')">Change PW</button>
                <button class="btn btn-sm btn-red" style="margin-left:.4rem" onclick="deleteUser('${escAttr(u.bid)}')">Delete</button>
            </td>
        </tr>
    `).join('');
}

el('add-user-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearMsg('add-user-err');
    const bid  = el('new-bid').value.trim();
    const pass = el('new-pass').value;
    const { ok, data } = await api.post('/api/users', { bid, password: pass });
    if (ok) {
        el('new-bid').value = '';
        el('new-pass').value = '';
        loadUsers();
    } else {
        showError('add-user-err', data.error || 'Failed to add user');
    }
});

async function deleteUser(bid) {
    if (!confirm(`Delete user ${bid}?`)) return;
    const { ok, data } = await api.delete(`/api/users/${bid}`);
    if (ok) loadUsers();
    else alert(data.error || 'Delete failed');
}

// Change password modal
let chpassTargetBid = null;

function openChpassModal(bid) {
    chpassTargetBid = bid;
    el('chpass-bid-label').textContent = bid;
    el('chpass-input').value = '';
    clearMsg('chpass-err');
    show(el('chpass-modal'));
    el('chpass-input').focus();
}

el('chpass-cancel').addEventListener('click', () => hide(el('chpass-modal')));

el('chpass-confirm').addEventListener('click', async () => {
    clearMsg('chpass-err');
    const pw = el('chpass-input').value;
    if (!pw) return showError('chpass-err', 'Password cannot be empty');
    const { ok, data } = await api.patch(`/api/users/${chpassTargetBid}/password`, { password: pw });
    if (ok) {
        hide(el('chpass-modal'));
        loadUsers();
    } else {
        showError('chpass-err', data.error || 'Failed');
    }
});

// ================================================================
// Settings
// ================================================================
let currentSettings = null;

async function loadSettings() {
    const { ok, data } = await api.get('/api/settings');
    if (!ok) { showError('settings-err', data.error || 'Failed to load'); return; }
    clearMsg('settings-err');
    currentSettings = data;
    renderSettingsForm(data.server || {});
}

function renderSettingsForm(server) {
    const container = el('settings-fields');
    container.innerHTML = '';

    const fieldDefs = [
        { key: 'default_port',          label: 'Default Port',            type: 'number' },
        { key: 'bind_host',             label: 'Bind Host',               type: 'text'   },
        { key: 'listen_backlog',        label: 'Listen Backlog',          type: 'number' },
        { key: 'accept_timeout_sec',    label: 'Accept Timeout (sec)',    type: 'number' },
        { key: 'heartbeat_timeout_sec', label: 'Heartbeat Timeout (sec)', type: 'number' },
        { key: 'stun_timeout_sec',      label: 'STUN Timeout (sec)',      type: 'number' },
        { key: 'network_refresh_sec',   label: 'Network Refresh (sec)',   type: 'number' },
        { key: 'stun_servers',          label: 'STUN Servers (comma-separated)', type: 'text' },
        { key: 'local_mode',            label: 'Local Mode',              type: 'bool'   },
        { key: 'auto_network_bootstrap',label: 'Auto Bootstrap',          type: 'bool'   },
        { key: 'enable_upnp',           label: 'Enable UPnP',             type: 'bool'   },
        { key: 'enable_stun',           label: 'Enable STUN',             type: 'bool'   },
        { key: 'socket_keepalive',      label: 'Socket Keepalive',        type: 'bool'   },
    ];

    for (const { key, label, type } of fieldDefs) {
        const val = server[key];
        const div = document.createElement('div');
        div.className = 'setting-field';

        if (type === 'bool') {
            div.innerHTML = `
                <label for="sf-${key}">${escHtml(label)}</label>
                <div class="bool-row">
                    <input type="checkbox" id="sf-${key}" ${val ? 'checked' : ''} />
                    <span id="sf-${key}-lbl" style="font-size:.85rem;color:var(--text-muted)">${val ? 'Enabled' : 'Disabled'}</span>
                </div>`;
            const chk = div.querySelector(`#sf-${key}`);
            const lbl = div.querySelector(`#sf-${key}-lbl`);
            chk.addEventListener('change', () => {
                lbl.textContent = chk.checked ? 'Enabled' : 'Disabled';
            });
        } else if (key === 'stun_servers') {
            const display = Array.isArray(val) ? val.join(', ') : (val || '');
            div.innerHTML = `
                <label for="sf-${key}">${escHtml(label)}</label>
                <input type="text" id="sf-${key}" value="${escAttr(display)}" />`;
        } else {
            div.innerHTML = `
                <label for="sf-${key}">${escHtml(label)}</label>
                <input type="${type}" id="sf-${key}" value="${escAttr(String(val ?? ''))}"/>`;
        }
        container.appendChild(div);
    }
}

el('settings-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearMsg('settings-err');
    hide(el('settings-restart-notice'));

    const server = {};
    const fieldDefs = [
        { key: 'default_port',          type: 'number' },
        { key: 'bind_host',             type: 'text'   },
        { key: 'listen_backlog',        type: 'number' },
        { key: 'accept_timeout_sec',    type: 'float'  },
        { key: 'heartbeat_timeout_sec', type: 'number' },
        { key: 'stun_timeout_sec',      type: 'float'  },
        { key: 'network_refresh_sec',   type: 'number' },
        { key: 'stun_servers',          type: 'csv'    },
        { key: 'local_mode',            type: 'bool'   },
        { key: 'auto_network_bootstrap',type: 'bool'   },
        { key: 'enable_upnp',           type: 'bool'   },
        { key: 'enable_stun',           type: 'bool'   },
        { key: 'socket_keepalive',      type: 'bool'   },
    ];

    for (const { key, type } of fieldDefs) {
        const inp = el(`sf-${key}`);
        if (!inp) continue;
        if (type === 'bool')   server[key] = inp.checked;
        else if (type === 'number') server[key] = parseInt(inp.value, 10);
        else if (type === 'float')  server[key] = parseFloat(inp.value);
        else if (type === 'csv')    server[key] = inp.value.split(',').map(s => s.trim()).filter(Boolean);
        else                        server[key] = inp.value;
    }

    const payload = { ...(currentSettings || {}), server };
    const { ok, data } = await api.put('/api/settings', payload);
    if (ok) {
        show(el('settings-restart-notice'));
    } else {
        showError('settings-err', data.error || 'Save failed');
    }
});

// ================================================================
// GitHub Update
// ================================================================
el('update-btn').addEventListener('click', async () => {
    const btn = el('update-btn');
    const out = el('update-output');
    const err = el('update-err');

    btn.disabled = true;
    btn.textContent = 'Updating…';
    hide(err);
    out.textContent = 'Running update…';
    show(out);

    const { ok, data } = await api.post('/api/update');
    out.textContent = data.output || '(no output)';
    btn.disabled = false;
    btn.textContent = 'Pull & Update';

    if (!ok) {
        showError('update-err', data.error || 'Update failed');
    }
});

// ================================================================
// Security helpers
// ================================================================
function escHtml(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function escAttr(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;');
}

// ================================================================
// Boot
// ================================================================
init();
