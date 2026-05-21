'use strict';

const path = require('path');
const fs = require('fs');
const http = require('http');
const { execFile } = require('child_process');

const express = require('express');
const bcrypt = require('bcryptjs');

const router = express.Router();

const PANEL_CONFIG_PATH = path.join(__dirname, '..', 'panel-config.json');
const DATA_DIR = path.join(__dirname, '..', 'data');
const USERS_PATH = path.join(DATA_DIR, 'users.json');
const SETTINGS_PATH = path.join(DATA_DIR, 'settings.json');

const AUTH_SERVER_HOST = '127.0.0.1';
const STATS_PORT = parseInt(process.env.BNET_STATS_PORT || '30311', 10);
const ADMIN_TOKEN = process.env.BNET_ADMIN_TOKEN || '';

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

function requireAuth(req, res, next) {
    if (req.session && req.session.authenticated) return next();
    res.status(401).json({ error: 'Unauthorized' });
}

function readJson(filePath) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJson(filePath, data) {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 4), 'utf8');
}

/**
 * Query the auth server's HTTP stats endpoint on 127.0.0.1:30311.
 */
function queryAuthServer(token, timeoutMs = 4000) {
    return new Promise((resolve, reject) => {
        const req = http.get(
            { host: AUTH_SERVER_HOST, port: STATS_PORT, path: '/stats',
              headers: { Authorization: `Bearer ${token}` }, timeout: timeoutMs },
            (res) => {
                let body = '';
                res.on('data', (c) => { body += c; });
                res.on('end', () => {
                    if (res.statusCode === 401) return reject(new Error('Admin token rejected by server'));
                    if (res.statusCode !== 200) return reject(new Error(`Stats server returned ${res.statusCode}`));
                    try { resolve(JSON.parse(body)); }
                    catch (_) { reject(new Error('Malformed JSON from stats server')); }
                });
            }
        );
        req.on('timeout', () => { req.destroy(); reject(new Error('Stats server timeout')); });
        req.on('error', reject);
    });
}

function systemctlAction(action) {
    return new Promise((resolve, reject) => {
        execFile('sudo', ['systemctl', action, 'bnet-authserver'], (err, stdout, stderr) => {
            if (err) reject(new Error((stderr || '').trim() || err.message));
            else resolve((stdout || '').trim());
        });
    });
}

function systemctlIsActive() {
    return new Promise((resolve) => {
        execFile('sudo', ['systemctl', 'is-active', 'bnet-authserver'], (_err, stdout) => {
            resolve((stdout || '').trim());
        });
    });
}

// ---------------------------------------------------------------
// Auth
// ---------------------------------------------------------------

router.post('/login', async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Password required' });

        let config;
        try {
            config = readJson(PANEL_CONFIG_PATH);
        } catch (_) {
            return res.status(500).json({ error: 'Panel not configured. Run setup.sh first.' });
        }

        const match = await bcrypt.compare(String(password), config.admin_password_hash);
        if (!match) return res.status(401).json({ error: 'Invalid password' });

        req.session.authenticated = true;
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.post('/logout', requireAuth, (req, res) => {
    req.session.destroy(() => res.json({ ok: true }));
});

// Check if current session is valid (used by frontend on page load)
router.get('/me', (req, res) => {
    res.json({ authenticated: !!(req.session && req.session.authenticated) });
});

// ---------------------------------------------------------------
// Server status + control
// ---------------------------------------------------------------

router.get('/status', requireAuth, async (req, res) => {
    const serviceStatus = await systemctlIsActive();
    let adminData = null;
    let adminError = null;

    if (ADMIN_TOKEN) {
        try {
            adminData = await queryAuthServer(ADMIN_TOKEN);
        } catch (err) {
            adminError = err.message;
        }
    } else {
        adminError = 'BNET_ADMIN_TOKEN not configured in .env';
    }

    res.json({ service_status: serviceStatus, admin: adminData, admin_error: adminError });
});

router.post('/server/start', requireAuth, async (req, res) => {
    try { await systemctlAction('start'); res.json({ ok: true }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/server/stop', requireAuth, async (req, res) => {
    try { await systemctlAction('stop'); res.json({ ok: true }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/server/restart', requireAuth, async (req, res) => {
    try { await systemctlAction('restart'); res.json({ ok: true }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------------------------------------------------------
// User management
// ---------------------------------------------------------------

router.get('/users', requireAuth, (req, res) => {
    try {
        const data = readJson(USERS_PATH);
        const clients = (data.bNETauth_data || {}).clients || {};
        const users = Object.entries(clients).map(([bid, entry]) => ({
            bid,
            status: (entry.data || {}).status || 'offline',
        }));
        res.json({ users });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.post('/users', requireAuth, (req, res) => {
    try {
        const { bid, password } = req.body;
        if (!bid || !password) return res.status(400).json({ error: 'bid and password are required' });
        if (!/^[0-9a-fA-F]{32}$/.test(bid)) {
            return res.status(400).json({ error: 'bid must be exactly 32 hex characters' });
        }

        const data = readJson(USERS_PATH);
        const clients = data.bNETauth_data.clients;
        if (clients[bid]) return res.status(409).json({ error: 'User already exists' });

        clients[bid] = { password: String(password), data: { status: 'offline' } };
        writeJson(USERS_PATH, data);
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.delete('/users/:bid', requireAuth, (req, res) => {
    try {
        const { bid } = req.params;
        if (!/^[0-9a-fA-F]{32}$/.test(bid)) {
            return res.status(400).json({ error: 'Invalid bid format' });
        }

        const data = readJson(USERS_PATH);
        if (!data.bNETauth_data.clients[bid]) {
            return res.status(404).json({ error: 'User not found' });
        }
        delete data.bNETauth_data.clients[bid];
        writeJson(USERS_PATH, data);
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.patch('/users/:bid/password', requireAuth, (req, res) => {
    try {
        const { bid } = req.params;
        const { password } = req.body;

        if (!/^[0-9a-fA-F]{32}$/.test(bid)) {
            return res.status(400).json({ error: 'Invalid bid format' });
        }
        if (!password) return res.status(400).json({ error: 'password is required' });

        const data = readJson(USERS_PATH);
        if (!data.bNETauth_data.clients[bid]) {
            return res.status(404).json({ error: 'User not found' });
        }
        data.bNETauth_data.clients[bid].password = String(password);
        writeJson(USERS_PATH, data);
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------------------------------------------------------------
// Settings management
// ---------------------------------------------------------------

router.get('/settings', requireAuth, (req, res) => {
    try {
        res.json(readJson(SETTINGS_PATH));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.put('/settings', requireAuth, (req, res) => {
    try {
        const incoming = req.body;
        if (!incoming || typeof incoming !== 'object' || !incoming.server) {
            return res.status(400).json({ error: 'Invalid settings: must be an object with a "server" key' });
        }
        writeJson(SETTINGS_PATH, incoming);
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------------------------------------------------------------
// GitHub update
// ---------------------------------------------------------------

const UPDATE_SCRIPT = path.join(__dirname, '..', 'update.sh');

router.post('/update', requireAuth, (req, res) => {
    execFile('sudo', [UPDATE_SCRIPT], { timeout: 120000 }, (err, stdout, stderr) => {
        const output = (stdout + stderr).trim();
        const detail = err ? `[exit ${err.code}] ${err.message}` : '';
        if (err && err.code !== 0) {
            return res.status(500).json({ ok: false, output: output || detail });
        }
        res.json({ ok: true, output });
    });
});

module.exports = router;
