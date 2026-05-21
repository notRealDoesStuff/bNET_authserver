'use strict';

const path = require('path');
const http = require('http');
const { spawn } = require('child_process');

const express = require('express');
const session = require('express-session');
const { WebSocketServer } = require('ws');

const apiRouter = require('./routes/api');

const PANEL_PORT = parseInt(process.env.PANEL_PORT || '8888', 10);
const SESSION_SECRET = process.env.SESSION_SECRET || 'bnet-panel-default-secret-change-me';

const app = express();
const httpServer = http.createServer(app);

const sessionMiddleware = session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 8 * 60 * 60 * 1000, // 8 hours
    },
});

app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(sessionMiddleware);

// Static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// API routes
app.use('/api', apiRouter);

// --- WebSocket: live log streaming via journalctl ---
const wss = new WebSocketServer({ noServer: true });

httpServer.on('upgrade', (req, socket, head) => {
    if (req.url !== '/ws/logs') {
        socket.destroy();
        return;
    }
    // Authenticate via session cookie before upgrading
    sessionMiddleware(req, {}, () => {
        if (!req.session || !req.session.authenticated) {
            socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
            socket.destroy();
            return;
        }
        wss.handleUpgrade(req, socket, head, (ws) => {
            wss.emit('connection', ws, req);
        });
    });
});

wss.on('connection', (ws) => {
    const proc = spawn('journalctl', [
        '-f', '-u', 'bnet-authserver',
        '-n', '200',
        '--no-pager',
        '--output=short',
        '-q',
    ], { env: { ...process.env, TERM: 'dumb' } });

    // Strip ANSI escape codes
    const stripAnsi = (str) => str.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '');

    proc.stdout.on('data', (chunk) => {
        const lines = stripAnsi(chunk.toString()).split('\n');
        for (const line of lines) {
            if (line.trim() && ws.readyState === ws.OPEN) {
                ws.send(line);
            }
        }
    });

    proc.stderr.on('data', (chunk) => {
        const msg = stripAnsi(chunk.toString()).trim();
        // Suppress the "insufficient permissions" noise — handled by group membership
        if (msg && !msg.includes('No journal files') && !msg.includes('systemd-journal') && ws.readyState === ws.OPEN) {
            ws.send('[panel] ' + msg);
        }
    });

    proc.on('error', (err) => {
        if (ws.readyState === ws.OPEN) {
            ws.send(`[panel] journalctl unavailable: ${err.message}`);
        }
    });

    ws.on('close', () => {
        try { proc.kill(); } catch (_) {}
    });
});

httpServer.listen(PANEL_PORT, '0.0.0.0', () => {
    console.log(`[panel] bNET auth panel listening on http://0.0.0.0:${PANEL_PORT}`);
});
