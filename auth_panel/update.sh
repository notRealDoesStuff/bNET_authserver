#!/usr/bin/env bash
# bNET Panel — Update Script
# Called by the web panel via sudo. Do not run directly as bnet user.
set -euo pipefail

REPO_DIR="/opt/bNET"
PANEL_DIR="$REPO_DIR/bNET_authserver/auth_panel"

echo "[update] Pulling latest changes from GitHub..."
git -C "$REPO_DIR" pull

echo "[update] Installing Node.js dependencies..."
cd "$PANEL_DIR"
npm install --omit=dev

echo "[update] Restarting services..."
systemctl restart bnet-authserver bnet-panel

echo "[update] Done."
