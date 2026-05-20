#!/usr/bin/env bash
# =====================================================================
# bNET Auth Panel — Setup Script
# Run as root on Ubuntu 20.04:  sudo bash setup.sh
# =====================================================================
set -euo pipefail

INSTALL_DIR="/opt/bNET/bNET_authserver/auth_panel"
SERVICE_USER="bnet"
PANEL_PORT="8888"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
error() { echo -e "${RED}[error]${NC} $*" >&2; }

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo bash setup.sh)"
    exit 1
fi

echo ""
echo "  bNET Auth Panel — Setup"
echo "  Install dir : $INSTALL_DIR"
echo "  Panel port  : $PANEL_PORT"
echo ""

# --- Create system user ---
if ! id "$SERVICE_USER" &>/dev/null; then
    info "Creating system user '$SERVICE_USER'..."
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
    info "System user '$SERVICE_USER' already exists"
fi

# --- Grant bnet user access to systemctl for its own services ---
SUDOERS_FILE="/etc/sudoers.d/bnet-panel"
if [[ ! -f "$SUDOERS_FILE" ]]; then
    info "Writing sudoers rule for panel systemctl access..."
    cat > "$SUDOERS_FILE" <<'SUDOERS'
# Allow the bnet-panel Node.js process to control the auth server service
bnet ALL=(root) NOPASSWD: /usr/bin/systemctl start bnet-authserver, \
                           /usr/bin/systemctl stop bnet-authserver, \
                           /usr/bin/systemctl restart bnet-authserver, \
                           /usr/bin/systemctl is-active bnet-authserver
SUDOERS
    chmod 0440 "$SUDOERS_FILE"
    info "Sudoers rule written to $SUDOERS_FILE"
fi

# --- Install Node.js (via NodeSource) ---
if ! command -v node &>/dev/null || [[ "$(node --version | cut -d. -f1 | tr -d 'v')" -lt 16 ]]; then
    info "Installing Node.js 20.x via NodeSource..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
else
    info "Node.js $(node --version) is already installed"
fi

# --- Install Python deps ---
info "Installing Python dependencies..."
pip3 install upnpy 2>/dev/null || warn "pip3 install upnpy failed — UPnP will be unavailable"

# --- npm install ---
info "Installing Node.js panel dependencies..."
cd "$INSTALL_DIR"
npm install --omit=dev

# --- Admin password ---
echo ""
read -rsp "Set admin panel password: " ADMIN_PASS
echo ""
read -rsp "Confirm password: " ADMIN_PASS2
echo ""

if [[ "$ADMIN_PASS" != "$ADMIN_PASS2" ]]; then
    error "Passwords do not match. Aborting."
    exit 1
fi
if [[ ${#ADMIN_PASS} -lt 8 ]]; then
    error "Password must be at least 8 characters."
    exit 1
fi

info "Hashing admin password..."
ADMIN_HASH=$(node -e "
const b = require('bcryptjs');
process.stdout.write(b.hashSync(process.argv[1], 12));
" "$ADMIN_PASS")

# --- Generate secrets ---
info "Generating admin token and session secret..."
ADMIN_TOKEN=$(node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))")
SESSION_SECRET=$(node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))")

# --- Write panel-config.json ---
info "Writing panel-config.json..."
cat > "$INSTALL_DIR/panel-config.json" <<JSON
{
    "admin_password_hash": "$ADMIN_HASH"
}
JSON

# --- Write .env ---
info "Writing .env..."
cat > "$INSTALL_DIR/.env" <<ENV
BNET_ADMIN_TOKEN=$ADMIN_TOKEN
SESSION_SECRET=$SESSION_SECRET
PANEL_PORT=$PANEL_PORT
AUTH_SERVER_PORT=30301
ENV

chmod 600 "$INSTALL_DIR/.env" "$INSTALL_DIR/panel-config.json"

# --- Set ownership ---
info "Setting file ownership to $SERVICE_USER..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# --- Install systemd units ---
info "Installing systemd service units..."
cp "$INSTALL_DIR/systemd/bnet-authserver.service" /etc/systemd/system/bnet-authserver.service
cp "$INSTALL_DIR/systemd/bnet-panel.service"      /etc/systemd/system/bnet-panel.service
systemctl daemon-reload

# --- Enable and start ---
info "Enabling and starting services..."
systemctl enable bnet-authserver bnet-panel
systemctl start  bnet-authserver bnet-panel

echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "  Panel URL   : http://$(hostname -I | awk '{print $1}'):$PANEL_PORT"
echo "  Auth server : port 30301 (TCP + UDP)"
echo ""
echo "  Check status:"
echo "    systemctl status bnet-authserver"
echo "    systemctl status bnet-panel"
echo ""
echo "  View logs:"
echo "    journalctl -u bnet-authserver -f"
echo "    journalctl -u bnet-panel -f"
echo ""
