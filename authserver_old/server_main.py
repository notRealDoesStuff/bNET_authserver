
# =============================
# bNET Auth Server: Direct Exposure State Machine
# -------------------------------------------------
# This server exposes itself to the public internet using:
#   1. UPnP port mapping (if enabled)
#   2. STUN public endpoint discovery (if enabled)
#   3. Manual port forwarding (fallback)
#
# Manual Port-Forward Deployment Mode:
#   - Disable UPnP and STUN in data/settings.json or via environment variables.
#   - Manually forward the chosen port on your router to the server's LAN IP.
#   - The server will bind to the configured port and host, but will not attempt NAT traversal.
#   - See MANUAL_PORT_FORWARD_DEPLOYMENT.md for full instructions.
#
# UDP Auth Packet Structure (Direct Only):
#   - Stateless, challenge-response protocol over UDP
#   - No relay/tunnel/edge fields; all packets are direct
#   - See UDP_AUTH_PACKET_SPEC.md for field definitions and encoding
#
# The state machine is:
#   INIT -> UPNP -> (success/fail) -> STUN -> (success/fail) -> MANUAL
#   If UPnP or STUN succeed, server is READY (publicly reachable).
#   If both fail, server is PARTIAL (local only, manual intervention required).
#
# The GET_NETWORK_STATUS response reports:
#   NETWORK_STATUS::BOUND::<bound_port>::PUBLIC::<public_ip:public_port>::UPNP::<ON|OFF>
#
# See DIRECT_EXPOSURE_STATE_MACHINE.md, MANUAL_PORT_FORWARD_DEPLOYMENT.md, and UDP_AUTH_PACKET_SPEC.md for full details.
# =============================

import os
import socket
import struct
import time
import asyncio
import threading
import curses
import json
import sys
import errno
import upnpy
import base64
import secrets
from collections import deque
from datetime import datetime, timezone
import bnet_stun
def udp_auth_server(listen_port):
    """
    Stateless UDP authentication server for direct client connections.
    Handles HELLO, CHALLENGE, RESPONSE, AUTH_RESULT packets as per UDP_AUTH_PACKET_SPEC.md.
    Runs in its own daemon thread — must not be used as an asyncio task.
    """
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        udp_sock.bind((server_config.get("bind_host", "0.0.0.0"), listen_port))
    except Exception as e:
        log_message(f"UDP bind failed: {e}")
        return

    log_message(f"UDP auth server listening on port {listen_port}")

    # In-memory challenge state: { (client_addr, client_id): {nonce, salt, kdf, kdf_params, ts} }
    challenges = {}
    CHALLENGE_TIMEOUT = 30  # seconds

    while True:
        try:
            udp_sock.settimeout(1.0)
            try:
                data, addr = udp_sock.recvfrom(4096)
            except socket.timeout:
                # Periodically clean up expired challenges
                now = time.time()
                expired = [k for k, v in challenges.items() if now - v["ts"] > CHALLENGE_TIMEOUT]
                for k in expired:
                    challenges.pop(k, None)
                continue

            try:
                pkt = json.loads(data.decode("utf-8"))
            except Exception:
                log_message(f"UDP: Invalid JSON from {addr}")
                continue

            magic = pkt.get("magic")
            ptype = pkt.get("type")
            if magic != "bNET2":
                continue

            if ptype == "HELLO":
                client_id = pkt.get("client_id")
                client_nonce = pkt.get("nonce")
                version = pkt.get("version")
                if not client_id or not client_nonce:
                    continue
                # Generate challenge
                server_nonce = base64.b64encode(secrets.token_bytes(16)).decode()
                salt = base64.b64encode(secrets.token_bytes(16)).decode()
                kdf = "scrypt"
                kdf_params = {"N": 16384, "r": 8, "p": 1}
                challenges[(addr, client_id)] = {
                    "server_nonce": server_nonce,
                    "salt": salt,
                    "kdf": kdf,
                    "kdf_params": kdf_params,
                    "ts": time.time(),
                }
                resp = {
                    "magic": "bNET2",
                    "type": "CHALLENGE",
                    "server_nonce": server_nonce,
                    "salt": salt,
                    "kdf": kdf,
                    "kdf_params": kdf_params,
                }
                udp_sock.sendto(json.dumps(resp).encode("utf-8"), addr)
                log_message(f"UDP: Sent CHALLENGE to {addr} for {client_id}")

            elif ptype == "RESPONSE":
                client_id = pkt.get("client_id")
                response = pkt.get("response")
                key = (addr, client_id)
                ch = challenges.get(key)
                if not ch:
                    continue
                # Load user data and verify
                data = load_user_data()
                entry = data.get("bNETauth_data", {}).get("clients", {}).get(client_id)
                if not entry:
                    result = "ERROR_NOUSER"
                else:
                    password = entry.get("password")
                    # Derive key using scrypt
                    try:
                        import hashlib
                        salt_bytes = base64.b64decode(ch["salt"])
                        kdf_params = ch["kdf_params"]
                        key_bytes = hashlib.scrypt(password.encode(), salt=salt_bytes, n=kdf_params["N"], r=kdf_params["r"], p=kdf_params["p"], dklen=32)
                        # Compute HMAC(server_nonce, key)
                        import hmac
                        server_nonce_bytes = base64.b64decode(ch["server_nonce"])
                        expected = hmac.new(key_bytes, server_nonce_bytes, digestmod="sha256").digest()
                        expected_b64 = base64.b64encode(expected).decode()
                        if hmac.compare_digest(expected_b64, response):
                            result = "OK"
                        else:
                            result = "ERROR_BADPASS"
                    except Exception as e:
                        log_message(f"UDP: Auth error: {e}")
                        result = "ERROR_INTERNAL"
                # Send AUTH_RESULT
                pub_ip = auth_public_endpoint["public_ip"] if auth_public_endpoint else "UNKNOWN"
                pub_port = auth_public_endpoint["public_port"] if auth_public_endpoint else 0
                resp = {
                    "magic": "bNET2",
                    "type": "AUTH_RESULT",
                    "result": result,
                    "public_ip": pub_ip,
                    "public_port": pub_port,
                }
                udp_sock.sendto(json.dumps(resp).encode("utf-8"), addr)
                log_message(f"UDP: Sent AUTH_RESULT {result} to {addr} for {client_id}")
                challenges.pop(key, None)

            # Ignore other packet types for now
        except Exception as e:
            log_message(f"UDP server error: {e}")


def clear_term():
    os.system('cls' if os.name == 'nt' else 'clear')


version = "1"
protocol = "bNET"
protocol_ver = "2"
software_ver = "3025b"
software_name = "bNET Authentication Server"
software_author = "Bleached Development"

status = None
server_running = False

prelog_messages = []


def prelog(message):
    prelog_messages.append(message)


def show_prelog_and_exit():
    print("\n--- BLEACH PRELOG LOGGING SYSTEM ---")
    print("\nHalting due to critical error.")
    for msg in prelog_messages:
        print(msg)
    exit(1)


try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_storage_path = os.path.join(script_dir, 'data')
    default_userdata_path = os.path.join(default_storage_path, 'users.json')
    default_settings_path = os.path.join(default_storage_path, 'settings.json')
except Exception as e:
    prelog(f"Error initializing paths: {e}")
    show_prelog_and_exit()


throbberchars = ["|", "/", "—", "\\"]
throbberchars2 = ["_","—","‾"]

try:
    with open(
        os.path.join(script_dir, 'splash.bnet'), "r", encoding="utf-8"
    ) as f:
        splash_ascii = f.read()
except Exception as e:
    splash_ascii = f"Error loading splash: {e}"


total_logged = 0
last_logmessages = deque(maxlen=500)
log_messages_lock = threading.Lock()
server_started_ts = time.time()

clients = []
active_sessions = {}
auth_public_endpoint = None
network_state = {
    "bound_port": None,
    "upnp_active": False,
    "upnp_external_ip": None,
    "last_stun_refresh_ts": 0.0,
}

# Relay sessions: token → {from_bid, to_bid, from_sock, to_sock, created_ts}
# A relay session is created when a peer requests a relay to another peer.
# Both peers open a fresh TCP connection to auth and JOIN_RELAY; auth then
# pipes bytes between the two sockets so CGNAT / symmetric-NAT clients can
# communicate without any direct P2P path.
relay_sessions = {}
relay_sessions_lock = threading.Lock()
RELAY_SESSION_TIMEOUT_SEC = 120

# ── UDP relay state ────────────────────────────────────────────────────────────
# Peers that cannot hole-punch UDP register here so the auth server can forward
# binary audio (and future screen-share) frames between them.
#
# Registration frame (client → server):  [4B magic 0xBEEFCAFE][32B ASCII token][1B stream_type]
# Data frame        (client → server):   [4B relay_id BE][1B stream_type][...payload]
# ACK               (server → client):   [4B magic][0x00]
#
# relay_id is derived from the relay token: int(token[:8], 16)
_UDP_RELAY_MAGIC = 0xBEEFCAFE
_UDP_RELAY_MAGIC_BYTES = struct.pack("!I", _UDP_RELAY_MAGIC)

# relay_id (int) → {"token": str, "udp_slots": {stream_type(int): [from_addr|None, to_addr|None]}}
_udp_relay_sessions = {}
# (ip, port) → (relay_id, stream_type, peer_slot_idx)  where peer_slot_idx is the OTHER peer's slot
_udp_relay_map = {}
_udp_relay_lock = threading.Lock()


def _cleanup_udp_relay_session(relay_id):
    """Evict all UDP relay state for relay_id (called when the TCP pipe closes)."""
    with _udp_relay_lock:
        session = _udp_relay_sessions.pop(relay_id, None)
        if not session:
            return
        stale_addrs = [addr for addr, info in _udp_relay_map.items() if info[0] == relay_id]
        for addr in stale_addrs:
            _udp_relay_map.pop(addr, None)
    log_message(f"[relay-udp] Cleaned up UDP relay session relay_id={relay_id:#010x}")


def _relay_pipe(src_sock, dst_sock, label, relay_id=None):
    """Blocking pipe: forward bytes from src_sock to dst_sock until either closes."""
    try:
        while True:
            data = src_sock.recv(4096)
            if not data:
                break
            dst_sock.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src_sock, dst_sock):
            try:
                s.close()
            except Exception:
                pass
        log_message(f"[relay] pipe {label} closed")
        if relay_id is not None:
            _cleanup_udp_relay_session(relay_id)


def _udp_relay_loop(udp_relay_port):
    """Forward UDP audio/screen frames between relay-connected peers.

    Peers register by sending a registration frame; subsequent data frames are
    forwarded verbatim to the paired peer's registered address.
    """
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        udp_sock.bind((server_config.get("bind_host", "0.0.0.0"), udp_relay_port))
    except Exception as exc:
        log_message(f"[relay-udp] Bind failed on port {udp_relay_port}: {exc}")
        return
    log_message(f"[relay-udp] UDP relay listening on port {udp_relay_port}")

    while True:
        try:
            data, addr = udp_sock.recvfrom(8192)
        except Exception:
            continue

        if len(data) < 5:
            continue

        # Registration frame: [4B magic][32B token ASCII][1B stream_type] — total 37 bytes
        if data[:4] == _UDP_RELAY_MAGIC_BYTES and len(data) >= 37:
            try:
                token = data[4:36].decode("ascii")
                stream_type = data[36]
            except Exception:
                continue
            relay_id = int(token[:8], 16)
            with _udp_relay_lock:
                session = _udp_relay_sessions.get(relay_id)
                if session is None or session.get("token") != token:
                    # Unknown or expired session — ignore
                    continue
                slots = session["udp_slots"].setdefault(stream_type, [None, None])
                if addr == slots[0] or addr == slots[1]:
                    pass  # Re-registration: just re-ACK
                elif slots[0] is None:
                    slots[0] = addr
                    _udp_relay_map[addr] = (relay_id, stream_type, 1)  # forward to slot 1
                elif slots[1] is None:
                    slots[1] = addr
                    _udp_relay_map[addr] = (relay_id, stream_type, 0)  # forward to slot 0
                else:
                    continue  # Both slots full
            # Send ACK
            try:
                udp_sock.sendto(_UDP_RELAY_MAGIC_BYTES + b"\x00", addr)
            except Exception:
                pass
            log_message(
                f"[relay-udp] Registered {addr} relay_id={relay_id:#010x} stream={stream_type:#04x}"
            )
            continue

        # Data frame: [4B relay_id BE][1B stream_type][...payload]
        recv_relay_id = struct.unpack("!I", data[:4])[0]
        recv_stream_type = data[4]
        with _udp_relay_lock:
            info = _udp_relay_map.get(addr)
            if info is None:
                continue
            ri, st, peer_slot = info
            if ri != recv_relay_id or st != recv_stream_type:
                continue
            session = _udp_relay_sessions.get(ri)
            if session is None:
                continue
            slots = session["udp_slots"].get(st)
            if not slots:
                continue
            dst_addr = slots[peer_slot]
        if dst_addr is None:
            continue
        try:
            udp_sock.sendto(data, dst_addr)
        except Exception:
            pass


def _cleanup_stale_relay_sessions():
    now = time.time()
    with relay_sessions_lock:
        stale = [
            tok for tok, rs in relay_sessions.items()
            if now - rs.get("created_ts", 0) > RELAY_SESSION_TIMEOUT_SEC
        ]
        for tok in stale:
            for key in ("from_sock", "to_sock"):
                s = relay_sessions[tok].get(key)
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
            relay_sessions.pop(tok, None)
            _cleanup_udp_relay_session(int(tok[:8], 16))


server_config = {
    "default_port": 30301,
    "udp_relay_port": 30302,     # UDP port for audio/screen relay frames
    "local_mode": False,
    "bind_host": "0.0.0.0",
    "listen_backlog": 128,
    "accept_timeout_sec": 1.0,
    "heartbeat_timeout_sec": 90,
    "auto_network_bootstrap": True,
    "enable_upnp": True,
    "enable_stun": True,
    "stun_servers": [
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun.cloudflare.com:3478"
    ],
    "stun_timeout_sec": 2.0,
    "network_refresh_sec": 300,
    "socket_keepalive": True,
}


def now_utc_iso():
    return datetime.now(timezone.utc).isoformat()


def _parse_int(value, fallback):
    try:
        return int(value)
    except Exception:
        return fallback


def _parse_bool(value, fallback=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return fallback
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _parse_csv(value):
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if value is None:
        return []
    return [v.strip() for v in str(value).split(",") if v.strip()]


def env_override_config():
    # Environment overrides simplify deployment in containers and cloud hosts.
    env_map = {
        "BNET_AUTH_PORT": ("default_port", int),
        "BNET_AUTH_LOCAL_MODE": ("local_mode", bool),
        "BNET_AUTH_BIND_HOST": ("bind_host", str),
        "BNET_AUTH_BACKLOG": ("listen_backlog", int),
        "BNET_AUTH_ACCEPT_TIMEOUT": ("accept_timeout_sec", float),
        "BNET_AUTH_HEARTBEAT_TIMEOUT": ("heartbeat_timeout_sec", int),
        "BNET_AUTH_AUTO_BOOTSTRAP": ("auto_network_bootstrap", bool),
        "BNET_AUTH_ENABLE_UPNP": ("enable_upnp", bool),
        "BNET_AUTH_ENABLE_STUN": ("enable_stun", bool),
        "BNET_AUTH_STUN_TIMEOUT": ("stun_timeout_sec", float),
        "BNET_AUTH_NETWORK_REFRESH": ("network_refresh_sec", int),
        "BNET_AUTH_SOCKET_KEEPALIVE": ("socket_keepalive", bool),
    }

    for env_key, mapping in env_map.items():
        key, expected = mapping
        raw_value = os.getenv(env_key)
        if raw_value is None:
            continue
        try:
            if expected is int:
                server_config[key] = int(raw_value)
            elif expected is float:
                server_config[key] = float(raw_value)
            elif expected is bool:
                server_config[key] = _parse_bool(raw_value, server_config.get(key, False))
            else:
                server_config[key] = raw_value
        except Exception:
            log_message(f"Invalid value for {env_key}, keeping existing config")

    stun_env = os.getenv("BNET_AUTH_STUN_SERVERS")
    if stun_env:
        parsed = _parse_csv(stun_env)
        if parsed:
            server_config["stun_servers"] = parsed


def apply_local_mode_overrides():
    if not _parse_bool(server_config.get("local_mode"), False):
        return

    server_config["bind_host"] = "127.0.0.1"
    server_config["auto_network_bootstrap"] = False
    server_config["enable_upnp"] = False
    server_config["enable_stun"] = False


def get_network_mode_label():
    return "LOCAL" if _parse_bool(server_config.get("local_mode"), False) else "PUBLIC"


def detect_local_lan_ip():
    # Best-effort LAN IP detection for UPnP InternalClient selection.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        probe.close()


def get_upnp_wan_service():
    upnp = upnpy.UPnP()
    devices = upnp.discover(delay=2)
    if not devices:
        return None

    device = upnp.get_igd()
    if device is None:
        return None

    try:
        return device.get_service('urn:schemas-upnp-org:service:WANIPConnection:1')
    except Exception:
        try:
            return device.get_service('urn:schemas-upnp-org:service:WANPPPConnection:1')
        except Exception:
            return None


def discover_auth_public_endpoint(listen_port):
    global auth_public_endpoint

    if not _parse_bool(server_config.get("enable_stun"), True):
        log_message("STUN discovery disabled for auth server")
        return

    stun_servers = server_config.get("stun_servers", [])
    timeout = float(server_config.get("stun_timeout_sec", 2.0))

    discovery = bnet_stun.discover_public_endpoint(
        stun_servers=stun_servers,
        timeout=max(0.5, timeout),
        source_port=listen_port,
        logger=log_message,
    )
    if discovery:
        discovered_port = int(discovery["public_port"])
        if discovered_port != int(listen_port):
            log_message(
                f"STUN reported public port {discovered_port}, but using fixed connectable port {int(listen_port)}"
            )
        auth_public_endpoint = {
            "public_ip": discovery["public_ip"],
            "public_port": int(listen_port),
            "stun_server": discovery.get("stun_server", "unknown"),
        }
        log_message(
            f"Auth public endpoint detected: {auth_public_endpoint['public_ip']}:{auth_public_endpoint['public_port']}"
        )
        network_state["last_stun_refresh_ts"] = time.time()


def prune_stale_sessions():
    timeout = _parse_int(server_config.get("heartbeat_timeout_sec"), 90)
    now_ts = time.time()
    stale = []

    for bID, session in active_sessions.items():
        if now_ts - session.get("last_seen_ts", 0) > timeout:
            stale.append(bID)

    for bID in stale:
        active_sessions.pop(bID, None)
        try:
            with open(default_userdata_path, 'r') as json_file:
                data = json.load(json_file)
            if bID in data.get("bNETauth_data", {}).get("clients", {}):
                data["bNETauth_data"]["clients"][bID]["data"]["status"] = "offline"
                with open(default_userdata_path, 'w') as json_file:
                    json.dump(data, json_file, indent=4)
        except Exception:
            pass


def build_peer_response(this_clientbID):
    peers = []
    for bID, session in active_sessions.items():
        if bID == this_clientbID:
            continue
        if not session.get("is_online", False):
            continue

        pub_ip = session.get("public_ip")
        pub_port = session.get("public_port")
        priv_ip = session.get("private_ip")
        priv_port = session.get("private_port")

        if not pub_ip or not pub_port:
            continue
        if not priv_ip or not priv_port:
            continue

        # Format: bID;public_ip:public_port;private_ip:private_port
        peers.append(f"{bID};{pub_ip}:{pub_port};{priv_ip}:{priv_port}")

    return "PEERS::" + "::".join(peers) if peers else "PEERS::NONE"


def load_user_data():
    with open(default_userdata_path, 'r', encoding='utf-8') as json_file:
        data = json.load(json_file)
    return ensure_user_data_shape(data)


def save_user_data(data):
    with open(default_userdata_path, 'w', encoding='utf-8') as json_file:
        json.dump(data, json_file, indent=4)


def ensure_user_data_shape(data):
    if not isinstance(data, dict):
        data = {}
    auth_data = data.setdefault("bNETauth_data", {})
    clients_map = auth_data.setdefault("clients", {})
    if not isinstance(clients_map, dict):
        auth_data["clients"] = {}
        clients_map = auth_data["clients"]

    for bID, entry in list(clients_map.items()):
        if not isinstance(entry, dict):
            entry = {"password": "", "data": {}}
            clients_map[bID] = entry
        ensure_client_record(entry, bID)

    return data


def ensure_client_record(entry, bID, password=None):
    if not isinstance(entry, dict):
        entry = {}
    if password is not None and not entry.get("password"):
        entry["password"] = str(password)

    data = entry.setdefault("data", {})
    if not isinstance(data, dict):
        data = {}
        entry["data"] = data

    data.pop("nickname", None)
    data.pop("friends", None)
    data.pop("incoming_requests", None)
    data.pop("outgoing_requests", None)
    data.setdefault("status", "offline")
    return entry


def user_label_for(entry, bID):
    return str(bID)


def user_is_online(bID):
    session = active_sessions.get(bID, {})
    return bool(session.get("is_online", False))


def friend_record_for(bID, entry):
    return {
        "bid": str(bID),
        "nickname": user_label_for(entry, bID),
        "online": user_is_online(bID),
        "status": "online" if user_is_online(bID) else str(entry.get("data", {}).get("status", "offline")),
    }


def build_social_state(data, requester_bID):
    return {"friends": [], "incoming": [], "outgoing": []}


def build_user_search(data, requester_bID, query):
    clients_map = data.get("bNETauth_data", {}).get("clients", {})
    requester_entry = clients_map.get(requester_bID)
    requester_data = requester_entry.get("data", {}) if requester_entry else {}
    friends = set(requester_data.get("friends", []))
    incoming = set(requester_data.get("incoming_requests", []))
    outgoing = set(requester_data.get("outgoing_requests", []))
    needle = str(query or "").strip().lower()

    results = []
    for candidate_bid, candidate_entry in clients_map.items():
        if candidate_bid == requester_bID:
            continue
        candidate_name = user_label_for(candidate_entry, candidate_bid)
        haystack = f"{candidate_bid} {candidate_name}".lower()
        if needle and needle not in haystack:
            continue
        relation = "none"
        if candidate_bid in friends:
            relation = "friend"
        elif candidate_bid in incoming:
            relation = "incoming"
        elif candidate_bid in outgoing:
            relation = "outgoing"
        results.append({
            "bid": candidate_bid,
            "nickname": candidate_name,
            "online": user_is_online(candidate_bid),
            "relation": relation,
        })

    results.sort(key=lambda item: (0 if item["relation"] == "friend" else 1, item["nickname"].lower(), item["bid"]))
    return results[:25]


def build_friend_peer_response(requester_bID, data):
    return "PEERS::NONE"


def build_user_directory(data, requester_bID, query):
    clients_map = data.get("bNETauth_data", {}).get("clients", {})
    needle = str(query or "").strip().lower()
    results = []

    for candidate_bid, candidate_entry in clients_map.items():
        if candidate_bid == requester_bID:
            continue
        if needle and needle not in candidate_bid.lower():
            continue
        results.append({
            "bid": candidate_bid,
            "online": user_is_online(candidate_bid),
        })

    results.sort(key=lambda item: ((not item.get("online", False)), item.get("bid", "")))
    return results[:50]


def authenticate_request(data, bID, password):
    clients_map = data.get("bNETauth_data", {}).get("clients", {})
    entry = clients_map.get(bID)
    if not entry:
        return None, "AUTH::FAILED::UNKNOWN_BID"
    if entry.get("password") != password:
        return None, "AUTH::FAILED::BAD_PASSWORD"
    ensure_client_record(entry, bID)
    return entry, None


def is_http_request(request_text):
    try:
        first_line = request_text.splitlines()[0] if request_text else ""
    except Exception:
        first_line = ""
    methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
    return first_line.startswith(methods) and "HTTP/" in first_line


def build_http_notice_response():
    body = "<html><body><h1>this is a bnet auth server. theres nothing here for you</h1></body></html>"
    headers = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body.encode('utf-8'))}",
        "Connection: close",
        "Cache-Control: no-store",
        "",
        "",
    ]
    return "\r\n".join(headers).encode("utf-8") + body.encode("utf-8")


class Client:
    def __init__(self, sock, address=None):
        self.socket = sock
        try:
            self.address = address if address is not None else self.socket.getpeername()
        except OSError:
            self.address = ("unknown", 0)
        self.conn_port = None
        self.bID = None
        # Set to True when this connection transitions to relay-pipe mode.
        # The finally block in handle_client will skip the normal socket close
        # so the relay pipe threads own the socket lifetime.
        self.relay_mode = False

    def __str__(self):
        return f"Client({self.address[0]}:{self.address[1]})"


def log_message(message):
    global total_logged

    # Keep log lines single-line and bounded so curses rendering stays stable.
    safe_message = str(message).replace("\r", " ").replace("\n", " ")
    safe_message = " ".join(safe_message.split())
    max_len = 180
    if len(safe_message) > max_len:
        safe_message = safe_message[:max_len - 3] + "..."

    with log_messages_lock:
        last_logmessages.append(f'[{total_logged}] {safe_message}')
        total_logged += 1


def clear_log_messages():
    global total_logged
    with log_messages_lock:
        last_logmessages.clear()
        last_logmessages.append(f'[{total_logged}] Console log cleared')
        total_logged += 1


def get_log_snapshot():
    with log_messages_lock:
        return list(last_logmessages)


def build_console_state():
    return {
        "input_buffer": "",
        "history": [],
        "history_index": None,
        "current_tab": "overview",
        "log_top_index": 0,
        "connection_top_index": 0,
        "follow_logs": True,
        "throbber_index": 0,
        "last_throbber_update": time.time(),
        "last_cursor_flash": time.time(),
        "cursor_visible": True,
    }


def _trim_text(value, width):
    text = str(value or "")
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[:width - 3] + "..."


def safe_addstr(stdscr, y, x, text, width=None):
    try:
        height, screen_width = stdscr.getmaxyx()
    except Exception:
        height, screen_width = 24, 80

    if y < 0 or y >= height or x >= screen_width:
        return

    available = max(0, screen_width - x)
    if width is not None:
        available = min(available, width)
    if available <= 0:
        return

    rendered = _trim_text(text, available)
    try:
        stdscr.addstr(y, x, rendered)
    except curses.error:
        pass


def format_duration(seconds):
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02}:{minutes:02}:{secs:02}"
    return f"{minutes:02}:{secs:02}"


def get_connectable_label():
    if auth_public_endpoint:
        return f"{auth_public_endpoint['public_ip']}:{auth_public_endpoint['public_port']}"

    bind_host = str(server_config.get("bind_host", "0.0.0.0")).strip() or "0.0.0.0"
    display_host = "127.0.0.1" if bind_host in {"", "0.0.0.0"} else bind_host
    bound_port = network_state.get("bound_port") or server_config.get("default_port") or "?"
    return f"{display_host}:{bound_port} (local/fallback)"


def build_network_summary_text():
    public = "UNKNOWN"
    if auth_public_endpoint:
        public = f"{auth_public_endpoint['public_ip']}:{auth_public_endpoint['public_port']}"

    mode = get_network_mode_label()
    bound_port = network_state.get("bound_port") or server_config.get("default_port") or "UNKNOWN"
    upnp = "ON" if network_state.get("upnp_active") else "OFF"
    last_stun = network_state.get("last_stun_refresh_ts", 0.0)
    if last_stun:
        stun_age = format_duration(time.time() - last_stun) + " ago"
    else:
        stun_age = "never"

    return f"mode={mode} bound={bound_port} public={public} upnp={upnp} stun_refresh={stun_age}"


def build_status_panel_lines():
    uptime = format_duration(time.time() - server_started_ts)
    public = "UNKNOWN"
    if auth_public_endpoint:
        public = f"{auth_public_endpoint['public_ip']}:{auth_public_endpoint['public_port']}"

    last_stun = network_state.get("last_stun_refresh_ts", 0.0)
    stun_age = "never" if not last_stun else format_duration(time.time() - last_stun) + " ago"

    return [
        "Status",
        f"Runtime: {'up' if server_running else 'down'}",
        f"State: {status}",
        f"Mode: {get_network_mode_label().lower()}",
        f"Uptime: {uptime}",
        f"Clients: {len(clients)}",
        f"Sessions: {len(active_sessions)}",
        f"Bound: {network_state.get('bound_port') or server_config.get('default_port') or '?'}",
        f"Public: {public}",
        f"UPnP: {'on' if network_state.get('upnp_active') else 'off'}",
        f"STUN: {stun_age}",
        f"Logs: {len(get_log_snapshot())}/{last_logmessages.maxlen}",
    ]


COMMAND_HELP = {
    "help": "Show available console commands",
    "status": "Print the current server status line",
    "network": "Print the current direct exposure summary",
    "sessions": "Print active session summaries",
    "clients": "Print connected client socket details",
    "test-listpeers": "Run the existing peer list diagnostic",
    "clear": "Clear the in-memory console log buffer",
    "exit": "Stop the console and exit the auth server",
}

CONSOLE_TABS = ["overview", "logs", "connections"]


def rotate_tab(current_tab, direction):
    try:
        current_index = CONSOLE_TABS.index(current_tab)
    except ValueError:
        current_index = 0
    return CONSOLE_TABS[(current_index + direction) % len(CONSOLE_TABS)]


def build_tab_line(current_tab):
    labels = []
    for tab in CONSOLE_TABS:
        label = tab.upper()
        if tab == current_tab:
            labels.append(f"[{label}]")
        else:
            labels.append(f" {label} ")
    return "Tabs: " + " | ".join(labels)


def get_client_snapshot():
    rows = []
    for client in list(clients):
        try:
            addr = client.socket.getpeername()
        except Exception:
            addr = getattr(client, "address", ("unknown", 0))
        rows.append({
            "remote": f"{addr[0]}:{addr[1]}",
            "bid": getattr(client, "bID", None) or "-",
            "conn_port": str(getattr(client, "conn_port", None) or "-"),
        })
    rows.sort(key=lambda row: (row["bid"], row["remote"]))
    return rows


def build_connections_lines():
    lines = [
        f"TCP clients: {len(clients)} | Active sessions: {len(active_sessions)}",
        "",
        "TCP client sockets",
    ]

    client_rows = get_client_snapshot()
    if not client_rows:
        lines.append("  none")
    else:
        lines.append("  remote                  bID                              listen")
        for row in client_rows:
            lines.append(
                f"  {_trim_text(row['remote'], 22):22} {_trim_text(row['bid'], 32):32} {_trim_text(row['conn_port'], 6):6}"
            )

    lines.extend(["", "Auth sessions"])
    if not active_sessions:
        lines.append("  none")
    else:
        lines.append("  bID                              online public                  private                 last_seen")
        for bid, session in sorted(active_sessions.items()):
            public = f"{session.get('public_ip') or '?'}:{session.get('public_port') or '?'}"
            private = f"{session.get('private_ip') or '?'}:{session.get('private_port') or '?'}"
            last_seen_iso = session.get("last_seen_iso") or "-"
            lines.append(
                "  "
                + f"{_trim_text(bid, 32):32} "
                + f"{('yes' if session.get('is_online') else 'no'):6} "
                + f"{_trim_text(public, 22):22} "
                + f"{_trim_text(private, 22):22} "
                + f"{_trim_text(last_seen_iso, 19):19}"
            )

    return lines


def get_tab_lines(console_state):
    current_tab = console_state.get("current_tab", "overview")
    if current_tab == "connections":
        return "Connections", build_connections_lines(), "connection_top_index"
    if current_tab == "logs":
        logs = [f"# {entry}" for entry in get_log_snapshot()]
        return f"Logs {len(logs)}/{last_logmessages.maxlen}", logs or ["# no log messages yet"], "log_top_index"

    logs = get_log_snapshot()
    recent_logs = [f"# {entry}" for entry in logs[-200:]] or ["# no log messages yet"]
    return f"Overview | recent logs {len(recent_logs)}", recent_logs, "log_top_index"


def compute_view_window(console_state, row_count, visible_rows, index_key):
    max_top_index = max(0, row_count - visible_rows)
    if index_key == "log_top_index" and console_state.get("follow_logs", True):
        top_index = max_top_index
        console_state[index_key] = top_index
    else:
        top_index = min(max(console_state.get(index_key, 0), 0), max_top_index)
        console_state[index_key] = top_index
    return top_index, max_top_index


def splash(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(0)
    stdscr.clear()

    splash_lines = splash_ascii.split("0\n")
    try:
        height, width = stdscr.getmaxyx()
    except Exception:
        _, width = 24, 80  # Fallback to default terminal size

    for idx, line in enumerate(splash_lines):
        line = line.rstrip()
        try:
            stdscr.addstr(0 + idx, 0, line[:width-1])
        except curses.error:
            pass  # Ignore drawing errors if terminal is too small

    stdscr.refresh()
    time.sleep(1)


def draw_console_ui(stdscr, throbber_char, console_state):
    height, width = stdscr.getmaxyx()
    is_split_layout = width >= 120 and height >= 18

    stdscr.erase()

    safe_addstr(stdscr, 0, 0, f"####### bNET auth v{version} ########")
    safe_addstr(stdscr, 1, 0, f"Protocol: {protocol} v{protocol_ver} | Software: {software_ver}")
    runmarker = "running" if server_running else "stopped"
    safe_addstr(stdscr, 2, 0, f"Server: {runmarker} {throbber_char} | Clients: {len(clients)} | Sessions: {len(active_sessions)}")
    safe_addstr(stdscr, 3, 0, f"Connectable: {get_connectable_label()}")
    safe_addstr(stdscr, 4, 0, f"Status: {status}")
    safe_addstr(stdscr, 5, 0, build_tab_line(console_state.get("current_tab", "overview")), width)

    footer_hint_y = max(6, height - 2)
    footer_input_y = max(7, height - 1)
    body_top = 7
    body_bottom = max(body_top, footer_hint_y - 1)
    body_height = max(1, body_bottom - body_top)

    status_width = 34 if is_split_layout else 0
    log_width = width if not is_split_layout else max(20, width - status_width - 1)
    log_x = 0
    status_x = log_width + 1

    content_title, content_lines, index_key = get_tab_lines(console_state)
    visible_rows = max(1, body_height - 1)
    top_index, max_top_index = compute_view_window(console_state, len(content_lines), visible_rows, index_key)

    if index_key == "log_top_index" and not console_state.get("follow_logs", True):
        content_title += f" | scroll {top_index + 1}-{min(len(content_lines), top_index + visible_rows)}"
    elif index_key != "log_top_index" and len(content_lines) > visible_rows:
        content_title += f" | rows {top_index + 1}-{min(len(content_lines), top_index + visible_rows)}"

    safe_addstr(stdscr, body_top, log_x, content_title, log_width)
    visible_lines = content_lines[top_index:top_index + visible_rows]
    for idx, line in enumerate(visible_lines):
        safe_addstr(stdscr, body_top + 1 + idx, log_x, line, log_width)

    if is_split_layout:
        panel_lines = build_status_panel_lines()
        for idx, line in enumerate(panel_lines[:body_height]):
            safe_addstr(stdscr, body_top + idx, status_x, line, status_width)

    hints = "Keys: Tab/Shift+Tab or Left/Right switch tabs | Up/Down history | PgUp/PgDn scroll | End live tail | Ctrl+C exit"
    safe_addstr(stdscr, footer_hint_y, 0, hints, width)
    prompt = "Input: "
    available_input_width = max(0, width - len(prompt))
    rendered_input = _trim_text(console_state["input_buffer"], available_input_width)
    safe_addstr(stdscr, footer_input_y, 0, prompt, width)
    safe_addstr(stdscr, footer_input_y, len(prompt), rendered_input, available_input_width)

    cursor_x = min(width - 1, len(prompt) + len(rendered_input)) if width > 0 else 0
    try:
        stdscr.move(footer_input_y, cursor_x)
    except curses.error:
        pass
    stdscr.refresh()


def console(stdscr):
    global status

    console_state = build_console_state()

    curses.curs_set(1)  # Show the cursor
    stdscr.nodelay(1)   # Don't block on input
    stdscr.keypad(True)
    stdscr.clear()

    while True:
        current_time = time.time()

        if current_time - console_state["last_throbber_update"] >= 0.35:
            throbber_char = throbberchars2[console_state["throbber_index"] % len(throbberchars2)]
            console_state["last_throbber_update"] = current_time
            console_state["throbber_index"] += 1
        else:
            throbber_char = throbberchars2[(console_state["throbber_index"] - 1) % len(throbberchars2)]

        if current_time - console_state["last_cursor_flash"] >= 1:
            console_state["cursor_visible"] = not console_state["cursor_visible"]
            try:
                curses.curs_set(1 if console_state["cursor_visible"] else 0)
            except curses.error:
                pass
            console_state["last_cursor_flash"] = current_time

        draw_console_ui(stdscr, throbber_char or "$", console_state)

        key = stdscr.getch()  # Get user input
        if key != -1:
            current_tab = console_state.get("current_tab", "overview")
            if current_tab == "connections":
                row_count = len(build_connections_lines())
                active_index_key = "connection_top_index"
            elif current_tab == "logs":
                row_count = len(get_log_snapshot())
                active_index_key = "log_top_index"
            else:
                row_count = min(200, len(get_log_snapshot()))
                active_index_key = "log_top_index"

            height, _ = stdscr.getmaxyx()
            max_log_rows = max(1, max(6, height - 2) - 8)
            max_top_index = max(0, row_count - max_log_rows)

            if key in (curses.KEY_BACKSPACE, 127, 8):  # Handle backspace
                console_state["input_buffer"] = console_state["input_buffer"][:-1]
                console_state["history_index"] = None
                try:
                    curses.curs_set(1)
                except curses.error:
                    pass
            elif key in (9, curses.KEY_RIGHT):
                console_state["current_tab"] = rotate_tab(console_state.get("current_tab", "overview"), 1)
                console_state["follow_logs"] = console_state["current_tab"] != "connections"
            elif key in (curses.KEY_BTAB, curses.KEY_LEFT):
                console_state["current_tab"] = rotate_tab(console_state.get("current_tab", "overview"), -1)
                console_state["follow_logs"] = console_state["current_tab"] != "connections"
            elif key == curses.KEY_UP:
                history = console_state["history"]
                if history:
                    if console_state["history_index"] is None:
                        console_state["history_index"] = len(history) - 1
                    else:
                        console_state["history_index"] = max(0, console_state["history_index"] - 1)
                    console_state["input_buffer"] = history[console_state["history_index"]]
            elif key == curses.KEY_DOWN:
                history = console_state["history"]
                if history:
                    if console_state["history_index"] is None:
                        continue
                    console_state["history_index"] += 1
                    if console_state["history_index"] >= len(history):
                        console_state["history_index"] = None
                        console_state["input_buffer"] = ""
                    else:
                        console_state["input_buffer"] = history[console_state["history_index"]]
            elif key == curses.KEY_PPAGE:
                current_top = max_top_index if (active_index_key == "log_top_index" and console_state["follow_logs"]) else console_state[active_index_key]
                if active_index_key == "log_top_index":
                    console_state["follow_logs"] = False
                console_state[active_index_key] = max(0, current_top - max(3, max_log_rows - 2))
            elif key == curses.KEY_NPAGE:
                current_top = max_top_index if (active_index_key == "log_top_index" and console_state["follow_logs"]) else console_state[active_index_key]
                console_state[active_index_key] = min(max_top_index, current_top + max(3, max_log_rows - 2))
                if active_index_key == "log_top_index":
                    console_state["follow_logs"] = console_state[active_index_key] >= max_top_index
            elif key == curses.KEY_HOME:
                if active_index_key == "log_top_index":
                    console_state["follow_logs"] = False
                console_state[active_index_key] = 0
            elif key == curses.KEY_END:
                console_state[active_index_key] = max_top_index
                if active_index_key == "log_top_index":
                    console_state["follow_logs"] = True
            elif key == 3:
                log_message("Received Ctrl+C, shutting down console")
                status = "Exiting..."
                return
            elif key == 10:  # Enter key
                command = console_state["input_buffer"].strip()
                if command:
                    if not console_state["history"] or console_state["history"][-1] != command:
                        console_state["history"].append(command)
                        if len(console_state["history"]) > 50:
                            console_state["history"] = console_state["history"][-50:]
                console_state["history_index"] = None
                should_continue = handle_command(command)
                console_state["input_buffer"] = ""
                console_state["follow_logs"] = True
                if not should_continue:
                    return
            elif 32 <= key <= 126:  # Printable characters
                console_state["input_buffer"] += chr(key)
                console_state["history_index"] = None
                try:
                    curses.curs_set(1)
                except curses.error:
                    pass

        time.sleep(0.01)  # Throttle the loop to avoid high CPU usage


def handle_command(command):
    global status

    command = str(command or "").strip()
    if not command:
        return True

    lowered = command.lower()

    if lowered == "help":
        log_message("Available commands:")
        for name, description in COMMAND_HELP.items():
            log_message(f" - {name}: {description}")
    elif lowered == "status":
        log_message(f"Current status: {status}")
    elif lowered == "network":
        log_message(f"Network: {build_network_summary_text()}")
    elif lowered == "sessions":
        if not active_sessions:
            log_message("Active sessions: none")
        else:
            log_message(f"Active sessions: {len(active_sessions)}")
            for bID, session in sorted(active_sessions.items()):
                summary = (
                    f" - {bID} online={session.get('is_online', False)} "
                    f"pub={session.get('public_ip')}:{session.get('public_port')} "
                    f"priv={session.get('private_ip')}:{session.get('private_port')}"
                )
                log_message(summary)
    elif lowered == "clear":
        clear_log_messages()
    elif lowered == "exit":
        log_message("killing server...")
        status = "Exiting..."
        return False
    elif lowered == "test-listpeers":

        peers = []

        this_clientbID = "000000000000000000000000000000" # Dummy bID for testing

        try:
            with open(default_userdata_path, 'r') as json_file:
                        data = json.load(json_file)

            for bID, info in data["bNETauth_data"]["clients"].items():
                if info["data"]["status"] == "offline" and bID != this_clientbID:
                    # fake a client connection for testing
                    peer_ip = "0.0.0.0"
                    peer_port = "00000"
                    # create tuple of bID,IP,PORT
                    peer_entry = f"{bID};{peer_ip}:{peer_port}"
                    peers.append(peer_entry)

            response = "PEERS::" + "::".join(peers) if peers else "PEERS::NONE"
            log_message(f"Test LISTPEERS result: {response}")
        except Exception as e:
            log_message(f"Error reading user data: {e}")
    elif lowered == "clients":
        log_message(f"Connected clients: {len(clients)}")
        for c in clients:
            try:
                addr = c.socket.getpeername()
                log_message(f" - {addr[0]}:{addr[1]} conn_port: {getattr(c,'conn_port', None)} bID: {getattr(c,'bID', None)}")
            except Exception:
                log_message(f" - <disconnected client> conn_port: {getattr(c,'conn_port', None)} bID: {getattr(c,'bID', None)}")
    else:
        log_message(f"Unknown command: {command}")
        log_message("Type 'help' to list console commands")

    return True  # Continue running the loop


# punch hole in NAT/firewall if possible
def nat_punch_hole(port):
    log_message("Attempting NAT hole punch via UPnP...")
    try:
        service = get_upnp_wan_service()
        if service is None:
            log_message("No UPnP WAN service found, skipping NAT punch")
            return None
        
        service.AddPortMapping(
            NewRemoteHost='',
            NewExternalPort=port,
            NewProtocol='TCP',
            NewInternalPort=port,
            NewInternalClient=detect_local_lan_ip(),
            NewEnabled='1',
            NewPortMappingDescription='bNET Auth Server',
            NewLeaseDuration='0'
        )

        external_ip = None
        try:
            external_ip = service.GetExternalIPAddress().get("NewExternalIPAddress")
        except Exception:
            pass
        
        log_message(f"UPnP port mapping successful for port {port}")
        if external_ip:
            log_message(f"UPnP external IP: {external_ip}")
        return {
            "external_ip": external_ip,
            "external_port": int(port),
            "internal_port": int(port),
        }
    except Exception as e:
        if isinstance(e, ImportError):
            log_message("UPnP library not available, skipping NAT punch")
        else:
            log_message(f"NAT punch hole failed: {e}")
            log_message("Continuing without NAT traversal...")
        return None


def apply_upnp_mapping(listen_port):
    mapping = nat_punch_hole(listen_port)
    if not mapping:
        network_state["upnp_active"] = False
        network_state["upnp_external_ip"] = None
        return

    network_state["upnp_active"] = True
    network_state["upnp_external_ip"] = mapping.get("external_ip")
    if mapping.get("external_ip"):
        global auth_public_endpoint
        auth_public_endpoint = {
            "public_ip": mapping["external_ip"],
            "public_port": int(mapping.get("external_port", listen_port)),
            "stun_server": "UPNP",
        }


def bootstrap_network_access(listen_port):
    global auth_public_endpoint
    network_state["bound_port"] = int(listen_port)
    network_state["upnp_active"] = False
    network_state["upnp_external_ip"] = None
    auth_public_endpoint = None

    if _parse_bool(server_config.get("local_mode"), False):
        log_message("Local mode enabled: skipping UPnP and STUN bootstrap")
        return

    if _parse_bool(server_config.get("enable_upnp"), True):
        apply_upnp_mapping(listen_port)

    discover_auth_public_endpoint(listen_port)

    if auth_public_endpoint:
        log_message(
            f"Internet bootstrap ready at {auth_public_endpoint['public_ip']}:{auth_public_endpoint['public_port']}"
        )
    else:
        log_message("Internet bootstrap incomplete: no public endpoint detected yet")


def periodic_network_maintenance(listen_port):
    if _parse_bool(server_config.get("local_mode"), False):
        return

    refresh_interval = max(30, _parse_int(server_config.get("network_refresh_sec"), 300))
    last_upnp_ts = 0.0
    while True:
        try:
            now_ts = time.time()
            upnp_attempted = False

            # Re-assert mapping before STUN so discovery reflects current NAT state.
            if _parse_bool(server_config.get("enable_upnp"), True):
                if now_ts - last_upnp_ts >= refresh_interval:
                    apply_upnp_mapping(listen_port)
                    last_upnp_ts = now_ts
                    upnp_attempted = True

            if _parse_bool(server_config.get("enable_stun"), True):
                if now_ts - network_state.get("last_stun_refresh_ts", 0.0) >= refresh_interval:
                    # If UPnP is enabled, prefer STUN immediately after an UPnP attempt.
                    if (not _parse_bool(server_config.get("enable_upnp"), True)) or upnp_attempted:
                        discover_auth_public_endpoint(listen_port)
                    else:
                        # If no UPnP cycle happened yet, wait for next loop to preserve ordering.
                        pass
        except Exception as e:
            log_message(f"Network maintenance error: {e}")

        time.sleep(5)

default_port = 0  # Default port, will be overridden by settings

async def run_server():
    global status
    global server_running

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if _parse_bool(server_config.get("socket_keepalive"), True):
        try:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

    if _parse_bool(server_config.get("local_mode"), False):
        server_ip = "127.0.0.1"
    else:
        configured_host = str(server_config.get("bind_host", "0.0.0.0")).strip()
        server_ip = configured_host if configured_host else "0.0.0.0"

    # Try to set SO_REUSEPORT if available (helps on some POSIX systems)
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass

    base_port = _parse_int(server_config.get("default_port"), default_port)
    port = base_port
    try:
        server.bind((server_ip, port))
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            log_message(f"Required port {port} is already in use. Auth server requires a fixed connectable port.")
            raise SystemExit(1)
        log_message(f"Failed to bind socket on required port {port}: {e}")
        raise

    backlog = _parse_int(server_config.get("listen_backlog"), 128)
    server.listen(backlog)
    server.settimeout(float(server_config.get("accept_timeout_sec", 1.0)))


    if _parse_bool(server_config.get("auto_network_bootstrap"), True):
        bootstrap_network_access(port)
        if not _parse_bool(server_config.get("local_mode"), False):
            maint = threading.Thread(target=periodic_network_maintenance, args=(port,), daemon=True)
            maint.start()
    else:
        # Explicit fallback path when bootstrap automation is disabled.
        network_state["bound_port"] = int(port)
        network_state["upnp_active"] = False
        network_state["upnp_external_ip"] = None
        if not _parse_bool(server_config.get("local_mode"), False) and _parse_bool(server_config.get("enable_upnp"), True):
            apply_upnp_mapping(port)
        if not _parse_bool(server_config.get("local_mode"), False):
            discover_auth_public_endpoint(port)

    # Start UDP auth server in a daemon thread — it uses blocking socket I/O
    # and must not run as an asyncio task or it will starve the event loop.
    udp_thread = threading.Thread(target=udp_auth_server, args=(port,), daemon=True)
    udp_thread.start()

    # Start UDP relay loop for audio/screen forwarding between relay-connected peers.
    _udp_relay_port = server_config.get("udp_relay_port", 30302)
    udp_relay_thread = threading.Thread(
        target=_udp_relay_loop, args=(_udp_relay_port,), daemon=True
    )
    udp_relay_thread.start()

    server_running = True
    log_message(f"Listening on {server.getsockname()}")
    status = "Listening..."

    last_title_update_ts = 0.0
    while True:
        try:
            if os.name == 'nt':
                now_ts = time.time()
                if now_ts - last_title_update_ts >= 2.0:
                    last_title_update_ts = now_ts
                    threading.Thread(
                        target=os.system,
                        args=('title bNET Auth - Status: ' + status,),
                        daemon=True,
                    ).start()
        except Exception:
            pass

        try:
            prune_stale_sessions()
            client_socket, client_address = \
                await \
                asyncio.get_event_loop().run_in_executor(
                    None,
                    server.accept
                    )

            log_message(f"Accepted connection from {client_address[0]}:{client_address[1]}")

            status = "Client connected"

            # Add socket to Client class instance
            client = Client(client_socket, client_address)

            # Add the client object to the clients list
            clients.append(client)

            # Handle client in a separate task
            asyncio.create_task(handle_client(client))

        except socket.timeout:
            pass
        except Exception as e:
            log_message(f"Error accepting connection: {e}")


async def handle_client(client):
    global status
    this_clientbID = None

    try:
        while True:
            response = None
            request = await \
                asyncio.get_event_loop().run_in_executor(
                    None, client.socket.recv, 1024)

            if not request:
                log_message("Client disconnected")
                break

            request = request.decode("utf-8", errors="replace")
            log_message(f"Received: {request}")

            if is_http_request(request):
                try:
                    client.socket.sendall(build_http_notice_response())
                    log_message("Served HTTP notice page to non-bNET client")
                except Exception as e:
                    log_message(f"Failed to serve HTTP notice page: {e}")
                break

            # >> >> Process requests

            # Check request
            # >> Checks if a bID is registered and if the password matches
            if request.startswith("HELLO"):
                if auth_public_endpoint:
                    response = f"HELLO::OK::bNET2::AUTH_PUBLIC::{auth_public_endpoint['public_ip']}:{auth_public_endpoint['public_port']}"
                else:
                    response = "HELLO::OK::bNET2"

            elif request.startswith("CHECK::"):
                check_request = request.split("::")[1]
                if check_request == "USER":
                    bID = request.split("::")[2]
                    password = request.split("::")[3]
                    log_message(f"Checking bID: {bID}")

                    # check if bID exists in the data
                    try:
                        data = load_user_data()

                        if bID in data["bNETauth_data"]["clients"]:
                            # check if password matches
                            if data["bNETauth_data"]["clients"][bID]["password"] == password:
                                response = "OK"
                            else:
                                response = "INUSE"
                        else:
                            response = "SENDDATA"
                    except Exception as e:
                        log_message(f"Error reading user data: {e}")
                        response = "FAILED"

                    

            # Registration request
            # >> Registers a new client or sets existing client's status to online
            elif request.startswith("REGISTER::"):
                thisbID = request.split("::")[1]
                password = request.split("::")[2]
                c_port = request.split("::")[3]
                log_message(f"Registering bID: {thisbID}")

                # check if bID already exists
                data = load_user_data()

                # register the existing client as online
                if thisbID in data["bNETauth_data"]["clients"]:
                    # if bID exists check if password matches
                    if data["bNETauth_data"]["clients"][thisbID]["password"] == password:
                        # set client status to online
                        data["bNETauth_data"]["clients"][thisbID]["data"]["status"] = "online"
                        save_user_data(data)
                        response = "OK"

                        client.conn_port = c_port
                        client.bID = thisbID
                        this_clientbID = thisbID

                else:
                    # register the new client
                    data["bNETauth_data"]["clients"][thisbID] = ensure_client_record({
                        "password": password,
                        "data": {"status": "online"}
                    }, thisbID, password=password)
                    save_user_data(data)
                    log_message(f"Registered new bID: {thisbID}")
                    response = "OK"
                    client.conn_port = c_port
                    client.bID = thisbID
                    this_clientbID = thisbID

                    observed_ip, observed_port = client.socket.getpeername()
                    active_sessions[thisbID] = {
                        "bID": thisbID,
                        "private_ip": observed_ip,
                        "private_port": _parse_int(c_port, 0),
                        "public_ip": observed_ip,
                        "public_port": _parse_int(c_port, 0),
                        "observed_port": observed_port,
                        "last_seen_ts": time.time(),
                        "last_seen_iso": now_utc_iso(),
                        "is_online": True,
                    }

                    observed_ip, observed_port = client.socket.getpeername()
                    active_sessions[thisbID] = {
                        "bID": thisbID,
                        "private_ip": observed_ip,
                        "private_port": _parse_int(c_port, 0),
                        "public_ip": observed_ip,
                        "public_port": _parse_int(c_port, 0),
                        "observed_port": observed_port,
                        "last_seen_ts": time.time(),
                        "last_seen_iso": now_utc_iso(),
                        "is_online": True,
                    }

            elif request.startswith("REGISTER_ENDPOINT::"):
                # v2: REGISTER_ENDPOINT::bID::password::listen_port::public_ip|AUTO::public_port|AUTO[::private_ip]
                parts = request.split("::")
                if len(parts) < 6:
                    response = "REGISTER::FAILED::INVALID_FORMAT"
                else:
                    thisbID = parts[1]
                    password = parts[2]
                    listen_port = _parse_int(parts[3], 0)
                    requested_public_ip = parts[4]
                    requested_public_port = parts[5]
                    # Optional field: client-reported LAN IP (avoids storing loopback as private IP)
                    client_reported_private_ip = parts[6].strip() if len(parts) > 6 else ""

                    data = load_user_data()

                    user_entry = data.get("bNETauth_data", {}).get("clients", {}).get(thisbID)
                    if user_entry and user_entry.get("password") != password:
                        response = "REGISTER::FAILED::BAD_PASSWORD"
                    else:
                        if not user_entry:
                            data["bNETauth_data"]["clients"][thisbID] = ensure_client_record({
                                "password": password,
                                "data": {"status": "online"}
                            }, thisbID, password=password)
                        else:
                            ensure_client_record(data["bNETauth_data"]["clients"][thisbID], thisbID, password=password)
                            data["bNETauth_data"]["clients"][thisbID]["data"]["status"] = "online"

                        save_user_data(data)

                        observed_ip, observed_port = client.socket.getpeername()
                        public_ip = observed_ip if requested_public_ip == "AUTO" else requested_public_ip
                        if requested_public_port == "AUTO":
                            public_port = listen_port
                        else:
                            public_port = _parse_int(requested_public_port, listen_port)

                        # Determine the private (LAN) IP: prefer client-reported value, but
                        # fall back to observed_ip.  If both are loopback, use public_ip so
                        # the private route is at least reachable within the same network.
                        def _is_loopback_ip(ip):
                            return str(ip or "").startswith("127.") or ip in ("::1", "localhost")

                        if client_reported_private_ip and not _is_loopback_ip(client_reported_private_ip):
                            private_ip = client_reported_private_ip
                        elif not _is_loopback_ip(observed_ip):
                            private_ip = observed_ip
                        else:
                            private_ip = public_ip

                        active_sessions[thisbID] = {
                            "bID": thisbID,
                            "private_ip": private_ip,
                            "private_port": listen_port,
                            "public_ip": public_ip,
                            "public_port": public_port,
                            "observed_port": observed_port,
                            "last_seen_ts": time.time(),
                            "last_seen_iso": now_utc_iso(),
                            "is_online": True,
                            # Tracks what peers we've already told this client about
                            # via HEARTBEAT hints.  0 = never notified (send all on first HB).
                            "last_peer_notify_ts": 0,
                        }

                        client.conn_port = listen_port
                        client.bID = thisbID
                        this_clientbID = thisbID
                        response = f"REGISTER::OK::{public_ip}:{public_port}"


            # List peers request
            # >> Lists online clients to the requester & their connection info for p2p initiation
            elif request.startswith("LISTPEERS"):
                log_message(f"Listing peers to {client.socket.getpeername()}")
                response = build_peer_response(this_clientbID)

                log_message(f"Compiled peer list: {response}")

            elif request.startswith("GET_PEERS::"):
                parts = request.split("::")
                requester_bID = parts[1] if len(parts) > 1 else this_clientbID
                response = build_peer_response(requester_bID)

            elif request.startswith("GET_FRIEND_PEERS::"):
                parts = request.split("::")
                if len(parts) < 3:
                    response = "PEERS::NONE"
                else:
                    requester_bID = parts[1]
                    password = parts[2]
                    data = load_user_data()
                    _, auth_error = authenticate_request(data, requester_bID, password)
                    if auth_error:
                        response = "PEERS::NONE"
                    else:
                        response = build_friend_peer_response(requester_bID, data)

            elif request.startswith("GET_USER_DIRECTORY::"):
                parts = request.split("::", 3)
                if len(parts) < 4:
                    response = "USER_DIRECTORY::[]"
                else:
                    thisbID = parts[1]
                    password = parts[2]
                    query = parts[3]
                    data = load_user_data()
                    _, auth_error = authenticate_request(data, thisbID, password)
                    if auth_error:
                        response = "USER_DIRECTORY::[]"
                    else:
                        response = "USER_DIRECTORY::" + json.dumps(build_user_directory(data, thisbID, query))

            elif request.startswith("SET_PROFILE::"):
                parts = request.split("::", 3)
                if len(parts) < 4:
                    response = "PROFILE::FAILED::INVALID_FORMAT"
                else:
                    thisbID = parts[1]
                    password = parts[2]
                    data = load_user_data()
                    _, auth_error = authenticate_request(data, thisbID, password)
                    if auth_error:
                        response = auth_error
                    else:
                        response = "PROFILE::OK"

            elif request.startswith("GET_SOCIAL_STATE::"):
                parts = request.split("::")
                if len(parts) < 3:
                    response = "SOCIAL_STATE::{}"
                else:
                    thisbID = parts[1]
                    password = parts[2]
                    data = load_user_data()
                    _, auth_error = authenticate_request(data, thisbID, password)
                    if auth_error:
                        response = "SOCIAL_STATE::{}"
                    else:
                        response = "SOCIAL_STATE::" + json.dumps(build_social_state(data, thisbID))

            elif request.startswith("SEARCH_USERS::"):
                parts = request.split("::", 3)
                if len(parts) < 4:
                    response = "USER_SEARCH::[]"
                else:
                    thisbID = parts[1]
                    password = parts[2]
                    query = parts[3]
                    data = load_user_data()
                    _, auth_error = authenticate_request(data, thisbID, password)
                    if auth_error:
                        response = "USER_SEARCH::[]"
                    else:
                        response = "USER_SEARCH::" + json.dumps(build_user_search(data, thisbID, query))

            elif request.startswith("SEND_FRIEND_REQUEST::"):
                parts = request.split("::")
                if len(parts) < 4:
                    response = "FRIEND_REQUEST::FAILED::INVALID_FORMAT"
                else:
                    from_bid = parts[1]
                    password = parts[2]
                    target_bid = parts[3]
                    data = load_user_data()
                    requester_entry, auth_error = authenticate_request(data, from_bid, password)
                    target_entry = data.get("bNETauth_data", {}).get("clients", {}).get(target_bid)
                    if auth_error:
                        response = auth_error
                    elif not target_entry:
                        response = "FRIEND_REQUEST::FAILED::UNKNOWN_TARGET"
                    elif target_bid == from_bid:
                        response = "FRIEND_REQUEST::FAILED::SELF"
                    else:
                        ensure_client_record(target_entry, target_bid)
                        response = "FRIEND_REQUEST::OK"

            elif request.startswith("RESPOND_FRIEND_REQUEST::"):
                parts = request.split("::")
                if len(parts) < 5:
                    response = "FRIEND_RESPONSE::FAILED::INVALID_FORMAT"
                else:
                    thisbID = parts[1]
                    password = parts[2]
                    from_bid = parts[3]
                    action = str(parts[4]).strip().lower()
                    data = load_user_data()
                    requester_entry, auth_error = authenticate_request(data, thisbID, password)
                    from_entry = data.get("bNETauth_data", {}).get("clients", {}).get(from_bid)
                    if auth_error:
                        response = auth_error
                    elif not from_entry:
                        response = "FRIEND_RESPONSE::FAILED::UNKNOWN_SOURCE"
                    else:
                        if action == "accept":
                            response = "FRIEND_RESPONSE::OK::ACCEPTED"
                        else:
                            response = "FRIEND_RESPONSE::OK::DECLINED"

            elif request.startswith("REMOVE_FRIEND::"):
                parts = request.split("::")
                if len(parts) < 4:
                    response = "FRIEND_REMOVE::FAILED::INVALID_FORMAT"
                else:
                    thisbID = parts[1]
                    password = parts[2]
                    target_bid = parts[3]
                    data = load_user_data()
                    requester_entry, auth_error = authenticate_request(data, thisbID, password)
                    target_entry = data.get("bNETauth_data", {}).get("clients", {}).get(target_bid)
                    if auth_error:
                        response = auth_error
                    elif not target_entry:
                        response = "FRIEND_REMOVE::FAILED::UNKNOWN_TARGET"
                    else:
                        response = "FRIEND_REMOVE::OK"

            elif request.startswith("HEARTBEAT::"):
                parts = request.split("::")
                if len(parts) < 2:
                    response = "HEARTBEAT::FAILED::MISSING_BID"
                else:
                    hb_bid = parts[1]
                    if hb_bid in active_sessions:
                        now_ts = time.time()
                        active_sessions[hb_bid]["last_seen_ts"] = now_ts
                        active_sessions[hb_bid]["last_seen_iso"] = now_utc_iso()
                        active_sessions[hb_bid]["is_online"] = True

                        # Piggyback any peers that became active since the last
                        # time we told this client about them (0 = send everyone).
                        last_notify = active_sessions[hb_bid].get("last_peer_notify_ts", 0)
                        new_peer_entries = []
                        for bid, session in active_sessions.items():
                            if bid == hb_bid:
                                continue
                            if not session.get("is_online"):
                                continue
                            if session.get("last_seen_ts", 0) <= last_notify:
                                continue
                            pub_ip = session.get("public_ip")
                            pub_port = session.get("public_port")
                            priv_ip = session.get("private_ip")
                            priv_port = session.get("private_port")
                            if pub_ip and pub_port and priv_ip and priv_port:
                                new_peer_entries.append(
                                    f"{bid};{pub_ip}:{pub_port};{priv_ip}:{priv_port}"
                                )
                        active_sessions[hb_bid]["last_peer_notify_ts"] = now_ts

                        if new_peer_entries:
                            response = "HEARTBEAT::OK::PEERS::" + "::".join(new_peer_entries)
                        else:
                            response = "HEARTBEAT::OK"

                        # Piggyback any pending relay invites for this peer.
                        pending_invites = active_sessions[hb_bid].pop("pending_relay_invites", [])
                        if pending_invites:
                            invite_parts = [
                                f"{inv['from_bid']}:{inv['token']}"
                                for inv in pending_invites
                                if inv.get("from_bid") and inv.get("token")
                            ]
                            if invite_parts:
                                response += "::RELAY_INVITES::" + "::".join(invite_parts)
                    else:
                        response = "HEARTBEAT::FAILED::UNKNOWN_BID"

            elif request.startswith("GET_AUTH_ENDPOINT"):
                if auth_public_endpoint:
                    response = f"AUTH_ENDPOINT::{auth_public_endpoint['public_ip']}:{auth_public_endpoint['public_port']}"
                else:
                    response = "AUTH_ENDPOINT::UNKNOWN"


            # ---
            # GET_NETWORK_STATUS: Returns the current network exposure state.
            #   - BOUND: Local port the server is bound to
            #   - PUBLIC: Public IP:port as detected by UPnP or STUN, or UNKNOWN
            #   - UPNP: ON if UPnP mapping is active, OFF otherwise
            # Example: NETWORK_STATUS::BOUND::30301::PUBLIC::203.0.113.42:30301::UPNP::ON
            # ---
            elif request.startswith("GET_NETWORK_STATUS"):
                public = "UNKNOWN"
                if auth_public_endpoint:
                    public = f"{auth_public_endpoint['public_ip']}:{auth_public_endpoint['public_port']}"
                upnp = "ON" if network_state.get("upnp_active") else "OFF"
                bound = str(network_state.get("bound_port", "UNKNOWN"))
                mode = get_network_mode_label()
                response = f"NETWORK_STATUS::MODE::{mode}::BOUND::{bound}::PUBLIC::{public}::UPNP::{upnp}"

            # Ping request
            #
            elif request.startswith("PING"):
                response = "PONG"

            # ---
            # REQUEST_RELAY::myBID::password::targetBID
            #   Creates a relay session and returns a one-time token.
            #   The requesting peer should immediately open a new TCP connection
            #   to auth and send JOIN_RELAY::token::myBID::password to claim the
            #   "from" slot.  The target peer's next heartbeat will carry a
            #   RELAY_INVITE hint so it can JOIN_RELAY to claim the "to" slot.
            #   Once both slots are filled auth pipes the two sockets together.
            # ---
            elif request.startswith("REQUEST_RELAY::"):
                parts = request.split("::")
                if len(parts) < 4:
                    response = "RELAY::FAILED::INVALID_FORMAT"
                else:
                    relay_req_bid = parts[1]
                    relay_req_pass = parts[2]
                    relay_target_bid = parts[3]
                    data = load_user_data()
                    _, auth_error = authenticate_request(data, relay_req_bid, relay_req_pass)
                    if auth_error:
                        response = auth_error
                    elif relay_target_bid not in active_sessions or not active_sessions[relay_target_bid].get("is_online"):
                        response = "RELAY::FAILED::TARGET_OFFLINE"
                    else:
                        _cleanup_stale_relay_sessions()
                        # Deduplicate: if a pending relay session already exists
                        # between the same two peers (in either direction) and
                        # still has an open slot, reuse that token so both peers
                        # end up joining the same session rather than each
                        # creating their own and waiting forever.
                        pair = {relay_req_bid, relay_target_bid}
                        relay_token = None
                        with relay_sessions_lock:
                            for tok, rs in relay_sessions.items():
                                if {rs["from_bid"], rs["to_bid"]} == pair:
                                    relay_token = tok
                                    log_message(
                                        f"[relay] Reusing existing session {tok[:8]}... "
                                        f"for {relay_req_bid} \u2194 {relay_target_bid}"
                                    )
                                    break
                            if relay_token is None:
                                relay_token = secrets.token_hex(16)
                                relay_sessions[relay_token] = {
                                    "from_bid": relay_req_bid,
                                    "to_bid": relay_target_bid,
                                    "from_sock": None,
                                    "to_sock": None,
                                    "created_ts": time.time(),
                                }
                                log_message(
                                    f"[relay] Session {relay_token[:8]}... created: "
                                    f"{relay_req_bid} \u2192 {relay_target_bid}"
                                )
                                # Register in UDP relay index so clients can
                                # register UDP endpoints for this session.
                                _relay_id = int(relay_token[:8], 16)
                                with _udp_relay_lock:
                                    _udp_relay_sessions[_relay_id] = {
                                        "token": relay_token,
                                        "udp_slots": {},
                                    }
                        # Queue a relay invite on the target's session so their
                        # next heartbeat response carries it.
                        if relay_target_bid in active_sessions:
                            active_sessions[relay_target_bid].setdefault(
                                "pending_relay_invites", []
                            ).append({"from_bid": relay_req_bid, "token": relay_token})
                        response = f"RELAY::PENDING::{relay_token}"

            # ---
            # JOIN_RELAY::token::myBID::password
            #   Claims one slot in an existing relay session.  When both slots
            #   are filled auth starts two pipe threads and exits handle_client
            #   without closing the socket (relay_mode=True).
            # ---
            elif request.startswith("JOIN_RELAY::"):
                parts = request.split("::")
                if len(parts) < 4:
                    response = "RELAY::FAILED::INVALID_FORMAT"
                else:
                    join_token = parts[1]
                    join_bid = parts[2]
                    join_pass = parts[3]
                    data = load_user_data()
                    _, auth_error = authenticate_request(data, join_bid, join_pass)
                    if auth_error:
                        response = auth_error
                    else:
                        with relay_sessions_lock:
                            rs = relay_sessions.get(join_token)
                            if not rs:
                                response = "RELAY::FAILED::UNKNOWN_TOKEN"
                            elif join_bid not in (rs["from_bid"], rs["to_bid"]):
                                response = "RELAY::FAILED::NOT_INVITED"
                            elif rs["from_sock"] is not None and rs["to_sock"] is not None:
                                response = "RELAY::FAILED::ALREADY_FULL"
                            else:
                                # Assign socket to the correct slot.
                                if join_bid == rs["from_bid"] and rs["from_sock"] is None:
                                    rs["from_sock"] = client.socket
                                elif rs["to_sock"] is None:
                                    rs["to_sock"] = client.socket

                                both_ready = (
                                    rs["from_sock"] is not None
                                    and rs["to_sock"] is not None
                                )
                                if both_ready:
                                    # Both peers are present — start the relay pipe.
                                    from_sock = rs["from_sock"]
                                    to_sock = rs["to_sock"]
                                    relay_sessions.pop(join_token, None)
                                    log_message(
                                        f"[relay] {join_token[:8]}... both peers joined "
                                        f"({rs['from_bid']} \u2194 {rs['to_bid']}) — piping"
                                    )
                                    _pipe_relay_id = int(join_token[:8], 16)
                                    _udp_rport = server_config.get("udp_relay_port", 30302)
                                    # Notify both peers — include UDP relay port so clients
                                    # can register audio frames without hole-punching.
                                    try:
                                        from_sock.sendall(
                                            f"RELAY::OK::{_udp_rport}".encode()
                                        )
                                    except Exception:
                                        pass
                                    try:
                                        to_sock.sendall(
                                            f"RELAY::OK::{_udp_rport}".encode()
                                        )
                                    except Exception:
                                        pass
                                    # Pipe threads own both sockets from here.
                                    # Pass relay_id so they can clean up UDP state on exit.
                                    threading.Thread(
                                        target=_relay_pipe,
                                        args=(from_sock, to_sock, f"{join_token[:8]} fwd", _pipe_relay_id),
                                        daemon=True,
                                    ).start()
                                    threading.Thread(
                                        target=_relay_pipe,
                                        args=(to_sock, from_sock, f"{join_token[:8]} rev", _pipe_relay_id),
                                        daemon=True,
                                    ).start()
                                    client.relay_mode = True
                                    response = None
                                    break  # Exit handle_client recv loop
                                else:
                                    # First joiner — wait for the other peer.
                                    # Mark relay_mode so the socket stays open when
                                    # handle_client exits after this break.
                                    client.relay_mode = True
                                    log_message(
                                        f"[relay] {join_token[:8]}... first peer joined "
                                        f"({join_bid}), waiting for partner"
                                    )
                                    # Send RELAY::WAITING so the client knows to block.
                                    try:
                                        client.socket.sendall("RELAY::WAITING".encode())
                                    except Exception:
                                        pass
                                    response = None
                                    break  # Exit handle_client recv loop

            else:
                log_message("Unknown request")
                client.socket.send("UNKNOWN".encode('utf-8'))

            if response:
                log_message(f"Sending response: {response}")
                client.socket.send(response.encode('utf-8'))

    except socket.timeout:
        log_message("Client timeout, closing connection")
    except Exception as e:
        log_message(f"Error handling client: {e}")
        try:
            clients.remove(client)
        except ValueError:
            pass
    finally:
        # set the client status to offline
        # Skip for relay-mode sockets: this connection is a temporary pipe for
        # a relay session, not the client's main auth connection. Marking the
        # account offline here would incorrectly evict a still-active user.
        if getattr(client, 'relay_mode', False):
            log_message(f"[relay] Skipping offline marking for relay socket ({this_clientbID})")
        else:
            try:
                data = load_user_data()

                # Mark this client offline only if we know its bID and it exists in the data
                if this_clientbID and this_clientbID in data.get("bNETauth_data", {}).get("clients", {}):
                    try:
                        if data["bNETauth_data"]["clients"][this_clientbID]["data"].get("status") == "online":
                            data["bNETauth_data"]["clients"][this_clientbID]["data"]["status"] = "offline"
                    except Exception:
                        # Defensive: if structure is unexpected, don't crash finalizer
                        pass

                    if this_clientbID in active_sessions:
                        active_sessions[this_clientbID]["is_online"] = False
                        active_sessions[this_clientbID]["last_seen_ts"] = time.time()
                        active_sessions[this_clientbID]["last_seen_iso"] = now_utc_iso()

                save_user_data(data)
            except Exception as e:
                log_message(f"Error updating client status: {e}")

        # Close the client socket
        if not getattr(client, 'relay_mode', False):
            try:
                client.socket.send("CLOSED".encode('utf-8'))
            except Exception:
                pass
            try:
                client.socket.close()
            except Exception:
                pass
        try:
            clients.remove(client)
        except ValueError:
            pass
        log_message("Connection socket closed")
        status = "Listening..."


def init():
    global status
    status = 'Initializing Console...'

    try:
        # Show splash screen first (runs briefly on main thread)
        status = 'Showing splash screen...'
        curses.wrapper(splash)
    except Exception as e:
        prelog(f"CRITICAL ERROR!; {e} failed at status: {status}")
        show_prelog_and_exit()

    status = 'Initializing...'

    try:
        if not os.path.exists(default_storage_path):
            log_message('Data folder not found')
            try:
                log_message('Creating Data folder...')
                os.makedirs(default_storage_path)
            except Exception as e:
                log_message(f'Unable to make Data folder; {e}')
            finally:
                log_message(f'Data folder created at {os.path.abspath(default_storage_path)}')
        else:
            log_message('Data folder found')
    except Exception as e:
        log_message(f'Error while searching for Data folder; {e}')

    status = 'Searching for data json...'

    try:
        if not os.path.exists(default_userdata_path):
            log_message("Data json not found")

            default_initdata = {
                "bNETauth_data": {
                    "clients": {

                    }
                }
            }

            try:
                with open(default_userdata_path, 'w') as json_file:
                    json.dump(default_initdata, json_file, indent=4)
            except Exception as e:
                log_message(f'Unable to create Data json; {e}')
            finally:
                log_message('Data json created')
        else:
            log_message('Data json found')
    except Exception as e:
        log_message(f'Error while searching for Data json; {e}')

    status = "Searching for settings json..."

    try:
        if not os.path.exists(default_settings_path):
            log_message("Settings json not found")

            default_settings = {
                "server": {
                    "default_port": 30301,
                    "local_mode": False,
                    "bind_host": "0.0.0.0",
                    "listen_backlog": 128,
                    "accept_timeout_sec": 1.0,
                    "heartbeat_timeout_sec": 90,
                    "auto_network_bootstrap": True,
                    "enable_upnp": True,
                    "enable_stun": True,
                    "stun_servers": [
                        "stun.l.google.com:19302",
                        "stun1.l.google.com:19302",
                        "stun.cloudflare.com:3478"
                    ],
                    "stun_timeout_sec": 2.0,
                    "network_refresh_sec": 300,
                    "socket_keepalive": True,
                }
            }

            try:
                with open(default_settings_path, 'w') as json_file:
                    json.dump(default_settings, json_file, indent=4)
            except Exception as e:
                log_message(f'Unable to create Settings json; {e}')
            finally:
                log_message('Settings json created')
        else:
            log_message('Settings json found')
            # Load settings
        
        if os.path.exists(default_settings_path):
            try:
                with open(default_settings_path, 'r') as json_file:
                    settings_data = json.load(json_file)
                    global default_port
                    default_port = settings_data["server"].get("default_port")

                    srv_cfg = settings_data.get("server", {})
                    server_config["default_port"] = _parse_int(srv_cfg.get("default_port"), server_config["default_port"])
                    server_config["local_mode"] = _parse_bool(srv_cfg.get("local_mode"), server_config["local_mode"])
                    server_config["bind_host"] = str(srv_cfg.get("bind_host", server_config["bind_host"]))
                    server_config["listen_backlog"] = _parse_int(srv_cfg.get("listen_backlog"), server_config["listen_backlog"])
                    server_config["accept_timeout_sec"] = float(srv_cfg.get("accept_timeout_sec", server_config["accept_timeout_sec"]))
                    server_config["heartbeat_timeout_sec"] = _parse_int(srv_cfg.get("heartbeat_timeout_sec"), server_config["heartbeat_timeout_sec"])
                    server_config["auto_network_bootstrap"] = _parse_bool(srv_cfg.get("auto_network_bootstrap"), server_config["auto_network_bootstrap"])
                    server_config["enable_upnp"] = _parse_bool(srv_cfg.get("enable_upnp"), server_config["enable_upnp"])
                    server_config["enable_stun"] = _parse_bool(srv_cfg.get("enable_stun"), server_config["enable_stun"])
                    parsed_stun = _parse_csv(srv_cfg.get("stun_servers", server_config["stun_servers"]))
                    if parsed_stun:
                        server_config["stun_servers"] = parsed_stun
                    server_config["stun_timeout_sec"] = float(srv_cfg.get("stun_timeout_sec", server_config["stun_timeout_sec"]))
                    server_config["network_refresh_sec"] = _parse_int(srv_cfg.get("network_refresh_sec"), server_config["network_refresh_sec"])
                    server_config["socket_keepalive"] = _parse_bool(srv_cfg.get("socket_keepalive"), server_config["socket_keepalive"])
                    env_override_config()
                    apply_local_mode_overrides()
            except Exception as e:
                log_message(f'Unable to load Settings json; {e}')

    except Exception as e:
        log_message(f'Error while searching for Settings json; {e}')

    status = 'Starting server session...'

    # Run the asyncio server in a separate daemon thread so the main thread
    # can safely run the curses UI. Running curses from a non-main thread
    # on many platforms (and especially remote terminals) causes crashes.
    def _server_runner():
        # Use new_event_loop + run_until_complete for compatibility with
        # Python versions that don't provide asyncio.run (pre-3.7).
        loop = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(run_server())
        except Exception as e:
            log_message(f'Failed to start server session; {e}')
        finally:
            if loop is not None:
                try:
                    loop.close()
                except Exception:
                    pass

    server_thread = threading.Thread(target=_server_runner, daemon=True)
    server_thread.start()

    log_message('Started server session')

    status = 'Initialization finished'

    # Start the curses console on the main thread (blocking). This keeps
    # curses in the main thread where it is supported by most terminals.
    try:
        status = 'Starting console thread...'
        curses.wrapper(console)
    except KeyboardInterrupt:
        status = 'Exiting...'
        log_message('Console interrupted by operator')
    except Exception as e:
        log_message(f'Console failed: {e}')


if __name__ == "__main__":
    init()
