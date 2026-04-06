import os
import socket
import time
import asyncio
import threading
import curses
import json
import sys
import errno
import upnpy
from datetime import datetime, timezone
import bnet_stun


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
last_logmessages = []

clients = []
active_sessions = {}
auth_public_endpoint = None
network_state = {
    "bound_port": None,
    "upnp_active": False,
    "upnp_external_ip": None,
    "last_stun_refresh_ts": 0.0,
}


server_config = {
    "default_port": 30301,
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

    last_logmessages.append(f'[{total_logged}] {safe_message}')
    total_logged += 1
    if len(last_logmessages) > 10:  # Keep only the last 10 messages
        last_logmessages.pop(0)


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


def draw_console_ui(stdscr, throbber_char, input_buffer):
    if auth_public_endpoint:
        connectable = f"{auth_public_endpoint['public_ip']}:{auth_public_endpoint['public_port']}"
    else:
        bind_host = str(server_config.get("bind_host", "0.0.0.0")).strip() or "0.0.0.0"
        display_host = "127.0.0.1" if bind_host in {"", "0.0.0.0"} else bind_host
        bound_port = network_state.get("bound_port") or server_config.get("default_port") or "?"
        connectable = f"{display_host}:{bound_port} (local/fallback)"

    stdscr.clear()
    stdscr.addstr(0, 0, f'####### bNET auth v{version} ########')
    stdscr.addstr(1, 0, f'##### Protocol: {protocol} v{protocol_ver} #####')
    stdscr.addstr(2, 0, f'#  {len(clients)} Clients connected')
    runmarker = 'Server is running...' if server_running else \
        'Server is not running...'
    stdscr.addstr(3, 0, f'#  {runmarker} {throbber_char}')
    stdscr.addstr(4, 0, f'#  Connectable at: {connectable}')
    stdscr.addstr(5, 0, '')
    stdscr.addstr(6, 0, f'Status: {status}')
    stdscr.addstr(7, 0, '### log ###')
    for idx, message in enumerate(last_logmessages):
        stdscr.addstr(8 + idx, 0, f"# {message}")
    stdscr.addstr(9 + len(last_logmessages), 0, 'Input: ')
    stdscr.addstr(9 + len(last_logmessages), 7, input_buffer)
    stdscr.refresh()


def console(stdscr):
    global status

    curses.curs_set(1)  # Show the cursor
    stdscr.nodelay(1)   # Don't block on input
    stdscr.clear()

    input_buffer = ""  # Buffer to hold user input
    throbber_index = 0
    last_throbber_update = time.time()  # Track the last update time
    last_cursor_flash = time.time()
    throbber_char = None

    while True:
        current_time = time.time()

        # Update throbber every 100 milliseconds
        if current_time - last_throbber_update >= 0.35:
            throbber_char = throbberchars2[throbber_index % len(throbberchars2)]
            last_throbber_update = current_time
            throbber_index += 1

        # Flash the cursor every second
        if current_time - last_cursor_flash >= 1:
            curses.curs_set(1 if curses.curs_set(0) == 0 else 0)
            last_cursor_flash = current_time

        if throbber_char:
            draw_console_ui(stdscr, throbber_char, input_buffer)
        else:
            draw_console_ui(stdscr, "$", input_buffer)


        key = stdscr.getch()  # Get user input
        if key != -1:
            if key in (curses.KEY_BACKSPACE, 127, 8):  # Handle backspace
                input_buffer = input_buffer[:-1]
                curses.curs_set(1)
            elif key == 10:  # Enter key
                # Process the input (e.g., log it, execute a command, etc.)
                handle_command(input_buffer)
                input_buffer = ""  # Clear the input buffer after processing
            elif 32 <= key <= 126:  # Printable characters
                input_buffer += chr(key)  # Add character to input buffer
                curses.curs_set(1)

        # put the cursor at the end of the input line
        stdscr.move(9 + len(last_logmessages), len(input_buffer))

        time.sleep(0.01)  # Throttle the loop to avoid high CPU usage


def handle_command(command):
    global status

    if command.lower() == "help":
        log_message("Available commands: help, status, exit, test-listpeers")
    elif command.lower() == "status":
        log_message(f"Current status: {status}")
    elif command.lower() == "exit":
        log_message("killing server...")
        status = "Exiting..."
        sys.exit(0)
    elif command.lower() == "test-listpeers":

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
    elif command.lower() == "clients":
        log_message(f"Connected clients: {len(clients)}")
        for c in clients:
            try:
                addr = c.socket.getpeername()
                log_message(f" - {addr[0]}:{addr[1]} conn_port: {getattr(c,'conn_port', None)} bID: {getattr(c,'bID', None)}")
            except Exception:
                log_message(f" - <disconnected client> conn_port: {getattr(c,'conn_port', None)} bID: {getattr(c,'bID', None)}")
    else:
        log_message(f"Unknown command: {command}")

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
    network_state["bound_port"] = int(listen_port)
    network_state["upnp_active"] = False
    network_state["upnp_external_ip"] = None

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


use_localhost = False
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

    if use_localhost:
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
        maint = threading.Thread(target=periodic_network_maintenance, args=(port,), daemon=True)
        maint.start()
    else:
        # Explicit fallback path when bootstrap automation is disabled.
        if _parse_bool(server_config.get("enable_upnp"), True):
            apply_upnp_mapping(port)
        discover_auth_public_endpoint(port)

    server_running = True
    log_message(f"Listening on {server.getsockname()}")
    status = "Listening..."

    while True:
        # Only try to set the console title on Windows. Calling external
        # commands while curses controls the terminal can break remote
        # terminals (PuTTY/SSH). Skip on POSIX systems.
        try:
            if os.name == 'nt':
                os.system('title bNET Auth - Status: ' + status)
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
                # v2: REGISTER_ENDPOINT::bID::password::listen_port::public_ip|AUTO::public_port|AUTO
                parts = request.split("::")
                if len(parts) < 6:
                    response = "REGISTER::FAILED::INVALID_FORMAT"
                else:
                    thisbID = parts[1]
                    password = parts[2]
                    listen_port = _parse_int(parts[3], 0)
                    requested_public_ip = parts[4]
                    requested_public_port = parts[5]

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

                        active_sessions[thisbID] = {
                            "bID": thisbID,
                            "private_ip": observed_ip,
                            "private_port": listen_port,
                            "public_ip": public_ip,
                            "public_port": public_port,
                            "observed_port": observed_port,
                            "last_seen_ts": time.time(),
                            "last_seen_iso": now_utc_iso(),
                            "is_online": True,
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
                        active_sessions[hb_bid]["last_seen_ts"] = time.time()
                        active_sessions[hb_bid]["last_seen_iso"] = now_utc_iso()
                        active_sessions[hb_bid]["is_online"] = True
                        response = "HEARTBEAT::OK"
                    else:
                        response = "HEARTBEAT::FAILED::UNKNOWN_BID"

            elif request.startswith("GET_AUTH_ENDPOINT"):
                if auth_public_endpoint:
                    response = f"AUTH_ENDPOINT::{auth_public_endpoint['public_ip']}:{auth_public_endpoint['public_port']}"
                else:
                    response = "AUTH_ENDPOINT::UNKNOWN"

            elif request.startswith("GET_NETWORK_STATUS"):
                public = "UNKNOWN"
                if auth_public_endpoint:
                    public = f"{auth_public_endpoint['public_ip']}:{auth_public_endpoint['public_port']}"
                upnp = "ON" if network_state.get("upnp_active") else "OFF"
                bound = str(network_state.get("bound_port", "UNKNOWN"))
                response = f"NETWORK_STATUS::BOUND::{bound}::PUBLIC::{public}::UPNP::{upnp}"

            # Ping request
            #
            elif request.startswith("PING"):
                response = "PONG"

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
    except Exception as e:
        log_message(f'Console failed: {e}')


if __name__ == "__main__":
    init()
