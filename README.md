# bNET_auth
 bNET auth gatekeeper server

## Network V2 (In Progress)

The auth server now supports a v2 control flow for internet-aware peer routing.

### New Request Verbs
- HELLO
- REGISTER_ENDPOINT
- HEARTBEAT
- GET_PEERS

### Peer Response Format
`PEERS::bID;public_ip:public_port;private_ip:private_port::...`

### Server Settings
`authserver/data/settings.json` now supports:
- `default_port`
- `local_mode`
- `bind_host`
- `listen_backlog`
- `accept_timeout_sec`
- `heartbeat_timeout_sec`
- `auto_network_bootstrap`
- `enable_upnp`
- `enable_stun`
- `stun_servers`
- `stun_timeout_sec`
- `network_refresh_sec`
- `socket_keepalive`

When STUN is enabled, auth attempts to discover its own public endpoint and includes
it in `HELLO` responses as `AUTH_PUBLIC` metadata. You can also query it via
`GET_AUTH_ENDPOINT`.

When `auto_network_bootstrap` is enabled, the server will automatically:
- bind and listen
- attempt UPnP mapping on the bound port
- discover public endpoint via STUN
- refresh mapping/discovery periodically

When `local_mode` is enabled, the server forces a loopback-only configuration:
- binds to `127.0.0.1`
- disables UPnP
- disables STUN
- disables automatic public bootstrap/refresh

Use local mode for single-machine development or LAN-only testing where the auth server should not expose itself to the public internet.

Use `GET_NETWORK_STATUS` to fetch bound port, current public endpoint, and UPnP state.

## Console Controls

The built-in curses console now keeps a larger in-memory log buffer and exposes a compact operator status panel when the terminal is wide enough.

Tabs:
- `Overview` shows recent logs with the live status summary.
- `Logs` focuses on the log stream and scrollback.
- `Connections` shows connected TCP clients and active auth sessions.

Keyboard controls:
- `Tab` / `Shift+Tab` switch tabs.
- `Left` / `Right` also switch tabs.
- `Up` / `Down` cycle command history.
- `Page Up` / `Page Down` scroll the current tab view.
- `Home` jumps to the oldest retained log entry.
- `End` returns the log tabs to live tail mode.
- `Ctrl+C` exits the console cleanly.

Console commands:
- `help`
- `status`
- `network`
- `sessions`
- `clients`
- `test-listpeers`
- `clear`
- `exit`

Environment variable overrides:
- `BNET_AUTH_PORT`
- `BNET_AUTH_LOCAL_MODE`
- `BNET_AUTH_BIND_HOST`
- `BNET_AUTH_BACKLOG`
- `BNET_AUTH_ACCEPT_TIMEOUT`
- `BNET_AUTH_HEARTBEAT_TIMEOUT`
- `BNET_AUTH_AUTO_BOOTSTRAP`
- `BNET_AUTH_ENABLE_UPNP`
- `BNET_AUTH_ENABLE_STUN`
- `BNET_AUTH_STUN_SERVERS`
- `BNET_AUTH_STUN_TIMEOUT`
- `BNET_AUTH_NETWORK_REFRESH`
- `BNET_AUTH_SOCKET_KEEPALIVE`
