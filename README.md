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

Use `GET_NETWORK_STATUS` to fetch bound port, current public endpoint, and UPnP state.

Environment variable overrides:
- `BNET_AUTH_PORT`
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
