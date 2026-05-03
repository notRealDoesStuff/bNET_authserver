# UDP Auth Packet Fields (Direct Connection Only)

This document defines the UDP authentication packet structure for direct client↔auth server connections in bNET.

## Design Principles
- No relay, tunnel, or edge intermediaries: all packets are direct between client and server.
- Stateless, challenge-response protocol for authentication.
- All fields are explicit; no legacy or fallback fields for relay/tunnel.

## Packet Types

### 1. HELLO (Client → Server)
| Field         | Type    | Description                       |
|-------------- |-------- |-----------------------------------|
| magic         | string  | "bNET2" (protocol marker)         |
| type          | string  | "HELLO"                           |
| client_id     | string  | 32-char hex bID                   |
| nonce         | bytes   | 16 bytes, client-generated nonce  |
| version       | string  | Client version string              |

### 2. CHALLENGE (Server → Client)
| Field         | Type    | Description                       |
|-------------- |-------- |-----------------------------------|
| magic         | string  | "bNET2"                           |
| type          | string  | "CHALLENGE"                      |
| server_nonce  | bytes   | 16 bytes, server-generated nonce  |
| salt          | bytes   | 16 bytes, per-user salt           |
| kdf           | string  | e.g., "scrypt"                    |
| kdf_params    | dict    | e.g., {N:16384, r:8, p:1}         |

### 3. RESPONSE (Client → Server)
| Field         | Type    | Description                       |
|-------------- |-------- |-----------------------------------|
| magic         | string  | "bNET2"                           |
| type          | string  | "RESPONSE"                       |
| client_id     | string  | 32-char hex bID                   |
| response      | bytes   | HMAC(server_nonce, KDF(password, salt, params)) |

### 4. AUTH_RESULT (Server → Client)
| Field         | Type    | Description                       |
|-------------- |-------- |-----------------------------------|
| magic         | string  | "bNET2"                           |
| type          | string  | "AUTH_RESULT"                    |
| result        | string  | "OK" or error code                |
| public_ip     | string  | Server's public IP                 |
| public_port   | int     | Server's public port               |

## Packet Encoding
- All packets are sent as JSON-encoded UTF-8 over UDP.
- Nonce, salt, and response fields are base64-encoded.

## Example HELLO Packet
```json
{
  "magic": "bNET2",
  "type": "HELLO",
  "client_id": "0123456789abcdef0123456789abcdef",
  "nonce": "base64==",
  "version": "3025b"
}
```

## Security Notes
- No relay/tunnel fallback fields are present.
- All authentication is direct and stateless.
- KDF and HMAC parameters are explicit per session.

## See Also
- server_main.py (for implementation)
- bnet_auth.py, bnet_network.py (client logic)
