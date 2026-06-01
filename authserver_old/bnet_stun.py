import os
import random
import socket
import struct


_STUN_MAGIC_COOKIE = 0x2112A442
_STUN_BINDING_REQUEST = 0x0001
_STUN_BINDING_SUCCESS = 0x0101

_ATTR_MAPPED_ADDRESS = 0x0001
_ATTR_XOR_MAPPED_ADDRESS = 0x0020


def _build_binding_request(txn_id):
    return struct.pack("!HHI12s", _STUN_BINDING_REQUEST, 0, _STUN_MAGIC_COOKIE, txn_id)


def _parse_server_entry(server_entry):
    entry = str(server_entry).strip()
    if not entry:
        return None

    if ":" not in entry:
        return entry, 3478

    host, port_text = entry.rsplit(":", 1)
    host = host.strip()
    if not host:
        return None

    try:
        port = int(port_text)
    except Exception:
        port = 3478

    return host, port


def _read_attr_value(payload, offset):
    if offset + 4 > len(payload):
        return None, None, None

    attr_type, attr_len = struct.unpack("!HH", payload[offset:offset + 4])
    value_start = offset + 4
    value_end = value_start + attr_len
    if value_end > len(payload):
        return None, None, None

    value = payload[value_start:value_end]
    padded_len = (attr_len + 3) & ~3
    next_offset = value_start + padded_len

    return attr_type, value, next_offset


def _decode_mapped_address(value, xor_mode):
    if len(value) < 8:
        return None

    family = value[1]
    if family != 0x01:
        return None

    raw_port = struct.unpack("!H", value[2:4])[0]
    raw_ip = value[4:8]

    if xor_mode:
        port = raw_port ^ (_STUN_MAGIC_COOKIE >> 16)
        cookie_bytes = struct.pack("!I", _STUN_MAGIC_COOKIE)
        ip_bytes = bytes(raw_ip[i] ^ cookie_bytes[i] for i in range(4))
    else:
        port = raw_port
        ip_bytes = raw_ip

    ip_text = socket.inet_ntoa(ip_bytes)
    return ip_text, int(port)


def _parse_stun_response(packet, expected_txn_id):
    if len(packet) < 20:
        return None

    msg_type, msg_len, cookie, txn_id = struct.unpack("!HHI12s", packet[:20])
    if msg_type != _STUN_BINDING_SUCCESS:
        return None
    if cookie != _STUN_MAGIC_COOKIE:
        return None
    if txn_id != expected_txn_id:
        return None

    body = packet[20:20 + msg_len]
    offset = 0
    mapped = None

    while offset < len(body):
        attr_type, value, next_offset = _read_attr_value(body, offset)
        if attr_type is None:
            break

        if attr_type == _ATTR_XOR_MAPPED_ADDRESS:
            mapped = _decode_mapped_address(value, xor_mode=True)
            if mapped:
                return mapped

        if attr_type == _ATTR_MAPPED_ADDRESS and mapped is None:
            mapped = _decode_mapped_address(value, xor_mode=False)

        offset = next_offset

    return mapped


def _discover_from_server(host, port, timeout, source_port):
    txn_id = os.urandom(12)
    request = _build_binding_request(txn_id)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp.settimeout(timeout)
        bind_port = int(source_port or 0)
        try:
            udp.bind(("0.0.0.0", bind_port))
        except Exception:
            udp.bind(("0.0.0.0", 0))

        udp.sendto(request, (host, port))
        packet, _ = udp.recvfrom(2048)
        return _parse_stun_response(packet, txn_id)
    finally:
        udp.close()


def discover_public_endpoint(stun_servers, timeout=2.0, source_port=0, logger=None):
    if not stun_servers:
        stun_servers = ["stun.l.google.com:19302", "stun1.l.google.com:19302"]

    timeout = max(0.5, float(timeout))

    servers = []
    for entry in stun_servers:
        parsed = _parse_server_entry(entry)
        if parsed:
            servers.append(parsed)

    random.shuffle(servers)

    for host, port in servers:
        try:
            result = _discover_from_server(host, port, timeout=timeout, source_port=source_port)
            if result:
                public_ip, public_port = result
                if logger:
                    logger(f"[STUN] Auth endpoint via {host}:{port} -> {public_ip}:{public_port}")
                return {
                    "public_ip": public_ip,
                    "public_port": int(public_port),
                    "stun_server": f"{host}:{port}",
                }
        except Exception as exc:
            if logger:
                logger(f"[STUN] {host}:{port} failed: {exc}")

    if logger:
        logger("[STUN] Auth endpoint discovery failed on all STUN servers")
    return None
