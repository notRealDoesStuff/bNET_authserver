# Manual Port-Forward Deployment Mode

This document describes how to deploy the bNET Authentication Server using manual port forwarding, as a fallback when UPnP and STUN are unavailable or disabled.

## When to Use Manual Port Forwarding
- Your router does not support UPnP, or UPnP is disabled.
- STUN discovery fails to detect a public endpoint.
- You want explicit control over which ports are exposed.

## Steps for Manual Deployment

1. **Choose a Port**
   - Default: 30301 (can be changed in `data/settings.json` or via environment variable `BNET_AUTH_PORT`).

2. **Configure the Server**
   - Set `enable_upnp` and `enable_stun` to `false` in `data/settings.json`:
     ```json
     {
       "server": {
         "enable_upnp": false,
         "enable_stun": false,
         "default_port": 30301,
         ...
       }
     }
     ```
   - Or set environment variables:
     - `BNET_AUTH_ENABLE_UPNP=0`
     - `BNET_AUTH_ENABLE_STUN=0`

3. **Set Up Port Forwarding on Your Router**
   - Forward the chosen port (e.g., 30301) from your router's WAN interface to the server's LAN IP and port.
   - Protocol: TCP (and UDP if required by your clients).
   - Example: Forward external port 30301 to 192.168.1.100:30301

4. **Verify Exposure**
   - Use an external tool (e.g., https://canyouseeme.org/) to check if the port is open.
   - The server's `GET_NETWORK_STATUS` will show:
     - `UPNP::OFF`
     - `PUBLIC::UNKNOWN` (unless the public IP is manually set)
     - `BOUND::<your_port>`

5. **Client Connection**
   - Clients must connect to your public IP and the forwarded port.
   - You may need to provide your public IP to clients manually.

## Example settings.json
```json
{
  "server": {
    "default_port": 30301,
    "bind_host": "0.0.0.0",
    "enable_upnp": false,
    "enable_stun": false
  }
}
```

## Notes
- The server will not attempt any automatic NAT traversal in this mode.
- All exposure and reachability depend on correct router configuration.
- This mode is suitable for static or cloud-hosted deployments where the public IP and port are known and fixed.
