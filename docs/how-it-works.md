# How it works

The container runs two programs: **nginx**, which serves the pages and
forwards traffic, and a small Python supervisor (`gateway/gateway.py`) that
keeps nginx's configuration current.

```text
phone ──https──▶ gateway (nginx) ──http──▶ controller
  │                    ▲
  └──http (setup)──────┘    supervisor: mDNS, certificates, nginx config
```

## Finding the controller

The controller announces an `_http._tcp` service with a TXT entry `obbw=1`.
The supervisor browses that service type with
[python-zeroconf](https://github.com/python-zeroconf/python-zeroconf) and
picks the controller by that entry, so a renamed controller, or one renamed
`-2` after a name clash, is still found. With `OBBW_CONTROLLER_NAME` it picks
the controller whose device name matches; with a `.local` name in
`OBBW_CONTROLLER_URL`, the one whose host name matches. An IP address in
`OBBW_CONTROLLER_URL` turns discovery off completely.

When the controller announces a new address, the supervisor rewrites nginx's
configuration and reloads it without dropping connections. When the
controller goes away, the last known address is kept, because a restarting
controller announces itself again.

### Network traffic

The controller shares one 2.4 GHz radio between Wi-Fi and the Bluetooth
scale, so the gateway avoids generating traffic toward it:

- No health checks or polling. Discovery relies on the controller's own
  announcements and on the standard mDNS query schedule, which backs off to
  roughly one query per hour.
- Each forwarded request closes its connection to the controller when done,
  which frees the controller's few sockets right away. Live updates use one
  WebSocket, as without the gateway.

## Publishing the name

The supervisor registers an `_https._tcp` service whose host is the gateway's
name (`openbrewbyweight-secure.local` by default) at `GATEWAY_IP`. That also
publishes the name's address record, so any device that understands mDNS can
open it. python-zeroconf shares the mDNS port with other responders on the
same host, such as Avahi or Home Assistant. On shutdown, the gateway sends
mDNS goodbye packets so devices forget the name at once.

## Certificates

On first start, the supervisor creates a private certificate authority (CA)
in the `data` folder:

- ECDSA P-256, valid for ten years.
- **Name-constrained** to the gateway's name only (`permitted;DNS:<name>`),
  so even a stolen CA key cannot produce a trusted certificate for any other
  site.

It then issues the server certificate for the gateway's name. That
certificate is valid for 397 days, the maximum Apple accepts, and is renewed
30 days before it expires. The supervisor checks twice a day and reloads
nginx after a renewal. Devices trust the CA, not the server certificate, so
renewals need nothing from them. If the gateway's name changes, the existing
CA cannot cover it and a new one is created.

The setup page offers the CA as a `.crt` file (Mac, Windows, Android) and as
an Apple configuration profile (`.mobileconfig`, iPhone and iPad). The
profile's identifiers come from the CA's fingerprint, so installing it again
replaces the earlier copy.

## Forwarding

nginx terminates HTTPS (TLS 1.2 and 1.3, HTTP/2) and forwards to the
controller over plain HTTP on your network. The controller only answers
requests addressed to itself, so nginx sends `Host` and `Origin` set to the
controller's address. WebSocket upgrades are forwarded and responses are not
buffered, so live readings flow without delay. Firmware updates from the Web
UI work through the gateway as well.

Until the controller is found, the secure address answers `503`. The setup
page stays on plain HTTP, because a device cannot use HTTPS before it trusts
the CA. The page checks whether the device trusts the CA by loading a small
probe from the secure address.

## Files

| Path | Purpose |
| --- | --- |
| `gateway/gateway.py` | Supervisor: configuration, discovery, mDNS, certificates, rendering. |
| `gateway/nginx.conf.in` | nginx configuration template. |
| `gateway/setup.html` | Setup page template. |
| `data/` (volume) | CA and server certificate with their keys. Keys are readable only by root. |
| `/run/gateway/` (container) | Rendered nginx configuration and setup page. |
