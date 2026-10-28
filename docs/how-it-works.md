# How it works

Open Brew by Weight Companion runs as one container. Its HTTPS gateway is two
programs: **nginx**, which serves the pages and forwards traffic, and a small
Python supervisor (`gateway/gateway.py`) that keeps nginx's configuration
current.

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

A controller in Wi-Fi power save can answer late, so the supervisor waits up
to 10 seconds for its details. Until it finds a controller, it asks the
network again after 30 seconds, then 1, 2, 5 and every 10 minutes; once one
is found, it stops asking. The log names every `_http._tcp` device it sees
and why it skipped it, once per device and reason.

When the controller announces a new address, the supervisor rewrites nginx's
configuration and reloads it without dropping connections. When the
controller goes away, the last known address is kept, because a restarting
controller announces itself again.

### Network traffic

The controller shares one 2.4 GHz radio between Wi-Fi and the Bluetooth
scale, so the gateway avoids generating traffic toward it:

- No health checks or polling. Once the controller is known, discovery
  relies on its own announcements and on the standard mDNS query schedule,
  which backs off to roughly one query per hour. The faster retries above
  only run while no controller has been found.
- Each forwarded request closes its connection to the controller when done,
  which frees the controller's few sockets right away. Live updates use one
  WebSocket, as without the gateway.

## Publishing the name

The supervisor registers an `_https._tcp` service whose host is the gateway's
name (`openbrewbyweight-secure.local` by default) at `COMPANION_IP`. That also
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

### Web UI cache

The gateway keeps a copy of the Web UI's files, so the controller sends them
once instead of once per device. That matters most right after a firmware
update, when every phone loads the new Web UI at the same time.

- **Scripts, styles and icons** are kept for as long as the controller allows:
  a year for the versioned URLs the Web UI uses, never for any other. A
  firmware update changes those URLs, so the new files are fetched at once.
  When several devices ask for a file the gateway does not have yet, only one
  request reaches the controller.
- **Pages and the service worker** are checked with the controller on each
  load, at most once every couple of seconds. An unchanged page costs the
  controller a short "not modified" answer instead of the whole page.
- **While the controller is off**, the gateway serves the last copy of each
  page it loaded, so a new device can still open the Web UI. Everything else
  waits for the controller.

The API, live readings and firmware updates are never cached. Every cached
response carries an `X-Gateway-Cache` header (`HIT`, `MISS`, `REVALIDATED`,
`STALE`…) that shows where it came from. The cache lives in
`/run/gateway/cache` inside the container, holds at most 16 MB, drops files
unused for 30 days, and starts empty when the container is recreated.

When the gateway restarts, it serves the controller it last found over mDNS
right away, from `data/controller.json`, and keeps searching until mDNS
confirms that address or reports a new one. It forgets that controller when
`OBBW_CONTROLLER_URL` or `OBBW_CONTROLLER_NAME` change.

Until a controller is known, the secure address answers `503`. The setup
page stays on plain HTTP, because a device cannot use HTTPS before it trusts
the CA. The page checks whether the device trusts the CA by loading a small
probe from the secure address.

## Status and health checks

`/__companion/gateway`, on both the setup page and the secure address, returns
the gateway's state as JSON (`/__gateway/status`, its earlier address,
redirects there): its name and address, the controller in use and
where it came from (`mdns`, `remembered` or `manual`), every `_http._tcp`
device discovery saw and what it made of it, and when the server certificate
expires. Monitoring tools such as Uptime Kuma or Home Assistant can read it.

`gateway.py check`, run inside the container, probes the setup page, the
secure address and the status. It is the image's Docker health check, so
`docker compose ps` shows `healthy` once a controller is known. The health
check never contacts the controller, to keep Wi-Fi traffic away from it.
`gateway.py check --controller` also loads the Web UI through the gateway;
`./setup` runs it once at the end.

## The setup script

`./setup` runs on the server, outside the container. It reads the default
route to learn the interface, range and router, and picks the network mode:
the server's own address when ports 80 and 443 are free
(`compose.host.yaml`), an existing macvlan or ipvlan network on the same
interface and range (`compose.existing-network.yaml`), or a new one. For a
new address it suggests the first one from `.240` down that answers neither
ping nor ARP and is not taken by a container, and asks you to confirm it is
outside the router's DHCP range. It keeps the name, controller and data
settings of an earlier `.env`, saved as `.env.bak`, so devices stay set up.
It then starts the container and runs `gateway.py check` until a controller
is found, asking for the controller's address or name when discovery
cannot settle it.

## Files

| Path | Purpose |
| --- | --- |
| `gateway/gateway.py` | Supervisor: configuration, discovery, mDNS, certificates, rendering. |
| `gateway/nginx.conf.in` | nginx configuration template. |
| `gateway/setup.html` | Setup page template. |
| `gateway/strings.json` | Setup page texts in English and Spanish. |
| `setup` | Setup and check script, run on the server. |
| `compose.host.yaml`, `compose.existing-network.yaml` | Network modes, chosen with `COMPOSE_FILE`. |
| `data/` (volume) | CA and server certificate with their keys (readable only by root), and the last controller found. |
| `/run/gateway/` (container) | Rendered nginx configuration, setup pages, `status.json` and the Web UI cache. |
