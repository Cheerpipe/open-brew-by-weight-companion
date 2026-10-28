# How it works

Open Brew by Weight Companion runs as one container with two programs:
**nginx**, which serves the pages and forwards traffic, and a Python
supervisor (`gateway/gateway.py`) that keeps nginx's configuration current
and runs the companion service (`companion/`) on a thread of its own.

```text
phone ──https──▶ nginx ──http──────────────▶ controller
  │                ▲  └─/__companion/─▶ companion service ──link (ws)──▶ controller
  └──http (setup)──┘                        │
                                            └──https/wss──▶ La Marzocco cloud
supervisor: mDNS, certificates, nginx config; tells the service the controller's address
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
- Once paired, the companion keeps one link open to the controller and
  sends only what the protocol needs: a ping when the link opens, every 2
  minutes (15 seconds while it carries La Marzocco, replacing the
  controller's own La Marzocco WebSocket ping) and when its La Marzocco
  connection comes up or goes down, and machine updates of a few hundred
  bytes as La Marzocco sends them. Pairing requests and polling happen only
  while you pair.

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

## The companion service

The service is written with `aiohttp` and `cryptography` and follows the
link protocol in the firmware's `docs/COMPANION_LINK.md`. nginx serves its
pages under `/__companion/` on both the setup page and the secure address,
through a Unix socket, so the service opens no port of its own (not even in
`compose.host.yaml`'s host network). The supervisor tells it the
controller's address when it starts and on every mDNS announcement.

### Pairing

On first start the service creates its id and a P-256 pairing key in
`data/secrets/`. They are independent of the certificate authority, so a new
`COMPANION_HOSTNAME` keeps the pairing.

1. When it knows a controller it is not paired with, it sends one
   `POST /api/v1/companion/pair` with its id, name, version and a
   commitment to its public key (`SHA-256("obbw-companion-commit-v1" ‖
   key)`), not the key itself. It sends a new request only when you press
   **Pair** on its page, after a restart, or when the controller did not
   answer.
2. While the request is pending, it asks for its state about once a second.
   Once the controller answers with the key it made for this request, the
   service sends the same request again with its public key (the reveal).
   Only when the controller accepts the reveal does it compute the
   six-digit code from the two public keys and show it on the page. Both
   keys are fixed before either side sees the other's, so a device in the
   middle cannot search for keys that would show matching codes.
3. On approval both sides derive the pairing secret with ECDH and HKDF.
   Nothing secret crosses the network. The service keeps it in
   `secrets/pairing.json`.

### The link

The service opens `ws://<controller>/api/v1/companion/link`; the controller
never connects to it. Both sides prove the pairing secret with fresh nonces
and derive a session key; every later frame carries a sequence number and
an HMAC, and a bad MAC or a wrong sequence closes the link. A frame type
this version does not know (from a newer controller) is ignored and
counted, and the page asks you to update the companion.

- **Liveness:** a `ping` as soon as the link opens, then every 2 minutes,
  every 15 seconds while the controller uses the companion for La Marzocco
  (and one right when it starts to), and one at once whenever its La
  Marzocco connection comes up or goes down (`up`), so the controller can
  move the route without waiting for the next interval.
- **Liveness is not symmetric.** The controller sends nothing on its own,
  so it notices a silent companion after two ping intervals, while the
  companion notices a vanished controller through its own pings: the link
  socket closes when the controller has not acknowledged a ping within 30
  seconds (`TCP_USER_TIMEOUT`), that is within 2.5 minutes at most, without
  any extra traffic.
- **Reconnection:** after 5, 15 and 60 seconds, then every 5 minutes, and at
  once when the controller announces itself over mDNS. `RETRY_LATER` (a shot
  with a scale or a scale connection in progress) retries every 15 seconds,
  however often it comes. An unexpected error in one session is logged with
  its traceback and counts as a failed attempt; the gateway keeps serving.
- **Forgotten:** when **Forget** was chosen in Admin, the controller answers
  the next link with `erase`, signed with the pairing secret. Only then does
  the service delete its pairing, the La Marzocco account and the
  installation key on its own.
- **Not recognized:** a controller that simply does not know the companion
  (after a factory reset) answers unsigned, so the service cannot trust it
  to delete anything. It stops its La Marzocco client at once and keeps
  every secret, and the page offers **Pair again** or **Erase this
  pairing**, which deletes the pairing, the La Marzocco account and the
  installation key. The account stays on the companion until one of them is
  chosen.

### La Marzocco

The service has its own La Marzocco client, the same minimal client the
controller has: it registers its own installation key (`/auth/init`), signs
in, signs every request with the installation key, renews the token after
50 minutes, reads the dashboard and sends the two commands the controller
uses (boiler temperature and mode). With the WebSocket connection type it
subscribes over STOMP to the machine's dashboard and pings every 15 seconds,
reconnecting after 30 seconds without an answer; with the API type it reads
the dashboard every 30 seconds. Only its renewal loop refreshes a valid
token; a token it needs at start or after a `401` is reported to the
controller at once with its new life.

It runs while it holds the account, the controller's La Marzocco switch is
on and **Show power state** is on, whether the controller uses it or not.
With **Show power state** off the controller keeps La Marzocco on its own
connection, commands included, so the companion does not even sign in. It sends machine state only
while the controller has set the route to the companion:

- **Only what the controller reads.** Each La Marzocco event is reduced to
  La Marzocco's own dashboard shape with only `connected`, the machine mode,
  the coffee and steam boiler status, target and ready time, and, in pushes
  only, the backflush status. An event that carries none of them is
  dropped; one that does is sent even when nothing changed.
- **`full`** when the route starts and after every new La Marzocco
  subscription; **`push`** for each WebSocket push, at once, also during a
  shot; **`read`** for its own reads (after a token renewal, a `refresh`
  command, API polling, or to check a command no push confirmed within 5
  seconds). While the controller reports a shot with a scale, reads wait and
  the last one is sent when the shot ends.
- `full` and `read` frames carry the id of the last command sent to La
  Marzocco before the observation was taken, so an older observation never
  undoes a newer power command. Pushes do not need it: the controller
  orders them by when it receives them.
- Commands answer `accepted` or `failed` with La Marzocco's HTTP status (0
  when it could not be reached).
- When the controller erases the account (switch off, or the account
  disconnected), the service deletes the account but keeps its
  installation key, so turning La Marzocco on again adds no installation to
  your account. The installation key goes only with the pairing.

The service never logs passwords, tokens, keys or pairing codes.

### Status page and JSON

`/__companion/` (and `/__companion/pair`) is the status and pairing page.
`/__companion/status` returns the same state as JSON for the Web UI's
Diagnostic page: `name`, `version`, `id`, `paired`, `pairedWith`, the
`controller`, `pairing` (`state`, and the `code` while pending), `link`
(`down`, `connecting`, `open` or `retry` with `linkReason`, for example
`VERSION` when the controller speaks another link version or `ERROR` after
an unexpected error), the La Marzocco `route`, `unknownFrames` (frames of
an unknown type in this session) and `laMarzocco` (`enabled`, `account`,
`connection`, `subscribed`, `up`). `POST /__companion/pair` with a JSON
body sends a new pairing request, and `POST /__companion/erase` erases a
pairing the controller no longer recognizes (`409` while it works); a page
on another site cannot send either without asking.

## Status and health checks

`/__companion/gateway`, on both the setup page and the secure address, returns
the gateway's state as JSON (`/__gateway/status`, its earlier address,
redirects there): its name and address, the controller in use and
where it came from (`mdns`, `remembered` or `manual`), every `_http._tcp`
device discovery saw and what it made of it, and when the server certificate
expires. Monitoring tools such as Uptime Kuma or Home Assistant can read it.

`gateway.py check`, run inside the container, probes the setup page, the
secure address, the gateway status and the companion service. It is the image's Docker health check, so
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
| `companion/service.py` | Companion service: the link, the La Marzocco route, the status page and JSON. |
| `companion/pairing.py`, `companion/link.py`, `companion/crypto.py` | Pairing client, link handshake and frame codec, link cryptography. |
| `companion/lamarzocco.py`, `companion/dashboard.py` | La Marzocco client, and the dashboard filter. |
| `companion/store.py` | The files in `data/secrets/`. |
| `companion/page.html` | Status and pairing page, styled like the setup page. |
| `setup` | Setup and check script, run on the server. |
| `compose.host.yaml`, `compose.existing-network.yaml` | Network modes, chosen with `COMPOSE_FILE`. |
| `data/` (volume) | CA and server certificate with their keys (readable only by root), and the last controller found. |
| `data/secrets/` (volume) | Companion id and pairing key, pairing secret, La Marzocco account and installation key (folder 0700, files 0600). |
| `/run/gateway/` (container) | Rendered nginx configuration, setup pages, `status.json`, the Web UI cache and the service's socket. |
