# How it works

Open Brew by Weight Companion runs as one container with two programs:
**nginx**, which serves the pages and forwards traffic, and a Python
supervisor (`gateway/gateway.py`) that keeps nginx's configuration current
and runs the companion service (`companion/`) on a thread of its own. The
container's entrypoint (`gateway/entrypoint.sh`) has the supervisor render
nginx's configuration first, then runs nginx and the supervisor side by side;
the supervisor reloads nginx through its pid file, and when either one stops,
the other does too and Docker's restart policy starts the container again.

```text
phones ─https─▶ nginx ──pages, assets──────────────────────────▶ controller
  │               │ └─/api/, live updates, /__companion/─▶ companion service
  └─http (setup)──┘                    ├─signed REST, one ui-stream──▶ controller
                                       ├─link (ws), only while needed─▶ controller
                                       └─https/wss──▶ La Marzocco cloud
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

Until mDNS confirms a controller, each of those retries logs how many
devices' mDNS address records have reached the companion, so a log tells a
network that does not pass multicast to the companion's address (none) from
a controller that does not answer (some). `gateway.py mdns-check [name.local]`
goes further from inside the container: it prints the interfaces, their flags
and multicast groups, then asks for the controller's address and for
`_http._tcp` as a legacy unicast query (random source port, unicast answer),
a QM query and a QU query from port 5353, and prints every packet that
arrives with its source, destination and interface.

### Searching the network

When mDNS finds nothing, the supervisor searches the companion's own IPv4
network for the controller's unauthenticated identity route,
`GET /api/v1/integration/info`. It accepts only a JSON object with
`apiVersion` 1 and the keys `name`, `firmwareVersion` and `authRequired`.
Each address gets exactly one request, with a 1 s timeout, 32 at a time, no
redirects and no proxy, so a `/24` takes about 9 seconds. The network is the
most specific on-link route that holds the companion's address; it is
searched only when it is a private range (`10/8`, `172.16/12`,
`192.168/16`) no larger than `/22`, which also leaves out Docker's own
bridges, as on Docker Desktop.

- The supervisor searches 2 minutes after it starts without a controller,
  and never with `OBBW_CONTROLLER_URL` set or when it remembers a
  controller found over mDNS. With nothing found it tries again after 5,
  10 and then every 30 minutes.
- One controller found is used and remembered with the source `scan`. It
  gets one request (3 s timeout) every 30 minutes; only when that goes
  unanswered does the supervisor search again. With several, it uses the
  first one that matches `OBBW_CONTROLLER_NAME`, if set, and lists the
  others as `another controller`.
- As soon as mDNS finds the controller, mDNS takes over and the search stops.
- `gateway.py scan`, run inside the container, searches once and prints one
  line per step (`range`, `controller`, or `skip` with the reason). It
  remembers the controller when exactly one answers. `./setup` uses it.

When the controller announces a new address, the supervisor rewrites nginx's
configuration and reloads it without dropping connections. When the
controller goes away, the last known address is kept, because a restarting
controller announces itself again.

mDNS and the network search are not authenticated, so an answer alone never
moves a paired companion. Before adopting a new address, the service asks the
device there to prove the pairing secret, the same proof a relay handshake
uses, with a few tries for a controller still starting up. A device that cannot
is ignored, and the log says so. Answers naming this host or another network
are ignored too. Before pairing there is no secret to prove, so discovery
decides; the verification code protects that step.

### Network traffic

The controller shares one 2.4 GHz radio between Wi-Fi and the Bluetooth
scale, so the gateway avoids generating traffic toward it:

- No health checks or polling. Once the controller is known, discovery
  relies on its own announcements and on the standard mDNS query schedule,
  which backs off to roughly one query per hour. The faster retries above
  only run while no controller has been found. A controller found by
  searching the network gets a single request every 30 minutes, and the
  network search itself sends the controller one request.
- Each forwarded request closes its connection to the controller when done,
  which frees the controller's few sockets right away. At most two requests
  reach it at once: one command and one read. Live updates use one WebSocket
  for every screen, which closes 5 seconds after the last screen does.
  With **Shot archive in the companion** on, History and Shots cost the
  controller nothing: the companion answers them from its replica of the
  history ([screens and the relay](#screens-and-the-relay)); with it off,
  reopening one costs one small frame when the page has not changed.
- Once paired, while La Marzocco is on, the companion keeps one link open to
  the controller and sends only what the protocol needs: a ping when the link opens, every 2
  minutes (15 seconds while it carries La Marzocco, replacing the
  controller's own La Marzocco WebSocket ping) and when its La Marzocco
  connection comes up or goes down, and machine updates of a few hundred
  bytes as La Marzocco sends them. During a shot nothing crosses the link at
  all, in either direction: no ping, no record, no log. Pairing requests and
  polling happen only while you pair.

## Publishing the name

The supervisor registers an `_https._tcp` service whose host is the gateway's
name (`openbrewbyweight-secure.local` by default) at `COMPANION_IP`. That also
publishes the name's address record, so any device that understands mDNS can
open it. python-zeroconf shares the mDNS port with other responders on the
same host, such as Avahi or Home Assistant. On shutdown, the gateway sends
mDNS goodbye packets so devices forget the name at once.

## Certificates

On first start, the supervisor creates a private certificate authority (CA)
in the `data` folder, with Python's `cryptography` library:

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

nginx terminates HTTPS (TLS 1.2 and 1.3, HTTP/2) and sends everything to the
companion service: the Web UI's pages and files, verified as described under
[Verified files](#verified-files), and the API (`/api/`) and live updates
(`/api/v1/ui/ui-stream`), with the browser's address in `X-Real-IP`,
unbuffered, so live readings flow
without delay; it relays them for every screen (see
[Screens and the relay](#screens-and-the-relay)). Larger JSON answers, such
as the shot list, curves and statistics, leave compressed (`gzip`) for every
screen that accepts it; files the controller already sends compressed and
firmware update bytes are passed through untouched. Firmware updates from the
Web UI work through the companion as well: their 64 KiB chunks go through
it, signed like any other request. The companion's own controller routes
(`/api/v1/companion/…`) answer `404` through the secure address, except
`/api/v1/companion/admin`, which Admin → Companion sends.

### Verified files

Whatever a browser loads from this address runs with everything the address
protects, and the files reach the companion from the controller over plain HTTP,
where a device on your network could change them. So each file is checked first:

- The controller publishes a list with the hash of every file, sent sealed
  under the pairing, so a device on the network cannot change it. It describes
  the running firmware, and the companion reads it again in each relay session.
- A file is served only if its bytes match its hash. Its headers, the content
  security policy included, come from the list rather than from the network.
  One that does not match is read once more against a new list, in case the
  firmware was updated. Then it is refused and never kept: the browser gets the
  last verified copy or an error saying not to sign in, and the refusal is counted
  in **Diagnostic → This screen** and logged.
- A path that is not on the list goes to the Web UI, without asking the controller.
- A browser checking a service worker at any other path than `/sw.js` is told to
  remove it, so one planted earlier cannot stay.

A controller from before the list keeps working unverified, and Diagnostic says
so. nginx keeps none of its files, so nothing unverified outlives the firmware
update that verifies them.

This protects what the browser runs. It does not cover answers streamed in chunks
(the Wi-Fi scan, time zones, downloads), which are data, nor the controller's own
address, which stays plain HTTP.

### Web UI cache

The gateway keeps a copy of the Web UI's files, so the controller sends them
once instead of once per device. That matters most right after a firmware
update, when every phone loads the new Web UI at the same time.

- **Scripts, styles and icons** are kept for as long as the controller allows:
  a year for the versioned URLs the Web UI uses, never for any other. A
  firmware update changes those URLs, so the new files are fetched at once.
  When several devices ask for a file the gateway does not have yet, only one
  request reaches the controller.
- **Pages and the service worker** are checked with the companion on each
  load, at most once every couple of seconds. An unchanged page costs the
  controller nothing: the list already says it is current.
- **While the controller is off**, the gateway serves the last copy of each
  page it loaded, so a new device can still open the Web UI. Everything else
  waits for the controller.
- **Before each page**, nginx asks the companion service
  (`auth_request /__companion/ui-gate`). While the controller has the Web UI
  through the companion turned off, the service answers `403` and nginx shows
  the companion's notice with the controller's own address
  (`/__companion/ui-off`) instead; the service worker (`/sw.js`) always
  loads.

The API, live readings and firmware updates are never cached. Every cached
response carries an `X-Gateway-Cache` header (`HIT`, `MISS`, `REVALIDATED`,
`STALE`…) that shows where it came from. The cache lives in
`/run/gateway/assets` inside the container, holds at most 16 MB, drops files
unused for a year, and starts empty when the container is recreated.

When the gateway restarts, it serves the controller it last found, over
mDNS or by searching the network, right away, from `data/controller.json`,
and keeps searching until mDNS confirms that address or reports a new one. It forgets that controller when
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

On first start the service creates its id in `data/secrets/`. It is
independent of the certificate authority, so a new `COMPANION_HOSTNAME` keeps
the pairing. Each pairing attempt makes its own P-256 key, kept only in memory:
a key already seen in an earlier attempt would let a device in the middle
search for a key of its own that shows matching codes.

1. When it knows a controller it is not paired with, it sends one
   `POST /api/v1/companion/pair` with its id, name, version and a
   commitment to its public key (`SHA-256("obbw-companion-commit-v1" ‖
   key)`), not the key itself. It sends a new request only when you press
   **Pair** on its page, after a restart, or when the controller did not
   answer.
2. While the request is pending, it asks for its state about once a second.
   Once the controller answers with the key it made for this request, the
   service sends the same request again with this attempt's public key (the
   reveal).
   Only when the controller accepts the reveal does it compute the
   six-digit code from the two public keys and show it on the page. Both
   keys are fixed before either side sees the other's, so a device in the
   middle cannot search for keys that would show matching codes.
   While a pairing works, **Pair** does nothing: only Forget in Admin ends it.
3. On approval both sides derive the pairing secret with ECDH and HKDF.
   Nothing secret crosses the network. The service keeps it in
   `secrets/pairing.json`.

### What API answers may carry

Everything under `/api/` reaches a browser under the companion's trusted origin,
so only what the controller's API really sends passes: JSON, plain text, CSV and
binary downloads, with the headers those answers use. Anything else, HTML above
all, is refused and logged. An answer that is not a download also carries
`Content-Security-Policy: sandbox`, so it can never become a working page.

### The link

The service opens `ws://<controller>/api/v1/companion/link`; the controller
never connects to it. Both sides prove the pairing secret with fresh nonces
and derive a session key; every later frame carries a sequence number and
an HMAC, and a bad MAC or a wrong sequence closes the link. A frame type
this version does not know (from a newer controller) is ignored and
counted, and the page asks you to update the companion.

- **The controller's name:** when the link opens, and again whenever the
  controller is renamed, it sends its device name in a `dev` frame. The page
  and its pairing message use that name instead of the address, however the
  controller was found (by mDNS or by a configured address).
- **Liveness:** a `ping` as soon as the link opens, then every 2 minutes,
  every 15 seconds while the controller uses the companion for La Marzocco
  (and one right when it starts to), and one at once whenever its La
  Marzocco connection comes up or goes down (`up`), so the controller can
  move the route without waiting for the next interval. None during a sync
  hold (a shot, its drip delay, a scale connecting: the controller says so
  with `hold` and `sync` true, on every build), and one at once when the hold
  ends; both sides trust the link meanwhile, so only a missing answer to that
  first ping finds a link that dropped during the shot. The one exception is
  a controller that announces itself or answers a relay handshake during
  the hold: it pings at once as always, since a controller that restarted
  mid-shot never sends the `hold` that ends it. The controller
  answers a ping with both store epochs (`sh`, `hi`), the replica's
  heartbeat.
- **Liveness is not symmetric.** The controller sends nothing on its own,
  so it notices a silent companion after two ping intervals, while the
  companion notices a vanished controller through its own pings: the link
  socket closes when the controller has not acknowledged a ping within 30
  seconds (`TCP_USER_TIMEOUT`), that is within 2.5 minutes at most, without
  any extra traffic.
- **A restarted controller is found at once.** An mDNS announcement and a
  relay handshake are both the controller answering right now, so each
  sends a ping immediately: a link whose socket died with the controller's
  restart — a reboot sends no FIN or RST — fails that ping at once, or by
  the 30-second timeout at the latest, instead of at the next ping
  interval.
- **Reconnection:** after 5, 15 and 60 seconds, then every 5 minutes, and at
  once when the controller announces itself over mDNS or answers a relay
  handshake (a screen's request after the controller restarted starts one).
  A manual address runs no service browser, so any mDNS record of that
  address (the controller's boot announcement, its answer to another
  device) reopens a link that is down, at most once a minute; it never
  moves the address and leaves an open link alone. A relay handshake that
  nobody answered (the controller was off when the companion started) is
  asked again on the same schedule before each attempt, so a manual address
  that mDNS does not reach still reconnects. `RETRY_LATER` (a shot
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
  installation key but keeps the log history and the archive (a factory
  reset keeps the archive, and pairing the same controller again reattaches
  to both; only Forget erases them). The account stays on the companion
  until one of them is chosen. Each first asks the controller again, and a
  controller that proves the pairing, then or later, brings it back: an attempt
  to pair again that failed changed nothing.

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

When the cloud accepts the sign-in but answers `401` or `403` to the
dashboard or a command, the companion tells the controller that reads and
commands are refused while the subscription lives, and signs in again on the
next request. A `403` with the code `USER_MUST_ACCEPT_POLICY` is told apart:
the account only has to accept La Marzocco's latest terms, so the token is
kept and the controller is told the refusal is a pending policy. The
companion never accepts the terms itself; the La Marzocco app or the
controller does, and the companion's next successful read clears the
refusal. While a refusal lasts, the companion reads the dashboard once every
five minutes whichever route the controller uses, so a refusal that clears
elsewhere is noticed and the controller can route through the companion
again without a restart.

It runs while it holds the account, the controller's La Marzocco switch is
on and **Show power state** is on, whether the controller uses it or not.
With **Show power state** off the controller keeps La Marzocco on its own
connection, commands included, so the companion does not even sign in. It sends machine state only
while the controller has set the route to the companion:

- **Only what the controller reads.** Each La Marzocco event is reduced to
  La Marzocco's own dashboard shape with only `connected`, the machine mode,
  the coffee and steam boiler status, target and ready time (with the range
  the machine accepts for the coffee target; a steam boiler set by
  temperature sends its status and ready time only), and, in pushes
  only, the backflush status. An event that carries none of them is
  dropped; one that does is sent even when nothing changed.
- **`full`** when the route starts and after every new La Marzocco
  subscription; **`push`** for each WebSocket push; **`read`** for its own
  reads (after a token renewal, a `refresh` command, API polling, or to check
  a command no push confirmed within 5 seconds). While the controller reports
  a shot with a scale, pushes and reads wait out the shot: only the latest of
  each goes, in the order observed, once it ends. The controller drops
  pushes until it has the `full` frame of their subscription, so a push that
  arrives while that read is taken (the machine coming online right then)
  waits and follows it.
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

### Screens and the relay

The controller keeps one Web UI claim and one live-update session for the
companion, apart from those of a browser at its own address. The service holds
both on behalf of every screen that opens the secure address, so the
controller's work does not grow with the number of screens. The controller stays
in charge of sign-in, Admin unlock, lockouts and every safety gate; the direct
address works as before, and neither interrupts the other.

**Relay session.** It needs no clock and stores nothing. At start, on each
controller announcement and when the controller answers `RELAY_STALE`, the
service reads `GET /api/v1/companion/relay` (the controller's 16-byte
challenge `rb`), then `POST`s its id, a fresh nonce `nc` and
`HMAC(S, "R" ‖ rb ‖ nc)`. The controller proves the secret back with
`HMAC(S, "Q" ‖ rb ‖ nc)` and says whether the Web UI goes through the
companion (`ui`) and whether a feature needs the link (`link`). Both sides
derive `Kr = HKDF-SHA256(S, salt = rb ‖ nc, info = "obbw-relay-v1")` for
signing and, from it, `Kb = HKDF-SHA256(Kr, salt = "",
info = "obbw-relay-body-v2")` for sealing. A
forgotten companion receives `erase`, signed like the link's, and then
deletes its pairing; an unsigned "not paired" only stops La Marzocco.

The first request of every session reads `GET /api/v1/integration/info`, always
as relay version 2, to learn `relayFeatures`. From 1 the session's requests use
version 3, where each sealed answer also covers its request's `q` and its
status, so an answer held back from one request opens for no other. A sealed
answer with exactly the older keys means a controller from before this, which
stays on version 2 with a line in the log. Anything else opens no session: a
device on the network cannot lower it, only make it wait.

**Signed and sealed requests.** Each request to the controller carries
`X-OBBW-Relay: 2 <q> <addr> <screen> <mac>`: a counter from 1 per relay
session, the browser's address from nginx, the browser's own
`X-WebUI-Client`, and the first 16 bytes of
`HMAC-SHA256(Kr, "obbw-relay-v2\nMETHOD\nURI\nq\naddr\nscreen\nsession\n")`
in hex, where `URI` is the path and query exactly as sent and `session` the
sealed `X-WebUI-Session` value exactly as sent. Everything that carries a
credential is sealed with AES-256-GCM under `Kb`: the session token and the
device password (as base64 header values), the request body (raw ciphertext,
the 16-byte tag appended) and every JSON answer (sealed under a response
counter the controller names in `X-OBBW-Enc`, which never reaches the
browser). The 12-byte nonce is the direction, a context byte, two zeros and
the counter little-endian, so a seal belongs to exactly one request and
never repeats under one `Kb`. A seal that does not open — a tampered body,
or a corrupted answer — is refused (`RELAY_INVALID`) or dropped, never
delivered or re-sent opened; the answer case starts a new relay session.
Firmware update ranges (`X-OTA-*`, `Content-Range`) go as they are: the
image is not secret, and its integrity is pinned by the session's sha256,
which arrives sealed. The controller accepts each counter once. A request
the controller refused as `RELAY_STALE` is sent once more after a new
handshake. The source address alone is never trusted: a Docker host may
share its address with Home Assistant.

**One client id.** The service has one random 24-digit client id per start.
Every claim and sign-in goes with that id, so the controller sees one Web UI
owner for every screen; a screen whose claim the controller accepted sends
its later calls with that id too. Another browser's calls keep their own
id, so the controller still refuses what that browser may not do.

**Live updates.** Screens connect to the service; their ops are validated
against the controller's own rules (an invalid one closes that screen with
`4003`) and never forwarded as they are. The service opens one signed
ui-stream, binds it with the union of the screens' subscriptions and builds
every op itself:

- Home, Settings and Diagnostic are kept as merged models. A new screen gets
  one snapshot built from them (Diagnostic split into frames of at most
  20 KiB); Settings sends nothing when the screen's `tag` is current, and
  Home leaves out the presets the screen already holds. Home's controller
  clock (`timeUtcSec`) moves on by the time since it arrived: the
  controller sends it only when it rebases and every page runs it locally,
  so a late screen would otherwise count warm-up and other times from an
  old clock. The firmware lists every such per-session field in its
  `src/tests/fixtures/companion_replay_v1.json`; the screens test holds
  `CLOCKS` in `mux.py` to a checksum-pinned copy, so a new one fails until
  the companion handles it.
- The shot card is kept from its last snapshot (at most 512 frames or
  256 KiB) and replayed to a new screen.
- The log keeps a ring of the last 1,024 events (512 KiB) and serves each
  screen from its own cursor; a cursor the ring does not hold refills that
  screen from the oldest event.
- History and Stats keep one standing window for the group of screens with
  the same parameters, replayed to screens that join it (up to 16 pages or
  512 KiB). Other groups get one fetch with every parameter, once when they
  appear and again when the store changes; scrolls and exports are fetches
  too, one at a time, and identical ones are shared. Home's request for the
  shots before its hero card is such a fetch, from a screen that has no
  Stats window of its own. When the standing
  group's last screen leaves, the most recently active other group takes
  the window.
- When no screen holds History or Stats any more, the service still ends the
  controller's window but parks its last whole page in memory: the rows by
  id, the page's `tag`, boot and epoch, within the same bound. The next
  subscribe to that group names the `tag`, and nothing reaches the screen
  until the controller answers. An unchanged page comes back as bare ids
  with current totals and, for Stats, a fresh header (one small frame, no
  curve reads); the service puts
  the parked rows back before the page enters the buffer, so every screen,
  late ones included, gets whole rows. A changed page arrives whole as
  before. Ids the parked page cannot resolve, or an answer from another
  boot, ask for the page again without the `tag`. The parked page outlives
  the session's idle close and goes on Forget, when the link or the session
  is lost, and when an `rs` notice shows that its store moved.
- With **Shot archive in the companion** off, every Stats and History op,
  Home's last-shots fetch included, goes to the controller. With it on, the
  companion answers each one from its [replica](#the-replica) and sends
  nothing upstream for it. A screen's
  `records` op (a record index an older Web UI asked for) is ignored: it
  goes nowhere and the screen stays open, so a page cached before an update
  never loops on 4003. With the controller off the Web UI reads the
  [archive](#the-shot-and-activation-archive) over HTTPS instead.
- `activity` is aggregated: the controller hears the longest power window of
  the visible screens, and `hidden` only when every screen is hidden.
  Screens get `alive` from the service while the controller was heard in
  the last 25 seconds.

**Commands.** Changes go to the controller one at a time, in order, beside at
most one read and one sign-in or claim, so a slow download keeps no page from
opening. A download whose browser takes over 10 seconds to accept a chunk is cut.
After a `202` the next change waits until Home's
`lastCommand` shows that request settled, or 4 seconds, about as long as the
Web UI waits for it: `lastCommand` holds one request, so another screen's change
would hide the result from the screen that is waiting. A time sync holds nothing,
since it never reaches `lastCommand`. `/api/v1/control/*`, Stop among them, joins
no queue and goes at once. A request from a browser that left while it waited is
dropped. A change with no valid `X-WebUI-Client` is refused with `400 UI_CLIENT_INVALID` while
paired, so nothing acts under the session the screens share; such a read still goes
through. A signed-out screen (a relayed logout or `401 AUTH_REQUIRED`) loses its
claim and its live updates, closed with `4001`.

**The relay ends.** When the relay session ends for good (a Forget, an erase, the
Web UI through the companion turned off), the claims go, every screen is closed
with `4001` and the shared session closes. A controller that is busy or does not
answer a handshake (5xx, no reply) ends nothing: the session stays.

**Takeover and loss.** A controller whose firmware predates a separate claim for
the companion closes the shared session with `4001` when a browser opens the Web
UI at its own address; every screen is closed with `4001` (reason `direct`) and
offers **Reload**. Current firmware sends this only when every session is revoked. Losing
the controller closes the screens plainly, so they show the out-of-reach
notice and reconnect. A screen that falls 1 MiB behind is closed with
`4002` and reconnects quietly.

**Before pairing, and the switch.** Without a pairing there is no secret to seal,
verify or tell browsers apart with, so nothing is relayed. Every page redirects to
`/__companion/?pair=1`, even one nginx holds in its cache, because `auth_request`
runs first; `/api/` and the ui-stream answer `409 COMPANION_NOT_PAIRED`, the stored
log and archive refuse whatever was granted before, and any service worker is told
to unregister. Nothing from a browser reaches the controller. A pairing the controller
seems to have forgotten counts as none; since only a signed answer can say so for
certain, a page load asks it again, at most once a minute. From that page, a pairing
returns to the Web UI once the relay session is ready. A paired companion never falls
back: without a relay session `/api/` and the ui-stream answer `502` and name the
controller's own address, because a fallback would let anyone who breaks the handshake
turn the sealing off. The link stays on as before. A request starts a new handshake at most every
10 seconds after a failed one; an announcement, a `cfg` frame or an Admin action
starts one at once. While the Web UI through the companion is off, or the controller
seems to have forgotten this companion, a page load also asks the controller again, at
most once a minute. While the controller has
the Web UI through the companion turned off, `/api/` answers
`409 COMPANION_UI_OFF` and pages show the notice. The controller then answers only in
clear, and the handshake's `ui` is unsigned too, so with it off no browser gains access to
the stored log or archive: a grant from before stands until the controller says its login
is on. The link itself opens
only while the controller's relay answer says a feature needs it, such as
La Marzocco.

### The diagnostic log history

With **Diagnostic log through the companion** on, the controller streams its
diagnostic log over the link (`docs/COMPANION_LINK.md` in the firmware
repository has the frames) and the companion keeps it in SQLite at
`data/companion.db` (WAL, `user_version` migrations, every call on the same
single disk thread as the secrets).

- **Subscription.** In each session the companion sends `logsub` once both
  `cfg` turned the stream on and `dev` named the controller's id, with that
  id's newest stored `(boot, sequence)`. The id is kept in the database, so a
  restarted companion resumes from its cursor instead of asking for the whole
  ring again, and its pages show the history before any link opens. `logsub`
  and the resync after a failed write leave only outside a sync hold, like
  the archive's requests.
- **Rows and marks.** Boots are numbered in the order they arrive, and
  events are keyed by `(device id, that number, sequence)`: the controller
  streams only its current boot, so arrival order is time order, and a boot
  id it repeats (one it could not save, or a counter a full flash erase
  restarted) starts a new boot instead of overwriting an old one. The cursor
  is the newest boot's id with its last stored sequence. A `miss` (events
  the controller's ring overwrote) and a `reset` (a cursor the controller
  could not resume, which only a repeated boot id causes) become mark rows
  anchored to the first event after them; nothing stored is deleted by either.
- **Failures.** A log frame never closes the link: text past its bounds is
  cut, an unknown level reads as info, a frame without a usable boot or
  sequence is dropped and counted (`log.dropped`), and a frame the database
  could not write makes the companion send `logsub` again from its cursor, so
  the controller sends it again. A database that cannot open (damaged, newer
  schema, read-only volume) disables the history only; the status names why.
- **Retention.** On start and daily: events older than
  `COMPANION_LOG_RETENTION_DAYS` (events without a clock stay), then the
  oldest until the log tables' pages, their indexes included, fit
  `COMPANION_LOG_RETENTION_MB` — other controllers' rows first, the excess's
  share of them at a time, measured before and after; the archive's tables in
  the same file never count (SQLite's `dbstat`). Freed pages are reused, so the log settles near
  the budget without a vacuum. Each round then writes `companion.db.backup`
  with SQLite's online backup, on its own connections and thread.
- **Access.** `GET /__companion/log` (newest-first pages: `?boot=&before=&limit=`
  taken from the previous answer's opaque `next`, `limit` 1–2000, answering
  `entries`, `next`, `hasMore`; optional `level`, the levels kept as letters
  of `cewid`, `category` (one subsystem) and, on a first page, `at`: wall
  seconds, starting at the newest event at or before it, found through the
  `(device_id, wall_sec)` index; events without a clock keep their place by
  order), `GET /__companion/log/export` (optional `from` and `to`, wall
  seconds: the events from the oldest at or after `from` to the newest at or
  before `to`, with those in between in order), `GET /__companion/log/boots`
  (the stored boots with events, oldest first: each `boot` id, its first and
  last synced wall seconds `from` and `to`, null when none of its events had a
  clock, and `end`, a cursor shaped like `next` whose page ends at that boot's
  newest event without naming the newer restart, so the Web UI steps from boot
  to boot) and
  `POST /__companion/log/delete` answer only over HTTPS (nginx refuses them
  on plain HTTP with `403 HTTPS_REQUIRED`) and only for a browser the
  controller lets open the Web UI: the companion asks `GET /api/v1/auth`
  through the relay with the browser's `X-WebUI-Session`, at most every five
  minutes per session, and answers `401 AUTH_REQUIRED` otherwise. Accepted
  sessions are remembered (their SHA-256, for 90 days unseen), so they keep
  reading while the controller is off. Delete history (Diagnostic in the Web
  UI) needs the controller's answer at that moment
  (`503 CONTROLLER_UNREACHABLE` otherwise) with `adminUnlocked` true for the
  screen asking (`401 ADMIN_LOCKED` otherwise; see Changes below). Forget
  erases the history, the id and every remembered session; Delete history
  erases only the history.
- **Entries.** An event is `{"b","s","ms","w","l","c","m"}` (boot, sequence,
  uptime ms, wall-clock seconds or 0, level `c/e/w/i/d`, category, text). A
  marker is `{"g":"gap","count":N}`, `{"g":"reset"}` or
  `{"g":"boot","boot":B}` (a restart into boot B). Pages put a marker below
  the event it precedes, by time, so it stays in place when a filter leaves
  that event out; the export
  (`{"format":"openbrewbyweight-companion-log","version":2,"device":…,"entries":[…]}`,
  oldest first) puts it before.

### The shot and activation archive

With **Shot archive in the companion** on (`cfg` carries `"archive":true`;
a controller whose `cfg` has no `archive` cannot send records), the companion
copies both of the controller's record stores into the same database
(`companion/archive.py`, on the log store's connection and disk thread;
`docs/COMPANION_LINK.md` in the firmware repository has the frames). The
last `cfg`'s switch is kept (`meta` key `archive`), so a companion restarted
while the controller is off still reports it and answers the reads below.

- **Sync.** Once per session, after `cfg` and `dev`, it asks each store's
  index (`rx` with the epoch it holds), activations first, then shots, then
  traces. Afterwards the controller's `rs` notice (sent as soon as a change
  is saved, one second after the last of a run of ratings, and right after a
  shot) and the epochs in each ping answer name both stores' epochs, and
  only a store whose epoch moved is asked again, at once. Missing or changed records come
  through fetch windows (`rf`, newest first, every shot including bad ones,
  contiguous positions joined across small gaps), traces through `rt`, once
  each (`none` is stored, so it is never asked again; `saving` is skipped and
  `busy` ends the pass, both retried after 60 s). A request unanswered for
  300 s is sent again. The epoch, the controller's oldest id and the ids it
  listed are adopted only once every listed record is stored.
- **Index deltas.** The archive keeps its own in-memory copy of each store's
  index (every shot, bad ones included). Every listed index answer carries
  `sum`; once the current link session answered with one, an `rx` from the
  epoch that copy holds adds `d:1`, and the controller may answer with only the
  difference; the copy rebuilds the whole index, checks it against `sum` and
  the sync runs on it exactly as on a whole index. A difference that does
  not check out is logged and the whole index is asked once (`ep` 0, no `d`);
  a whole index that still does not check out stops that pass until the next
  notice. A new link session or a companion restart starts again from a
  whole index.
- **Generations.** Rows are keyed `(device, store, generation, id)`. The
  index names the store's write counter, next record id and the user's Clear
  count (`gen`, `next`, `clr`); an index without them or without `gone` is
  malformed and stops the pass. A `clr` above the one kept per store is a
  Clear the user made: every generation of that store is deleted, with its
  traces and holes, and the next opens; a lower one deletes nothing and is
  kept as the new baseline. Otherwise `gen` and `next` only grow and fall back
  only on a restarted history (a factory reset), so a decrease of either is
  a restart, decided before any
  page is written. When both may have overtaken their old
  values (a long absence), identities decide: the index's newest id below the last complete sync's
  oldest, or every id it shares with the archive another record (all shared
  ids are fetched before deciding), is a restart; when only some differ, the
  old record is set aside in generation 0 or below (archive-only) instead of
  being overwritten, and that pass mirrors no deletion. A restart deletes
  nothing: it closes the generation (all its rows become archive-only) and
  opens the next one, noting when. An empty index restarts the generation
  only when a counter fell back; otherwise it changes nothing. Pairing the same controller again reattaches to its rows,
  and erasing a pairing the controller no longer recognizes keeps them. A
  change the user makes during a pass makes it start again from the index.
- **Identity and deletions.** A shot is `bootId:endedAtMs`, an activation
  every immutable field (`type`, `durationS`, `hasWallTime`, `noWeight`,
  both end times), so a controller without a clock still tells records
  apart. Another identity under the same id replaces that record alone. In
  the open generation, a record missing from the index is deleted when its
  id is at least the index's oldest, or when the index's `gone` (the ids the
  user deleted last, at most 16) names it; below the oldest and not named it
  stays (rotation). A record deleted before it was copied is never listed
  again, so it is never copied. A hole row says how many records
  could not be copied. A refetched row whose curve is empty (the controller
  recycled it) keeps the stored curve.
- **Archive-only rows** are those of closed generations and those below the
  open generation's oldest id (records the controller no longer holds).
  `GET /__companion/archive/shots` and `/history` answer them with the
  controller's own semantics, so the Web UI merges them with the
  controller's list: `sort=date|rating` (shots), `dir=desc|asc`, `bad=1`,
  `result=`, `preset=`, `scale=` (the firmware's scale key, CRC-32 without
  the final xor), `types=` (activations), at most eight values each; rating
  order puts unrated shots last, then the rating, then the newest first.
  `cursor` is the opaque `next` of the previous page (a keyset on the sort
  key). `all=1` lists every copied row instead, each marked `archiveOnly`:
  the Web UI's read-only view with the controller off, which reads through
  the remembered grant like the log history and answers `409 ARCHIVE_OFF`
  while **Shot archive in the companion** is off. Each row carries
  `archiveGeneration` (shots also `archiveTrace`);
  the answer adds `holes`, `generations` (`generation`, `count`,
  `restartedAt`, `current`) and, for shots, `presets` found among those rows.
- **Changes.** The archive is a copy that follows the controller; the only
  changes the Web UI makes on it are `POST /__companion/archive/rate`
  (archive-only shots; a `generation` may be 0 or below for records set
  aside) and `/delete` (`store`, `id`, optional `generation`; archive-only
  rows only, `404 NOT_FOUND` for any other: the controller deletes its own
  records and the archive follows). Both need the controller's answer at that
  moment (`503 CONTROLLER_UNREACHABLE` otherwise). `/delete`, like the log's
  Delete history, also needs `adminUnlocked` true: the companion asks
  `GET /api/v1/auth` through the relay signing the browser's own
  `X-WebUI-Client` as the screen, so the controller answers for that screen's
  unlock, never the companion's shared client; without a relay session or a
  valid client id it is locked (`401 ADMIN_LOCKED`, logged). Reads, `GET .../trace` and
  `GET .../export` (every generation:
  `{"format":"openbrewbyweight-companion-archive","version":1,"device",
  "shots","history","traces","holes"}`) follow the log's rules (HTTPS only, a
  session the controller accepts, remembered while it is off). Forget erases
  the archive with the log.
- **Stats over the whole history.** `GET /__companion/archive/stats?window=
  10|50|100|500|1000&active=<preset of the "This preset" chart>&epoch=<the
  controller's shot epoch the screen saw>` (and the list's `result`,
  `preset`, `scale`) answers `{"stats","good","epoch"}`: `stats` is the
  header the firmware's `formatStatsHeader` builds, over every stored shot
  of every generation newest first (`companion/stats.py`, a line-for-line
  port held to the firmware's golden vectors
  `tests/fixtures/stats-header-v1.vectors.json`, checksum-pinned), and `good`
  the good shots the filters keep, from which the browser offers the window
  choices. When the copy is behind `epoch`, the companion syncs the shots at
  once and waits up to 8 s; it also syncs as soon as the live Stats frames a
  screen receives show a new shot. While the controller holds sync (or a
  request waits for it), the newest complete header answers at once with its
  own `epoch`. A real failure answers `503 STATS_UNAVAILABLE` (the cause in
  the companion's log, at most every five minutes); the browser then shows
  the controller's header, labelled as covering only its shots, offers 10, 50
  and 100 only, and asks again every 15 s while Stats are open. With the
  controller off (the link down) the header comes from the copy as it is. Headers and the status facts are cached by the
  archive's state; the header reads only the fields it needs.
- **No sync traffic during a shot.** The controller sends `hold` with
  `sync` true when a sync hold starts and `sync` false when it ends, on every
  build. In between the companion sends nothing (but the liveness exception
  above): no ping, `rx`, `rf`, `rt`,
  `logsub`, re-ask or retry; anything due waits, one per kind, and leaves
  the moment the hold ends. Until a session's first `hold` arrives, sync
  requests wait too.

### The replica

With **Shot archive in the companion** on, the archive is the replica the
mux serves Shots and History from (`companion/mux.py`, `companion/pages.py`).

- **Current or catching up.** A store is current once a pass ended at the
  epoch the controller last named (its `rs`, its ping answer, an index
  answer) with nothing changed since. A notice of another epoch, a rating,
  deletion or Clear the relay forwards (`POST /api/v1/stats/rate`,
  `/stats/delete`, `/stats/clear`, `/history/delete`, `/history/clear`: not
  current from the moment it leaves, caught up once the controller
  answered), or a new link session makes it catch up at once: the index (a
  delta when it can), then the changed records and new traces, back to back,
  paused only by a sync hold. Ratings, deletions and Clears made elsewhere
  (another screen opened directly, Home Assistant, the USB console) arrive
  as an `rs` notice.
- **Pages.** Every History and Stats subscribe, fetch and export window
  comes from the replica: the whole history, the controller's records and
  the ones only the companion keeps, filtered, ordered and sliced as the
  controller does, with `total`, `hasMore`, `good` and, for Stats, the
  header over the whole history for the active preset in Home's model. The
  frames match the controller's member for member (`tests/test_link_vectors.py`
  replays the firmware's `page_*` golden cases) except `tag`, `seq` and
  `request`, which the companion assigns; a screen that resubscribes with
  the page's own `tag` gets its rows as bare ids. Rows only the companion
  keeps carry `archiveOnly`, `archiveGeneration` and, for shots,
  `archiveTrace` (in a Stats row's last object), and that page's first
  frame adds `archive` (`generations`, `holes`) for the Web UI's markers and
  lines. A change to the copy (a catch-up that moved an epoch, a rating or
  deletion of an archive-only record) or a new active preset sends every
  open page again.
- **Waiting and falling back.** A page whose store is not current waits for
  its catch-up; when it cannot finish within 3 seconds (the link is down or
  the controller does not answer), that page comes whole from the controller
  through the shared session, as with the switch off, never mixed. During a
  sync hold the replica serves what it holds and nothing goes upstream.
- **Traces.** `GET /api/v1/diagnostic/shot-trace` for a shot whose trace the
  replica holds is answered by the companion (for a browser the controller
  lets in, as for the archive's reads); any other goes to the controller.
- **Tables.** `archive_records`, `archive_traces`, `archive_sync` and
  `archive_holes`, in schema 4 of `companion.db`; the log's size budget
  counts only the log's own tables. Schema 4 turned the records an earlier
  companion kept after a deletion into ordinary archive-only rows (setting
  aside those of the open generation the controller may still list) and
  dropped the exclusions, so a record one kept out is copied again while the
  controller holds it.

### Beanconqueror

The firmware's [Beanconqueror machine endpoints](https://github.com/Cheerpipe/Open-Brew-by-Weight/blob/main/docs/schemas/README.md#beanconqueror-machine-endpoints-v1)
are served here too, from the archive alone. The controller's `cfg` names the
format (`bc`: `gaggiuino`, `gaggimate` or `off`, which it sends only while the
archive and **Beanconqueror through the companion** switches are on); the
companion keeps it in the log store, so it answers after its own restart with
the controller off, and forgets it with the pairing. A request never reaches
the controller: `/beanconqueror/` reads the open generation's good shots,
newest first, with the controller's ids (`companion/beanconqueror.py`, pinned
by `tests/fixtures/beanconqueror-v1.vectors.json`, byte-identical to the
firmware's). nginx passes it on both ports, without the Web UI gate and with
the request's `Host`, checked as the controller checks its own: an IP address,
or the companion's host name, bare or under a home-network suffix (`.local`,
`.lan`, `.home.arpa`, `.internal`), so a page from elsewhere cannot read it
through a rebound name. The address is public by design, like the machines it
stands in for. Each
served shot is logged at INFO (`Beanconqueror: shot <id> sent as a Gaggiuino
shot`, or `GaggiMate`), as the controller logs its own. The
status JSON gives `beanconqueror`, `ip` and `httpPort` for the address the
Settings section shows.

### Notifications

`companion/push.py` delivers Web Push and decides nothing else: the controller
decides which events exist and when they fire, and the firmware's service worker
holds all their text. An `ev` link frame's `d` is encrypted and sent unread to the
subscriptions listing its `topic`, which are opaque strings the Web UI chose. A new
event or wording needs no change here. The frames are in the firmware's
`docs/COMPANION_LINK.md`.

- **Keys and devices.** The VAPID key is derived from the companion's identity key, so
  it needs no file. Up to 16 subscriptions live in `data/secrets/push.json` (0600), and the
  last 50 events in `data/secrets/push-activity.json`; neither exists until a device
  subscribes. An endpoint can address its device, so it is never logged or returned;
  everything names a device by a hash of it. **Forget** erases both files; the erase
  that keeps your history keeps them too.
- **Asking.** With a device subscribed, the companion sends `ps` `on:true` on each
  session's `cfg`, and `on:false` when the last one leaves. With none, the controller
  sends no `ev`. `ps` waits for the end of a sync hold, like any sync request.
- **Sending.** Encryption is RFC 8291 and the token RFC 8292, reused for an hour per push
  service, so no account is needed. Sends go only to `fcm.googleapis.com`,
  `*.push.apple.com`, `*.push.services.mozilla.com` and `*.notify.windows.com`, checked when
  subscribing and when sending, with TLS verified and redirects not followed. 404 and 410
  remove the subscription; 400, 401, 403 and 413 are reported and not retried; 429, 5xx and
  network failures retry after 5, 30 and 120 s, honoring `Retry-After`, within the event's TTL.
- **Routes.** Under `/__companion/push/`, HTTPS only (nginx refuses them in clear), JSON
  only. `status` and `test` need a browser the controller would let open the Web UI. A new
  device's `subscribe` needs that answer now; a known device refreshes with the controller
  off. `unsubscribe` and `ack` accept the holder of the endpoint, so turning off works signed
  out. `remove` (another device) needs Admin unlocked. `test` reaches only the asking
  device, once within 2 s. `/__companion/status` carries `push`, with the public key only.

A failure here stays here: it is recorded for **Diagnostic → Push** and never affects the
link or the archive. Only a malformed `ev` closes the link, like any malformed frame.

### Status page and JSON

`/__companion/` (and `/__companion/pair`) is the status and pairing page.
`/__companion/status` returns the same state as JSON for the Web UI's
Diagnostic page: `name`, `version`, `id`, `paired`, `pairingRequired`, `pairedWith`, the
`controller`, `pairing` (`state`, and the `code` while pending), `relay`
(`passthrough`, `ready` or `disabled`; `passthrough` means no session yet, and
nothing is relayed), `relayFeatures`, `assets` (files `verified` and `refused`,
`lastPath`, `legacy`), `screens` (screens connected),
`owner` (whether the companion holds the controller's Web UI claim),
`views` (screens per view: `home`, `settings`, `diagnostic`, `log`,
`history`, `stats`), `link`
(`down`, `connecting`, `open` or `retry` with `linkReason`, for example
`VERSION` when the controller speaks another link version or `ERROR` after
an unexpected error), the La Marzocco `route`, `unknownFrames` (frames of
an unknown type in this session), `laMarzocco` (`enabled`, `account`,
`connection`, `subscribed`, `up`) and `log` (`enabled`, `days`, `mb`,
`dropped`, and the store's `rows`, `bytes`, `oldestBoot`, `newestBoot`,
`marks`, `missed` for the controller's id, or `error`) and `archive` (`on`,
`available`, `syncing`, `syncedAt`, `error`, `replica` (per store `off`,
`current` or `catchingUp`), the counters `served` (pages and traces the
replica answered), `fallbacks` (pages it left to the controller) and
`catchUpFetches` (requests it sent the controller to catch up), `generations`
per store, and per store the archive-only count `shots`/`history`,
`shotsTotal`/`historyTotal` and the first and last end times, plus `traces`,
`bytes` and `holes`). `POST /__companion/pair` with a JSON
body sends a new pairing request, and `POST /__companion/erase` erases a
pairing the controller no longer recognizes (`409` while it works; only over
HTTPS, nginx answers `403 HTTPS_REQUIRED` on plain HTTP, since it deletes
secrets); a page on another site cannot send either without asking.

## Status and health checks

`/__companion/gateway`, on both the setup page and the secure address, returns
the gateway's state as JSON (`/__gateway/status`, its earlier address,
redirects there): its name and address, the controller in use and
where it came from (`mdns`, `remembered`, `scan` or `manual`), every `_http._tcp`
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
It then builds the image and starts the container, saying when each step
starts and how it ended, waits up to 20 seconds for mDNS, and otherwise runs
`gateway.py scan`. One controller found is remembered and the container
restarted to use it; with several, it lists them and asks which, then sets
`OBBW_CONTROLLER_NAME` (or `OBBW_CONTROLLER_URL` when two have the same
name). It asks for the controller's address only when nothing answers.

## Files

| Path | Purpose |
| --- | --- |
| `gateway/gateway.py` | Supervisor: configuration, discovery, mDNS, certificates, rendering. |
| `gateway/entrypoint.sh` | The container's entrypoint: renders, then runs nginx beside the supervisor. |
| `gateway/nginx.conf.in` | nginx configuration template. |
| `gateway/setup.html` | Setup page template. |
| `gateway/strings.json` | Setup page texts. |
| `companion/service.py` | Companion service: the link, the La Marzocco route, the status page and JSON. |
| `companion/relay.py` | Relay session, signed requests, header whitelist. |
| `companion/screens.py`, `companion/mux.py`, `companion/upstream.py` | Screens' API and live updates, the multiplexer, and the one session with the controller. |
| `companion/pairing.py`, `companion/link.py`, `companion/crypto.py` | Pairing client, link handshake and frame codec, link cryptography. |
| `companion/lamarzocco.py`, `companion/dashboard.py` | La Marzocco client, and the dashboard filter. |
| `companion/store.py` | The files in `data/secrets/`. |
| `companion/logstore.py` | The owner of `data/companion.db`: the controller's log history, migrations, backup and erase. |
| `companion/archive.py` | The shot and activation archive in the same database, and its sync. |
| `companion/push.py` | Web Push delivery: keys, subscriptions, encryption and sending. |
| `companion/index_mirror.py` | The controller's record index as the archive last received it, rebuilt from deltas and checked by `sum`. |
| `companion/stats.py` | The Stats header over the whole history, ported from the firmware. |
| `companion/page.html` | Status and pairing page, styled like the setup page. |
| `companion/ui-off.html` | Notice with the controller's address while the Web UI goes directly to it. |
| `setup` | Setup and check script, run on the server. |
| `compose.host.yaml`, `compose.existing-network.yaml` | Network modes, chosen with `COMPOSE_FILE`. |
| `data/` (volume) | CA and server certificate with their keys (readable only by root), and the last controller found. |
| `data/secrets/` (volume) | Companion id and pairing key, pairing secret, La Marzocco account and installation key (folder 0700, files 0600). |
| `data/companion.db`, `data/companion.db.backup` (volume) | The controller's log history and the archive, and their daily consistent copy. |
| `/run/gateway/` (container) | Rendered nginx configuration, setup pages, `status.json`, the Web UI cache and the service's socket. |
