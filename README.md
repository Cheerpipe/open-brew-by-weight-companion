# Open Brew by Weight Companion

A small Docker container that runs beside your [Open Brew by Weight](https://github.com/Cheerpipe/Open-Brew-by-Weight)
controller, on a computer at home that is always on. It is optional: the
controller does everything on its own, and the companion takes work off it.

- **A secure address for the Web UI:**
  **`https://openbrewbyweight-secure.local`**. Over HTTPS your phone keeps a
  full copy of the Web UI. It opens instantly, shows up even while the
  espresso machine is off, and reconnects on its own as soon as the
  controller is back. The controller's own address keeps working as before.
- **Every screen live at once.** Once paired, a phone, a tablet and a computer
  can all use the Web UI through the companion at the same time, each on its
  own page, while the controller serves a single one: the companion's.
- **The La Marzocco cloud, handled for the controller** (Linea Micra). Once
  you pair the companion and turn this on, the companion keeps the
  connection to La Marzocco's servers. The controller stops encrypting and
  parsing cloud traffic, which leaves its radio to your scale, and keeps
  showing the same machine state and sending the same commands. If the
  companion goes away, the controller quietly goes back to its own
  connection.

The companion does the fiddly parts for you:

- **Finds the controller by itself** over mDNS, even after you rename it or
  its address changes. If your network does not pass mDNS to the companion,
  it searches your home network for the controller instead.
- **Announces its own `.local` name**, so every device on the network can
  open it without touching your router.
- **Creates and renews its certificate**, signed by a private certificate
  authority that only works for the companion's name.
- **Serves a setup page**, in English or Spanish to match the device, with
  step-by-step instructions, the right download for iPhone and iPad, Mac,
  Windows and Android, and a QR code to open it on a phone.
- **Sets itself up**: one command picks how the companion joins your network,
  starts it and checks that the Web UI answers through it.

## Pair it with the controller

Pairing is what lets the controller hand work to the companion and share its
Web UI between your screens. It takes a minute and you do it once:

1. Start the companion (see below). It finds the controller and asks to pair
   on its own.
2. The Web UI's Home shows that **Open Brew by Weight Companion** wants to
   connect, with the companion's name. Open **Admin → Companion**.
3. On any device, open the companion's page,
   **`http://openbrewbyweight-secure.local/__companion/`**. It shows a
   six-digit code. Type it in **Admin → Companion** and choose **Approve**.

The code proves that the companion asking is the one you are looking at, so
no other device on your network can pair in its place. If the request
expired or you did not see it, press **Pair with the controller** on the
companion's page and approve the new request. **Ignore** in Admin stops a
companion's requests until you choose **Stop ignoring**; **Forget** unpairs
it, and the companion then erases everything it received from the
controller.

A factory reset of the controller forgets the companion too, but the
companion cannot be sure the controller really means it, so it only stops
using your La Marzocco account and keeps it. Its page then offers **Pair
again** or **Erase this pairing**; until you choose one, your La Marzocco
account stays on the companion.

## Several screens at once

Without the companion, the controller shows its live Web UI on one device at a
time: opening it on another device takes it over, and the first one offers
**Reload**. Through a paired companion, every device that opens
**`https://openbrewbyweight-secure.local`** stays live:

- Home, the shot card, Settings, History, Stats, Diagnostic and its log work
  on every screen, each with its own page, filters and scroll position. A
  shot shows on all of them as it happens.
- The controller still talks to one Web UI only, the companion's, so a second
  or third screen adds almost nothing to its Wi-Fi traffic. The companion
  keeps what each new screen needs and answers it itself.
- Commands from different screens reach the controller one at a time, in the
  order you gave them, each after the previous one has taken effect.
- Each screen keeps its own Admin unlock: unlocking Admin on one screen locks
  it on the screen that had it, so only one screen at a time can change
  protected settings.
- Opening the Web UI at the controller's own address still takes it over:
  every companion screen then offers **Reload**, which brings that screen
  back and hands the Web UI back to the companion.

**Web UI through the companion**, in **Admin → Companion**, is on by default.
Turn it off to keep every device on the controller's own address: the
companion's secure address then shows a page with the controller's address
instead of the Web UI. A controller with older firmware, or a companion that
is not paired yet, keeps working as before: the companion passes the Web UI
straight through, one screen at a time.

## La Marzocco

On a Linea Micra, turn on **La Marzocco** in **Admin → Companion** after
pairing. There is nothing to type: the controller sends its La Marzocco
account to the companion, encrypted with a key only the two of them know.

- The companion signs in as its own installation of the La Marzocco app, so
  your account gains one installation, as when you install the app on a new
  phone. It follows your **Settings** for the connection type (WebSocket or
  API) and **Show power state**.
- At a quiet moment, never during a shot, the controller switches to the
  companion. You see the same machine state, temperature and power commands
  keep working, the scale and paddle still wake the machine, and backflush
  supervision is unchanged.
- When the companion stops, restarts or loses the network, the controller
  goes back to its own connection by itself, waiting until a shot with a
  scale has ended.
- Turning the switch off, or disconnecting the account in the Web UI, makes
  the companion erase the account. It keeps its installation key, so
  turning the switch on again adds no new installation to your account; the
  key goes when the companion is unpaired.
- With **Show power state** off the controller keeps using its own La
  Marzocco connection, and the companion does not sign in at all.

The companion's page shows whether it is paired, how many screens use the
Web UI through it, whether it is connected to the controller, and whether the
controller is using its La Marzocco connection.

## What you need

- An always-on **Linux** computer with Docker and Docker Compose on the same
  network as the controller, such as a NAS, a Raspberry Pi or a home server.
  Docker Desktop on a Mac or Windows PC cannot announce `.local` names to the
  rest of the network.
- If ports 80 and 443 are already in use on that server, for example by
  Home Assistant or another reverse proxy, a **free IP address** for the
  companion, outside the range your router hands out automatically. The setup
  suggests one.

## Install and run

Run this on the server:

```bash
git clone https://github.com/Cheerpipe/open-brew-by-weight-companion.git && cd open-brew-by-weight-companion && ./setup
```

`./setup` looks at your network and decides on its own wherever it can:

- If ports 80 and 443 are free, the companion shares the server's address.
  Otherwise it gets an address of its own, and the setup suggests a free one
  for you to confirm.
- If another container already has a network on your LAN, such as AdGuard
  Home or Pi-hole, the companion joins it.
- It builds and starts the container, waits until the companion finds the
  controller, and checks that the Web UI answers through the secure
  address. If something is missing, such as the controller's address, it
  asks.

Each step says when it starts and how it ended, with the time it took:

```text
  Building the companion image (about a minute the first time)…
  Image ready (52 s).
  Starting the companion…
  Running (4 s).
  Looking for the controller over mDNS (up to 20 s)…
  Not found over mDNS (20 s).
  Searching 192.168.4.0/24 for a controller (253 addresses, about 9 s)…
  Found Open Brew by Weight "openbrewbyweight" at 192.168.4.194, firmware 1.1.0 (8 s).
```

If mDNS does not find the controller within 20 seconds, which happens on
some networks, the setup asks every address of your home network once
whether it is an Open Brew by Weight controller. When it finds one, the
companion uses it and keeps following it; when it finds several, it lists
them and asks which one to use. Only if none answers, for example because
the espresso machine is off, does it ask for the controller's address,
which the Web UI shows under **Admin → Network**.

At the end it shows the setup address and a QR code. On each phone, tablet
or computer, open **`http://openbrewbyweight-secure.local`** (plain `http`)
and follow the steps for that device; see [device setup](docs/device-setup.md).
Then open **`https://openbrewbyweight-secure.local`** and sign in as usual.

Run `./setup` again any time: it checks the running companion, or changes its
settings if you choose to. `./setup --yes` accepts every suggestion without
asking. You can also fill in `.env` by hand from `.env.example` and run
`docker compose up -d --build`; the image is built from the `Dockerfile` in
this repository, which takes about a minute the first time.

### Update

Get the latest version, then rebuild and check it:

```bash
git pull && ./setup --yes
```

Your settings and the `data` folder are kept, so devices stay set up.

### Stop

```bash
docker compose down
```

This stops and removes the container but keeps `.env` and the `data` folder;
`docker compose up -d` starts it again.

## Configuration

All settings live in `.env`, which `./setup` writes for you. Settings from
the time this was called the HTTPS gateway (`GATEWAY_IP`, `HTTP_PORT`…)
still work, and `./setup` renames them in `.env` for you. To change one by
hand, edit `.env`, leave a value empty to use its default, and run
`docker compose up -d` again.

| Setting | Default | What it does |
| --- | --- | --- |
| `COMPANION_IP` | set by `./setup` | The companion's address: its own, or the server's when it shares it. |
| `LAN_INTERFACE` | set by `./setup` | The server's network interface, for example `eth0`. |
| `LAN_SUBNET` | set by `./setup` | Your network range, for example `192.168.1.0/24`. |
| `LAN_ROUTER` | set by `./setup` | Your router's address. |
| `LAN_DRIVER` | `macvlan` | `ipvlan` when the server itself is on Wi-Fi. |
| `COMPOSE_FILE` | `compose.yaml` | How the companion joins the network: add `compose.host.yaml` to share the server's address, or `compose.existing-network.yaml` to join `LAN_NETWORK`. |
| `LAN_NETWORK` | empty | A macvlan or ipvlan network that already exists on the server, to join instead of creating one; see [examples](examples/README.md#a-lan-network-that-already-exists). |
| `COMPANION_NAME` | this server's name | The name the companion shows on its pages. |
| `COMPANION_TZ` | `UTC` | Timezone of the companion's log lines (for example `America/Santiago`), so they line up with the controller's log. |
| `COMPANION_HOSTNAME` | `openbrewbyweight-secure` | The name devices open, followed by `.local`. Changing it means setting up every device again. |
| `COMPANION_MDNS_PUBLISH` | `true` | Turn off if your own DNS already points the name at the companion. |
| `COMPANION_HTTP_PORT` / `COMPANION_HTTPS_PORT` | `80` / `443` | Ports for the setup page and the secure Web UI. |
| `OBBW_CONTROLLER_URL` | empty | Empty finds the controller by itself. `http://<ip>` or `http://<name>.local` uses that one controller only. |
| `OBBW_CONTROLLER_NAME` | empty | With more than one controller, the device name to use, as shown in the Web UI. |
| `COMPANION_DATA` | `./data` | Folder that keeps the companion's certificate authority, pairing and keys. |
| `COMPANION_LOG_RETENTION_DAYS` | `30` | How long the controller's diagnostic log history is kept. |
| `COMPANION_LOG_RETENTION_MB` | `50` | Size budget for the stored diagnostic log; the oldest events go first. |

See [examples](examples/README.md) for setups done by hand: a server on
Wi-Fi, a fixed controller address, several controllers, your own DNS, and
sharing the server's address.

## What it stores, and your privacy

Everything lives in the `data` folder on your server:

| File | What it is |
| --- | --- |
| `openbrewbyweight-ca.*`, `server.*` | The certificate authority your devices trust and the companion's certificate. |
| `controller.json` | The controller found last, so the companion starts with it. |
| `secrets/identity.json` | The companion's id and its pairing key. |
| `secrets/pairing.json` | The secret it shares with the controller after pairing. |
| `secrets/credentials.json` | Your La Marzocco email, password and machine serial, only while La Marzocco is on. |
| `secrets/lamarzocco.json` | The key of the companion's own La Marzocco installation, kept until the companion is unpaired. |

The keys the companion uses to sign each screen's requests to the controller
live only in memory and change every time it starts.

- The `secrets` folder and the keys can be read only by the server's
  administrator (root).
- The pairing secret never crosses the network: the controller and the
  companion each work it out from the keys they exchanged. Your La Marzocco
  password crosses your network only encrypted with it.
- The only connection to the internet is the one to La Marzocco's own
  servers, and only while the La Marzocco switch is on.
- The log never shows passwords, tokens, keys or pairing codes.
- The companion's pages show its state and, while a request is open, the
  pairing code. Like the setup page, anyone on your network can open them;
  they never show account details.

## Good to know

- **Keep the `data` folder.** It holds the certificate your devices trust
  and the companion's pairing. If you delete it, every device has to be set
  up again and the companion paired again. Changing `COMPANION_HOSTNAME`
  also means setting up every device again, but keeps the pairing. Routine
  renewals happen by themselves and need nothing from your devices.
- **The certificate only works for the companion's name.** A device that trusts
  it cannot be fooled into trusting any other website with it.
- **The server cannot open the companion itself** because the companion has its
  own address. Every other device on the network can.
- **Each device signs in on its own.** A paired companion tells the controller
  which device each request comes from, signed so that no other device on
  your network can claim to be the companion, so five wrong passwords on one
  phone pause sign-in for that phone only. Before pairing, or with older
  firmware, every device looks like the same one to the controller, as with
  any reverse proxy, and five wrong passwords pause sign-in for everyone
  using the companion for 30 seconds.
- **The name has a single part before `.local` on purpose.** Names such as
  `secure.openbrewbyweight.local` work on Apple devices, but some Windows,
  Linux and Android devices cannot open `.local` names with more than one
  part. Android needs version 12 or newer for any `.local` name.
- **The companion saves the controller traffic.** It learns the
  controller's address from the announcements the controller already sends
  and only forwards what your devices ask for. It keeps a copy of the Web
  UI's files, so after a firmware update each one crosses the controller's
  Wi-Fi once rather than once per device. Only while it has not found the
  controller yet does it ask the network again, every few minutes. If mDNS
  has not found it after two minutes, the companion asks each address of
  your home network once whether it is a controller, and searches again
  only while no controller answers, at most every 30 minutes. A controller
  found that way gets one short request every 30 minutes to check that it
  is still there. Once paired, all your screens share one live connection to
  the controller, which closes a few seconds after the last screen does.
  While La Marzocco is on, the companion also keeps one quiet connection open
  for it: a short message when it connects, every two minutes, or every 15
  seconds while it carries La Marzocco (replacing the controller's own La
  Marzocco check one for one), and when its La Marzocco connection comes up
  or goes down, plus the machine's updates as La Marzocco sends them, each a
  few hundred bytes. Without La Marzocco that connection stays closed.

More: [device setup](docs/device-setup.md),
[troubleshooting](docs/troubleshooting.md) and
[how it works](docs/how-it-works.md).

## Development

The image is `nginx:1.28-alpine` plus Python, `zeroconf`, `aiohttp`,
`cryptography` and OpenSSL, all from Alpine's packages; nothing is installed
with `pip`. `gateway/gateway.py` is the supervisor (discovery, certificates,
nginx) and starts the companion service in `companion/` (pairing, the Web UI
relay for every screen, the controller link and the La Marzocco client); see
[how it works](docs/how-it-works.md). The link and relay protocols are defined in
the firmware's `docs/COMPANION_LINK.md`; `tests/fixtures` holds a copy of its
shared test vectors.

Every test runs offline inside the image, against a real nginx, a fake
controller (`tests/fake_controller.py` for the relay and the screens) and a
fake La Marzocco cloud:

```bash
docker build -t openbrewbyweight-companion:local . && for t in gateway cache protocol lamarzocco link relay screens scan logstore; do docker run --rm --network none -v "$PWD:/src:ro" --entrypoint python3 openbrewbyweight-companion:local /src/tests/test_$t.py || break; done
```

`./setup`'s test runs the script against a fake Docker (about 20 seconds,
since it waits out the real mDNS step) and needs bash, so it runs on the
server or your computer, as does the gateway test (Python 3.10+ and
OpenSSL 3):

```bash
python3 tests/test_setup.py && python3 tests/test_gateway.py
```

To try the companion on Docker Desktop (Mac or Windows), where it cannot
have its own LAN address, publish its ports and point it at the controller:

```bash
docker run -d --name openbrewbyweight-companion -p 8080:80 -p 8443:443 -v "$PWD/data:/data" \
  -e OBBW_CONTROLLER_URL=http://<controller ip> -e COMPANION_MDNS_PUBLISH=false \
  -e COMPANION_NAME="Test companion" openbrewbyweight-companion:local
```

Then open `http://localhost:8080/__companion/`.

To build only the image, without starting it:

```bash
docker build -t openbrewbyweight-companion:local .
```

## License

[GNU Affero General Public License v3.0](LICENSE), like Open Brew by Weight.
