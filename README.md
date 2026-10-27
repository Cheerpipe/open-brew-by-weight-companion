# Open Brew by Weight HTTPS gateway

A small Docker container that gives the [Open Brew by Weight](https://github.com/Cheerpipe/Open-Brew-by-Weight)
Web UI a secure address on your home network:
**`https://openbrewbyweight-secure.local`**.

Over HTTPS your phone keeps a full copy of the Web UI. It opens instantly,
shows up even while the espresso machine is off, and reconnects on its own as
soon as the controller is back. The controller's own address keeps working as
before.

The gateway does the fiddly parts for you:

- **Finds the controller by itself** over mDNS, even after you rename it or
  its address changes.
- **Announces its own `.local` name**, so every device on the network can
  open it without touching your router.
- **Creates and renews its certificate**, signed by a private certificate
  authority that only works for the gateway's name.
- **Serves a setup page**, in English or Spanish to match the device, with
  step-by-step instructions, the right download for iPhone and iPad, Mac,
  Windows and Android, and a QR code to open it on a phone.
- **Sets itself up**: one command picks how the gateway joins your network,
  starts it and checks that the Web UI answers through it.

## What you need

- An always-on **Linux** computer with Docker and Docker Compose on the same
  network as the controller, such as a NAS, a Raspberry Pi or a home server.
  Docker Desktop on a Mac or Windows PC cannot announce `.local` names to the
  rest of the network.
- If ports 80 and 443 are already in use on that server, for example by
  Home Assistant or another reverse proxy, a **free IP address** for the
  gateway, outside the range your router hands out automatically. The setup
  suggests one.

## Install and run

Run this on the server:

```bash
git clone https://github.com/Cheerpipe/open-brew-by-weight-https-gateway.git && cd open-brew-by-weight-https-gateway && ./setup
```

`./setup` looks at your network and decides on its own wherever it can:

- If ports 80 and 443 are free, the gateway shares the server's address.
  Otherwise it gets an address of its own, and the setup suggests a free one
  for you to confirm.
- If another container already has a network on your LAN, such as AdGuard
  Home or Pi-hole, the gateway joins it.
- It builds and starts the container, waits until the gateway finds the
  controller, and checks that the Web UI answers through the secure
  address. If something is missing, such as the controller's address, it
  asks.

At the end it shows the setup address and a QR code. On each phone, tablet
or computer, open **`http://openbrewbyweight-secure.local`** (plain `http`)
and follow the steps for that device; see [device setup](docs/device-setup.md).
Then open **`https://openbrewbyweight-secure.local`** and sign in as usual.

Run `./setup` again any time: it checks the running gateway, or changes its
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

All settings live in `.env`, which `./setup` writes for you. To change one by
hand, edit `.env`, leave a value empty to use its default, and run
`docker compose up -d` again.

| Setting | Default | What it does |
| --- | --- | --- |
| `GATEWAY_IP` | set by `./setup` | The gateway's address: its own, or the server's when it shares it. |
| `LAN_INTERFACE` | set by `./setup` | The server's network interface, for example `eth0`. |
| `LAN_SUBNET` | set by `./setup` | Your network range, for example `192.168.1.0/24`. |
| `LAN_ROUTER` | set by `./setup` | Your router's address. |
| `LAN_DRIVER` | `macvlan` | `ipvlan` when the server itself is on Wi-Fi. |
| `COMPOSE_FILE` | `compose.yaml` | How the gateway joins the network: add `compose.host.yaml` to share the server's address, or `compose.existing-network.yaml` to join `LAN_NETWORK`. |
| `LAN_NETWORK` | empty | A macvlan or ipvlan network that already exists on the server, to join instead of creating one; see [examples](examples/README.md#a-lan-network-that-already-exists). |
| `GATEWAY_HOSTNAME` | `openbrewbyweight-secure` | The name devices open, followed by `.local`. Changing it means setting up every device again. |
| `MDNS_PUBLISH` | `true` | Turn off if your own DNS already points the name at the gateway. |
| `HTTP_PORT` / `HTTPS_PORT` | `80` / `443` | Ports for the setup page and the secure Web UI. |
| `OBBW_CONTROLLER_URL` | empty | Empty finds the controller by itself. `http://<ip>` or `http://<name>.local` uses that one controller only. |
| `OBBW_CONTROLLER_NAME` | empty | With more than one controller, the device name to use, as shown in the Web UI. |
| `GATEWAY_DATA` | `./data` | Folder that keeps the gateway's certificate authority. |

See [examples](examples/README.md) for setups done by hand: a server on
Wi-Fi, a fixed controller address, several controllers, your own DNS, and
sharing the server's address.

## Good to know

- **Keep the `data` folder.** It holds the certificate your devices trust.
  If you delete it or change `GATEWAY_HOSTNAME`, the gateway creates a new one
  and every device has to be set up again. Routine renewals happen by
  themselves and need nothing from your devices.
- **The certificate only works for the gateway's name.** A device that trusts
  it cannot be fooled into trusting any other website with it.
- **The server cannot open the gateway itself** because the gateway has its
  own address. Every other device on the network can.
- **Every phone looks like the same device to the controller**, as with any
  reverse proxy, so five wrong passwords pause sign-in for everyone using the
  gateway for 30 seconds.
- **The name has a single part before `.local` on purpose.** Names such as
  `secure.openbrewbyweight.local` work on Apple devices, but some Windows,
  Linux and Android devices cannot open `.local` names with more than one
  part. Android needs version 12 or newer for any `.local` name.
- **The gateway adds no traffic to the controller.** It learns the
  controller's address from the announcements the controller already sends
  and only forwards what your devices ask for. Only while it has not found
  the controller yet does it ask the network again, every few minutes. The controller still allows
  one live Web UI at a time, exactly as without the gateway.

More: [device setup](docs/device-setup.md),
[troubleshooting](docs/troubleshooting.md) and
[how it works](docs/how-it-works.md).

## Development

The image is `nginx:1.28-alpine` plus Python, `zeroconf` and OpenSSL from
Alpine's packages. `gateway/gateway.py` is the whole supervisor. The tests
need Python 3.10+ and OpenSSL 3 on the `PATH`, and use neither the network
nor Docker:

```bash
python3 tests/test_gateway.py
```

To build only the image, without starting it:

```bash
docker build -t openbrewbyweight-https-gateway:local .
```

## License

[GNU Affero General Public License v3.0](LICENSE), like Open Brew by Weight.
