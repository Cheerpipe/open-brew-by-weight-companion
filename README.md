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
- **Serves a setup page** with step-by-step instructions and the right
  download for iPhone and iPad, Mac, Windows and Android.

## What you need

- An always-on **Linux** computer with Docker and Docker Compose on the same
  network as the controller, such as a NAS, a Raspberry Pi or a home server.
  Docker Desktop on a Mac or Windows PC cannot announce `.local` names to the
  rest of the network.
- A **free IP address** for the gateway, outside the range your router hands
  out automatically. The gateway gets its own address, so it never clashes
  with Home Assistant, another reverse proxy, or anything else already using
  ports 80 and 443 on the same server.

## Install and run

There is no prebuilt image to download: Docker Compose builds it from the
`Dockerfile` in this repository the first time you start it. Run these steps
on the server.

1. Get the code:

   ```bash
   git clone https://github.com/Cheerpipe/open-brew-by-weight-https-gateway.git
   ```

   ```bash
   cd open-brew-by-weight-https-gateway
   ```

2. Create your settings from the example:

   ```bash
   cp .env.example .env
   ```

   Open `.env` in any text editor, for example `nano .env`, and fill in the
   four network values: `GATEWAY_IP`, `LAN_INTERFACE`, `LAN_SUBNET` and
   `LAN_ROUTER`. `ip -br addr` shows the interface and its range, and
   `ip route` shows the router after `default via`.

3. Build the image from the `Dockerfile` and start the container:

   ```bash
   docker compose up -d --build
   ```

   The first build downloads the nginx base image and a few packages, which
   takes about a minute. The container starts again by itself after a
   restart of the server.

4. Check that it found the controller:

   ```bash
   docker compose logs -f
   ```

   Look for `publishing openbrewbyweight-secure.local at 192.168.1.240` and
   `controller Cafe Bar at 192.168.1.50:80`, with your own name and
   addresses. Press Ctrl-C to stop watching; the gateway keeps running.

5. On each phone, tablet or computer, open
   **`http://openbrewbyweight-secure.local`** (plain `http`) and follow the
   steps for that device; see [device setup](docs/device-setup.md). Then open
   **`https://openbrewbyweight-secure.local`** and sign in as usual.

### Update

Get the latest version and rebuild the image:

```bash
git pull
```

```bash
docker compose up -d --build
```

Your settings and the `data` folder are kept, so devices stay set up.

### Stop

```bash
docker compose down
```

This stops and removes the container but keeps `.env` and the `data` folder;
`docker compose up -d` starts it again.

## Configuration

All settings live in `.env`. Leave a value empty to use its default, and run
`docker compose up -d` again after changing it.

| Setting | Default | What it does |
| --- | --- | --- |
| `GATEWAY_IP` | required | The gateway's own address on your network. |
| `LAN_INTERFACE` | required | The server's network interface, for example `eth0`. |
| `LAN_SUBNET` | required | Your network range, for example `192.168.1.0/24`. |
| `LAN_ROUTER` | required | Your router's address. |
| `LAN_DRIVER` | `macvlan` | Use `ipvlan` when the server itself is on Wi-Fi. |
| `GATEWAY_HOSTNAME` | `openbrewbyweight-secure` | The name devices open, followed by `.local`. Changing it means setting up every device again. |
| `MDNS_PUBLISH` | `true` | Turn off if your own DNS already points the name at the gateway. |
| `HTTP_PORT` / `HTTPS_PORT` | `80` / `443` | Ports for the setup page and the secure Web UI. |
| `OBBW_CONTROLLER_URL` | empty | Empty finds the controller by itself. `http://<ip>` or `http://<name>.local` uses that one controller only. |
| `OBBW_CONTROLLER_NAME` | empty | With more than one controller, the device name to use, as shown in the Web UI. |
| `GATEWAY_DATA` | `./data` | Folder that keeps the gateway's certificate authority. |

See [examples](examples/README.md) for common setups: a server on Wi-Fi, a
fixed controller address, several controllers, your own DNS, and running on
the server's own address.

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
  and only forwards what your devices ask for. The controller still allows
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
