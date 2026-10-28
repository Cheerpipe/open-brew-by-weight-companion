# Examples

`./setup` handles most of these by itself. Each example changes only a few
lines of `.env`; everything else stays as in [`.env.example`](../.env.example).
Run `docker compose up -d` after editing.

## Wired server (default)

The companion gets `192.168.1.240` on a typical `192.168.1.x` home network:

```dotenv
COMPANION_IP=192.168.1.240
LAN_INTERFACE=eth0
LAN_SUBNET=192.168.1.0/24
LAN_ROUTER=192.168.1.1
```

Choose an address your router never hands out automatically. Most routers
show their automatic (DHCP) range in their settings.

## Server on Wi-Fi

Wi-Fi access points usually accept only one hardware address per device, so
use `ipvlan`, which shares the server's:

```dotenv
LAN_INTERFACE=wlan0
LAN_DRIVER=ipvlan
```

## A LAN network that already exists

Docker allows only one macvlan or ipvlan network per address range. If
another container, such as AdGuard Home or Pi-hole, already has one,
`docker compose up` fails with `Pool overlaps with other one on this address
space`. Find that network:

```bash
docker network ls --filter driver=macvlan --filter driver=ipvlan
```

Then join it instead of creating a new one:

```dotenv
COMPOSE_FILE=compose.yaml:compose.existing-network.yaml
LAN_NETWORK=adguard-macvlan
```

Keep the other `LAN_*` values filled in; they describe the same network.
`COMPANION_IP` must still be free and outside the router's automatic range.
This needs Docker Compose 2.24 or newer.

## A Raspberry Pi with Docker

The image runs on 64-bit Raspberry Pi OS as is. With the Pi on its cable,
the defaults above work with `LAN_INTERFACE=eth0`.

## A fixed controller address

If neither mDNS nor the companion's search of your network finds the
controller, for example because it is on a different network than the
companion, give the controller a fixed address in your router and point the
companion at it:

```dotenv
OBBW_CONTROLLER_URL=http://192.168.1.50
```

With an IP address, the companion sends no mDNS queries at all. A `.local`
name, such as `http://cafe-bar.local`, still follows address changes.

## Several controllers

Name the one this companion serves, as shown in the Web UI:

```dotenv
OBBW_CONTROLLER_NAME=Cafe Bar
```

For a second controller, run a second copy of this folder with its own
`COMPANION_IP`, `COMPANION_HOSTNAME` (for example `cafe-bar-secure`),
`OBBW_CONTROLLER_NAME` and `COMPANION_DATA`.

## A different name

```dotenv
COMPANION_HOSTNAME=espresso
```

Devices then open `https://espresso.local`. Changing the name later creates a
new certificate authority, and every device has to be set up again.

## Your own DNS instead of mDNS

If your router or Pi-hole already resolves a name to the companion, turn off
the mDNS announcement and use that name. It must end in `.local` here,
matching `COMPANION_HOSTNAME`:

```dotenv
COMPANION_MDNS_PUBLISH=false
```

## Run on the server's own address

When ports 80 and 443 are free on the server, the companion can share its
address instead of getting one of its own; `./setup` chooses this by itself.
By hand:

```dotenv
COMPOSE_FILE=compose.yaml:compose.host.yaml
COMPANION_IP=
```

With `COMPANION_IP` empty, the companion uses the server's main address, and the
`LAN_*` settings are not used. If the ports are busy, choose others with
`COMPANION_HTTP_PORT` and `COMPANION_HTTPS_PORT`; devices then open the name with the port, for
example `https://openbrewbyweight-secure.local:8443`.
