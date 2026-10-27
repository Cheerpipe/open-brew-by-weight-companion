# Examples

Each example changes only a few lines of `.env`; everything else stays as in
[`.env.example`](../.env.example). Run `docker compose up -d` after editing.

## Wired server (default)

The gateway gets `192.168.1.240` on a typical `192.168.1.x` home network:

```dotenv
GATEWAY_IP=192.168.1.240
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

## A Raspberry Pi with Docker

The image runs on 64-bit Raspberry Pi OS as is. With the Pi on its cable,
the defaults above work with `LAN_INTERFACE=eth0`.

## A fixed controller address

If discovery cannot see the controller, for example because mDNS does not
cross between your Wi-Fi and wired networks, give the controller a fixed
address in your router and point the gateway at it:

```dotenv
OBBW_CONTROLLER_URL=http://192.168.1.50
```

With an IP address, the gateway sends no mDNS queries at all. A `.local`
name, such as `http://cafe-bar.local`, still follows address changes.

## Several controllers

Name the one this gateway serves, as shown in the Web UI:

```dotenv
OBBW_CONTROLLER_NAME=Cafe Bar
```

For a second controller, run a second copy of this folder with its own
`GATEWAY_IP`, `GATEWAY_HOSTNAME` (for example `cafe-bar-secure`),
`OBBW_CONTROLLER_NAME` and `GATEWAY_DATA`.

## A different name

```dotenv
GATEWAY_HOSTNAME=espresso
```

Devices then open `https://espresso.local`. Changing the name later creates a
new certificate authority, and every device has to be set up again.

## Your own DNS instead of mDNS

If your router or Pi-hole already resolves a name to the gateway, turn off
the mDNS announcement and use that name. It must end in `.local` here,
matching `GATEWAY_HOSTNAME`:

```dotenv
MDNS_PUBLISH=false
```

## Run on the server's own address

Use [`host-network.compose.yaml`](host-network.compose.yaml) when the gateway
cannot have its own address. It shares the server's address, so it needs
ports that are still free, and devices open the name with the port, for
example `https://openbrewbyweight-secure.local:8443`.

```bash
cp examples/host-network.compose.yaml compose.yaml
```

Then set free ports in `.env` and start it as usual:

```dotenv
HTTP_PORT=8080
HTTPS_PORT=8443
GATEWAY_IP=
```

With `GATEWAY_IP` empty, the gateway uses the server's main address. The
`LAN_*` settings are not used.
