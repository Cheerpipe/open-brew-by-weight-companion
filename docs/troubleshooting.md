# Troubleshooting

Start by running the setup again, from the gateway's folder. It checks the
running gateway step by step, says what is wrong, and asks for what it needs:

```bash
./setup
```

Answer **yes** when it offers to keep your settings. For more detail, read
the gateway's own log:

```bash
docker compose logs -f
```

It reports the name it publishes, the controller it found and its address,
certificate renewals, and every device it skipped and why.
`docker compose ps` shows the gateway as `healthy` once it serves the setup
page and the secure address and has found a controller.

## `docker compose up` fails with a network error

- **`no configured subnet contains IP address`:** `GATEWAY_IP` is outside
  `LAN_SUBNET`. Set both, and `LAN_ROUTER`, to your network's values, run
  `docker compose down` to remove the network created with the old values,
  and start again.
- **`Pool overlaps with other one on this address space`:** another Docker
  network already covers your LAN range, usually a macvlan network another
  container uses. Join it instead; see
  [examples](../examples/README.md#a-lan-network-that-already-exists).

## The setup page says it is looking for the controller

- Check that the controller is on and connected to the same network. The
  gateway keeps looking and asks the network again every few minutes.
- Read the log: each `skipping <device>: <reason>` line names a device the
  gateway saw and why it did not use it. `no answer yet` means the device did
  not reply in time; `not the controller named in OBBW_CONTROLLER_NAME` means
  the name does not match.
- If you have several controllers, set `OBBW_CONTROLLER_NAME` to the device
  name of the one to use.
- If it is still not found, set `OBBW_CONTROLLER_URL` to the controller's IP
  address, shown in **Admin → Network** of the Web UI. Give the controller a
  fixed address in your router so it does not change.

## `openbrewbyweight-secure.local` does not open

- Open `http://<GATEWAY_IP>` instead. If that works, the device cannot open
  `.local` names: on Android update to 12 or newer, or point the name at
  `GATEWAY_IP` in your router's DNS and set `MDNS_PUBLISH=false`.
- If the gateway's address does not answer either, the container may not be
  on the network. Check `LAN_INTERFACE`, `LAN_SUBNET` and `LAN_ROUTER`, and
  that `GATEWAY_IP` is free. Some hypervisors and NAS systems need
  promiscuous mode on the interface for `macvlan`; with a Wi-Fi server use
  `LAN_DRIVER=ipvlan`.
- Opening the gateway from the server it runs on does not work by design; use
  another device.

## The browser still warns about the certificate

- On iPhone and iPad, check **Certificate Trust Settings**; installing the
  profile alone is not enough.
- Restart the browser after installing the certificate.
- In Firefox, see [device setup](device-setup.md#firefox).
- If you deleted the `data` folder or changed `GATEWAY_HOSTNAME`, the gateway
  made a new certificate authority. Remove the old one from the device and
  install the new one from the setup page.

## The Web UI opens but shows the controller as unreachable

The gateway is fine but cannot reach the controller. The machine may be off,
or its address changed. The gateway follows address changes that the
controller announces; with `OBBW_CONTROLLER_URL` set to an IP address it does
not, so update the setting.

## Ports 80 or 443 are busy

With the default setup they cannot be: the gateway has its own address. If
you run it on the server's own address instead, choose free ports; see
[examples](../examples/README.md#run-on-the-servers-own-address).
