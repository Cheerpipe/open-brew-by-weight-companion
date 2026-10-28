# Troubleshooting

Start by running the setup again, from the companion's folder. It checks the
running companion step by step, says what is wrong, and asks for what it needs:

```bash
./setup
```

Answer **yes** when it offers to keep your settings. For more detail, read
the companion's own log:

```bash
docker compose logs -f
```

It reports the name it publishes, the controller it found and its address,
certificate renewals, and every device it skipped and why.
`docker compose ps` shows the companion as `healthy` once it serves the setup
page and the secure address and has found a controller.

## `docker compose up` fails with a network error

- **`no configured subnet contains IP address`:** `COMPANION_IP` is outside
  `LAN_SUBNET`. Set both, and `LAN_ROUTER`, to your network's values, run
  `docker compose down` to remove the network created with the old values,
  and start again.
- **`Pool overlaps with other one on this address space`:** another Docker
  network already covers your LAN range, usually a macvlan network another
  container uses. Join it instead; see
  [examples](../examples/README.md#a-lan-network-that-already-exists).

## The setup page says it is looking for the controller

- Check that the controller is on and connected to the same network. The
  companion keeps looking and asks the network again every few minutes.
- Read the log: each `skipping <device>: <reason>` line names a device the
  companion saw and why it did not use it. `no answer yet` means the device did
  not reply in time; `not the controller named in OBBW_CONTROLLER_NAME` means
  the name does not match.
- If you have several controllers, set `OBBW_CONTROLLER_NAME` to the device
  name of the one to use.
- If it is still not found, set `OBBW_CONTROLLER_URL` to the controller's IP
  address, shown in **Admin → Network** of the Web UI. Give the controller a
  fixed address in your router so it does not change.

## `openbrewbyweight-secure.local` does not open

- Open `http://<COMPANION_IP>` instead. If that works, the device cannot open
  `.local` names: on Android update to 12 or newer, or point the name at
  `COMPANION_IP` in your router's DNS and set `COMPANION_MDNS_PUBLISH=false`.
- If the companion's address does not answer either, the container may not be
  on the network. Check `LAN_INTERFACE`, `LAN_SUBNET` and `LAN_ROUTER`, and
  that `COMPANION_IP` is free. Some hypervisors and NAS systems need
  promiscuous mode on the interface for `macvlan`; with a Wi-Fi server use
  `LAN_DRIVER=ipvlan`.
- Opening the companion from the server it runs on does not work by design; use
  another device.

## The browser still warns about the certificate

- On iPhone and iPad, check **Certificate Trust Settings**; installing the
  profile alone is not enough.
- Restart the browser after installing the certificate.
- In Firefox, see [device setup](device-setup.md#firefox).
- If you deleted the `data` folder or changed `COMPANION_HOSTNAME`, the companion
  made a new certificate authority. Remove the old one from the device and
  install the new one from the setup page.

## The Web UI opens but shows the controller as unreachable

The companion is fine but cannot reach the controller. The machine may be off,
or its address changed. The companion follows address changes that the
controller announces; with `OBBW_CONTROLLER_URL` set to an IP address it does
not, so update the setting.

## Ports 80 or 443 are busy

With the default setup they cannot be: the companion has its own address. If
you run it on the server's own address instead, choose free ports; see
[examples](../examples/README.md#run-on-the-servers-own-address).

## After updating from the HTTPS gateway

The companion was called the HTTPS gateway before. `./setup` renames the
settings in `.env` (the earlier file is kept as `.env.bak`) and removes the
old `openbrewbyweight-https-gateway` container, so run it once after
updating. Settings with the earlier names keep working if you start the
companion with `docker compose up -d` instead. If `docker compose up` then
reports `Pool overlaps`, the old container's network is still there: run
`./setup` and choose new settings, and it joins that network.
