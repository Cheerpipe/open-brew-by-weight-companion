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

## The Web UI does not show the companion's request

Open the companion's page, `http://openbrewbyweight-secure.local/__companion/`
(or `http://<COMPANION_IP>/__companion/`). It says what happened:

- **Looking for the controller:** the companion has not found it yet; see
  above.
- **The controller did not answer:** the controller is off or unreachable.
  Press **Pair with the controller** once it is back.
- **The request expired** or **was declined:** press **Pair again** and
  approve it within 10 minutes.
- **The controller ignores this companion:** choose **Stop ignoring** in
  Admin → Companion, then pair again.
- **Already paired with a companion:** the controller pairs with one
  companion at a time. Forget the other one in Admin → Companion first.

Pairing needs a controller with a firmware that has **Admin → Companion**.

## Admin does not accept the code

Type the code shown on the companion's page while the request is open. Three
wrong codes decline the request; press **Pair again** on the companion's page
for a new one. If the code on the page and the request in Admin name
different companions, do not approve it.

## The companion says the controller no longer recognizes it

The controller lost its pairing, for example after a factory reset, but the
companion still has it. Press **Pair again** on the companion's page and
approve the request in Admin → Companion; the new pairing replaces the old
one.

## La Marzocco stays on the controller's own connection

The controller switches to the companion only at a quiet moment, never
during a shot, and only while everything below holds. Check the companion's
page:

- **Link** says **Connected**. If it says **Reconnecting**, the reason in
  brackets says why; `RETRY_LATER` means a shot with a scale or a scale
  connection was in progress, and it tries again by itself.
- **La Marzocco** says **Connected**. **Off** means the switch in Admin →
  Companion is off. **Waiting for the account** means the controller has not
  sent it yet: connect the La Marzocco account in the Web UI first.
- The log (`docker compose logs`) says
  `La Marzocco refused the account` when the email or password is wrong.
  Correct them in the Web UI; the companion tries again with the new account
  only, so a wrong password is never retried until your account is locked.

## Start the pairing over

Choose **Forget** in Admin → Companion first. The next time the companion
connects, the controller tells it to erase its pairing and the La Marzocco
account, and it can be paired again with **Pair with the controller**. Deleting
`data/secrets` by hand also works, but then forget the old companion in
Admin as well.

## After updating from the HTTPS gateway

The companion was called the HTTPS gateway before. `./setup` renames the
settings in `.env` (the earlier file is kept as `.env.bak`) and removes the
old `openbrewbyweight-https-gateway` container, so run it once after
updating. Settings with the earlier names keep working if you start the
companion with `docker compose up -d` instead. If `docker compose up` then
reports `Pool overlaps`, the old container's network is still there: run
`./setup` and choose new settings, and it joins that network.
