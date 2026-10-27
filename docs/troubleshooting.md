# Troubleshooting

Start with the gateway's own log, from its folder:

```bash
docker compose logs -f
```

It reports the name it publishes, the controller it found and its address,
certificate renewals, and anything it ignored.

## The setup page says it is looking for the controller

- Check that the controller is on and connected to the same network.
- If you have several controllers, set `OBBW_CONTROLLER_NAME` to the device
  name of the one to use. The log names each controller it ignores.
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
