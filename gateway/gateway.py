#!/usr/bin/env python3
"""HTTPS gateway for the Open Brew by Weight Web UI.

Finds the controller over mDNS, publishes the gateway's own `.local` name,
keeps a name-constrained local CA and its server certificate current, and runs
nginx as a reverse proxy plus a plain-HTTP setup page. The controller is never
polled: discovery relies on mDNS announcements and the browser's own schedule.
"""

import hashlib
import html
import os
import plistlib
import queue
import signal
import socket
import ssl
import subprocess
import threading
import uuid
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("GATEWAY_DATA_DIR", "/data"))
RUN = Path(os.environ.get("GATEWAY_RUN_DIR", "/run/gateway"))
HTTP_SERVICE = "_http._tcp.local."
CA_NAME = "openbrewbyweight-ca"
LEAF_DAYS = 397  # Apple rejects TLS server certificates valid for more than 398 days.
RENEW_BEFORE_S = 30 * 86400
CERT_CHECK_S = 12 * 3600
INFO_TIMEOUT_MS = 10000  # A controller in Wi-Fi power save can answer late.
RETRY_S = (30, 60, 120, 300, 600)  # Fresh mDNS queries only while no controller is known.
OPENSSL_CNF = "[req]\ndistinguished_name=dn\n[dn]\n"


def log(message):
    print(f"gateway: {message}", flush=True)


def local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))  # UDP connect sends nothing; it only picks the default-route address.
        return probe.getsockname()[0]


def enabled(value):
    return value.strip().lower() not in {"0", "false", "no", "off"}


def load_config(env):
    host = (env.get("GATEWAY_HOSTNAME") or "openbrewbyweight-secure").strip().lower().rstrip(".")
    controller = None
    if url := (env.get("OBBW_CONTROLLER_URL") or "").strip():
        parts = urlsplit(url if "://" in url else "http://" + url)
        if parts.scheme != "http" or not parts.hostname:
            raise SystemExit("OBBW_CONTROLLER_URL must look like http://192.168.1.50 or http://name.local")
        controller = (parts.hostname.lower(), parts.port or 80)
    return {
        "hostname": host.removesuffix(".local") + ".local",
        "ip": (env.get("GATEWAY_IP") or "").strip() or local_ip(),
        "http_port": int(env.get("HTTP_PORT") or 80),
        "https_port": int(env.get("HTTPS_PORT") or 443),
        "controller": controller,
        "controller_name": (env.get("OBBW_CONTROLLER_NAME") or "").strip().lower(),
        "mdns_publish": enabled(env.get("MDNS_PUBLISH") or "true"),
    }


def static_controller(cfg):
    """Return the configured controller when its address needs no mDNS lookup."""
    if cfg["controller"] and cfg["controller"][0].replace(".", "").isdigit():
        return cfg["controller"][0], cfg["controller"]
    return None


def match_controller(cfg, instance, server, properties, addresses, port):
    """Map one `_http._tcp` service to ((label, (ip, port)), None), or (None, why it was skipped)."""
    host = server.rstrip(".").lower()
    ipv4 = [a for a in addresses if ":" not in a]
    wanted = cfg["controller_name"]
    names = {instance.lower(), instance.lower().replace(" ", "-"), host.removesuffix(".local")}
    if cfg["controller"]:
        if host != cfg["controller"][0]:
            return None, f"not {cfg['controller'][0]}"
    elif properties.get(b"obbw") != b"1":
        return None, "not an Open Brew by Weight controller"
    elif wanted and wanted not in names and wanted.replace(" ", "-") not in names:
        return None, "not the controller named in OBBW_CONTROLLER_NAME"
    if not ipv4:
        return None, "no IPv4 address"
    return (instance, (ipv4[0], port)), None


def openssl(*args):
    result = subprocess.run(["openssl", *args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"openssl {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def ensure_certificates(cfg, data):
    """Create or renew the CA and server certificate; return True when files changed."""
    host, ca, ca_key = cfg["hostname"], data / f"{CA_NAME}.crt", data / f"{CA_NAME}.key"
    leaf, leaf_key, cnf = data / "server.crt", data / "server.key", data / "openssl.cnf"
    data.mkdir(parents=True, exist_ok=True)
    cnf.write_text(OPENSSL_CNF)
    base = ["-config", str(cnf), "-x509", "-new", "-noenc", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"]
    changed = False
    if not ca.exists() or f"DNS:{host}" not in openssl("x509", "-in", str(ca), "-noout", "-ext", "nameConstraints"):
        if ca.exists():
            log(f"the CA does not cover {host}; creating a new one, so every device must be set up again")
        openssl("req", *base, "-keyout", str(ca_key), "-out", str(ca), "-days", "3650",
                "-subj", f"/CN=Open Brew by Weight local CA ({host})",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", f"nameConstraints=critical,permitted;DNS:{host}")
        changed = True
    try:
        valid = not changed and leaf.exists() and bool(
            openssl("verify", "-CAfile", str(ca), "-verify_hostname", host, str(leaf))) and bool(
            openssl("x509", "-in", str(leaf), "-noout", "-checkend", str(RENEW_BEFORE_S)))
    except RuntimeError:
        valid = False
    if not valid:
        openssl("req", *base, "-keyout", str(leaf_key), "-out", str(leaf), "-days", str(LEAF_DAYS),
                "-subj", f"/CN={host}", "-CA", str(ca), "-CAkey", str(ca_key),
                "-addext", f"subjectAltName=DNS:{host}",
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "keyUsage=critical,digitalSignature",
                "-addext", "extendedKeyUsage=serverAuth")
        log(f"issued the server certificate for {host}")
        changed = True
    for key in (ca_key, leaf_key):
        key.chmod(0o600)
    return changed


def mobileconfig(ca_der, host):
    """Apple configuration profile that installs the CA as a trusted root."""
    digest = hashlib.sha256(ca_der).hexdigest()
    ident = f"org.openbrewbyweight.gateway.{host}"
    return plistlib.dumps({
        "PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": ident,
        "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, digest)).upper(),
        "PayloadDisplayName": "Open Brew by Weight secure access",
        "PayloadDescription": f"Lets this device open https://{host} without warnings.",
        "PayloadContent": [{
            "PayloadType": "com.apple.security.root", "PayloadVersion": 1,
            "PayloadIdentifier": ident + ".ca",
            "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, digest + ".ca")).upper(),
            "PayloadDisplayName": "Open Brew by Weight local CA",
            "PayloadCertificateFileName": f"{CA_NAME}.cer",
            "PayloadContent": ca_der,
        }],
    })


def fill(template, values):
    for key, value in values.items():
        template = template.replace(f"@{key}@", str(value))
    return template


def site_url(scheme, cfg, port, default):
    return f"{scheme}://{cfg['hostname']}" + ("" if port == default else f":{port}")


def write_site(cfg, data, run, target):
    """Render nginx.conf and the setup page for the current controller address."""
    www = run / "www"
    www.mkdir(parents=True, exist_ok=True)
    www.chmod(0o755)
    ca_pem = (data / f"{CA_NAME}.crt").read_text()
    ca_der = ssl.PEM_cert_to_DER_cert(ca_pem)
    secure = site_url("https", cfg, cfg["https_port"], 443)
    upstream = target[1][0] + ("" if target[1][1] == 80 else f":{target[1][1]}") if target else "127.0.0.1:9"
    fingerprint = hashlib.sha256(ca_der).hexdigest().upper()
    files = {
        f"{CA_NAME}.crt": ca_pem.encode(),
        f"{CA_NAME}.mobileconfig": mobileconfig(ca_der, cfg["hostname"]),
        "index.html": fill((HERE / "setup.html").read_text(), {
            "SECURE_URL": html.escape(secure),
            "HOSTNAME": html.escape(cfg["hostname"]),
            "CA_NAME": CA_NAME,
            "FINGERPRINT": ":".join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2)),
            "CONTROLLER": html.escape(f"Found {target[0]} at {upstream}" if target
                                      else "Looking for the controller on your network…"),
        }).encode(),
    }
    for name, content in files.items():
        (www / name).write_bytes(content)
        (www / name).chmod(0o644)
    (run / "nginx.conf").write_text(fill((HERE / "nginx.conf.in").read_text(), {
        "RUN": run, "DATA": data, "HTTP_PORT": cfg["http_port"], "HTTPS_PORT": cfg["https_port"],
        "UPSTREAM": upstream, "OFFLINE": "" if target else "return 503;",
    }))


def main():
    from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, ServiceStateChange, Zeroconf

    cfg = load_config(os.environ)
    target = static_controller(cfg)
    ensure_certificates(cfg, DATA)
    write_site(cfg, DATA, RUN, target)
    nginx = subprocess.Popen(["nginx", "-c", str(RUN / "nginx.conf"), "-g", "daemon off;"])
    events = queue.Queue()
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    threading.Thread(target=lambda: (nginx.wait(), events.put("nginx")), daemon=True).start()

    zc = Zeroconf(interfaces=[cfg["ip"]], ip_version=IPVersion.V4Only)
    if cfg["mdns_publish"]:
        zc.register_service(ServiceInfo(
            "_https._tcp.local.", f"{cfg['hostname'].removesuffix('.local')}._https._tcp.local.",
            addresses=[socket.inet_aton(cfg["ip"])], port=cfg["https_port"],
            server=cfg["hostname"] + ".", properties={"path": "/"}), allow_name_change=True)
        log(f"publishing {cfg['hostname']} at {cfg['ip']}")

    reported = {}  # Last reason logged per service, so repeated announcements stay quiet.

    def report(key, message):
        if reported.get(key) != message:
            reported[key] = message
            log(message)

    def on_change(zeroconf, service_type, name, state_change):
        if state_change is ServiceStateChange.Removed:
            return  # Keep the last address; a restarting controller announces itself again.
        instance = name.removesuffix("." + service_type)
        info = zeroconf.get_service_info(service_type, name, timeout=INFO_TIMEOUT_MS)
        found, reason = match_controller(
            cfg, instance, info.server, info.properties, info.parsed_addresses(IPVersion.V4Only),
            info.port) if info and info.server else (None, "no answer yet")
        if found:
            events.put(found)
        else:
            report(name, f"skipping {instance}: {reason}")

    browser = None
    if not target:
        browser = ServiceBrowser(zc, HTTP_SERVICE, handlers=[on_change])
        log("looking for " + (cfg["controller"][0] if cfg["controller"] else "the controller") + " over mDNS")
    else:
        log(f"using the controller at {target[1][0]}:{target[1][1]}")
    retries = iter(RETRY_S)
    status = 0
    try:
        while True:
            searching = browser and not target
            try:
                event = events.get(timeout=next(retries, RETRY_S[-1]) if searching else CERT_CHECK_S)
            except queue.Empty:
                event = None
                if searching:
                    log("no controller found yet; asking the network again")
                    browser.cancel()
                    browser = ServiceBrowser(zc, HTTP_SERVICE, handlers=[on_change])
            if event == "nginx":
                log(f"nginx exited with status {nginx.returncode}")
                status = 1
                break
            if event and target and event[0] != target[0] and not cfg["controller_name"]:
                report(event[0], f"ignoring another controller, {event[0]}; set OBBW_CONTROLLER_NAME to choose")
                continue
            if (event and event != target) or (event is None and ensure_certificates(cfg, DATA)):
                if event:
                    target = event
                    log(f"controller {target[0]} at {target[1][0]}:{target[1][1]}")
                write_site(cfg, DATA, RUN, target)
                nginx.send_signal(signal.SIGHUP)
    except KeyboardInterrupt:
        pass
    finally:
        zc.close()  # Sends mDNS goodbyes for the published name.
        if nginx.poll() is None:
            nginx.terminate()
            nginx.wait()
    raise SystemExit(status)


if __name__ == "__main__":
    main()
