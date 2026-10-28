#!/usr/bin/env python3
"""Supervisor of Open Brew by Weight Companion and its HTTPS gateway.

Finds the controller over mDNS, publishes the companion's own `.local` name,
keeps a name-constrained local CA and its server certificate current, and runs
nginx as a reverse proxy plus a plain-HTTP setup page. The controller is never
polled: discovery relies on mDNS announcements and the browser's own schedule.
"""

import hashlib
import html
import json
import os
import plistlib
import queue
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
# Settings are COMPANION_<name>; the HTTPS gateway's earlier names still work.
LEGACY = {"HOSTNAME": "GATEWAY_HOSTNAME", "IP": "GATEWAY_IP", "HTTP_PORT": "HTTP_PORT",
          "HTTPS_PORT": "HTTPS_PORT", "MDNS_PUBLISH": "MDNS_PUBLISH",
          "DATA_DIR": "GATEWAY_DATA_DIR", "RUN_DIR": "GATEWAY_RUN_DIR"}


def setting(env, name):
    return (env.get("COMPANION_" + name) or env.get(LEGACY.get(name, ""), "") or "").strip()


DATA = Path(setting(os.environ, "DATA_DIR") or "/data")
RUN = Path(setting(os.environ, "RUN_DIR") or "/run/gateway")
HTTP_SERVICE = "_http._tcp.local."
CA_NAME = "openbrewbyweight-ca"
LEAF_DAYS = 397  # Apple rejects TLS server certificates valid for more than 398 days.
RENEW_BEFORE_S = 30 * 86400
CERT_CHECK_S = 12 * 3600
INFO_TIMEOUT_MS = 10000  # A controller in Wi-Fi power save can answer late.
RETRY_S = (30, 60, 120, 300, 600)  # Fresh mDNS queries only while no controller is confirmed.
CONTROLLER_FILE = "controller.json"
OPENSSL_CNF = "[req]\ndistinguished_name=dn\n[dn]\n"


def instance_name(value):
    """COMPANION_NAME as the controller accepts it (1 to 32 bytes, no control characters)."""
    name = "".join(c for c in value if c.isprintable()).strip()
    if not name:
        host = socket.gethostname().split(".")[0]
        name = "Companion" if re.fullmatch(r"[0-9a-f]{12}", host) else host  # A container id says nothing.
    return name.encode()[:32].decode(errors="ignore").strip() or "Companion"


def log(message):
    print(f"gateway: {message}", flush=True)


def local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))  # UDP connect sends nothing; it only picks the default-route address.
        return probe.getsockname()[0]


def enabled(value):
    return value.strip().lower() not in {"0", "false", "no", "off"}


def load_config(env):
    host = (setting(env, "HOSTNAME") or "openbrewbyweight-secure").lower().rstrip(".")
    controller = None
    if url := (env.get("OBBW_CONTROLLER_URL") or "").strip():
        parts = urlsplit(url if "://" in url else "http://" + url)
        if parts.scheme != "http" or not parts.hostname:
            raise SystemExit("OBBW_CONTROLLER_URL must look like http://192.168.1.50 or http://name.local")
        controller = (parts.hostname.lower(), parts.port or 80)
    return {
        "name": instance_name(env.get("COMPANION_NAME") or ""),
        "hostname": host.removesuffix(".local") + ".local",
        "ip": setting(env, "IP") or local_ip(),
        "http_port": int(setting(env, "HTTP_PORT") or 80),
        "https_port": int(setting(env, "HTTPS_PORT") or 443),
        "controller": controller,
        "controller_name": (env.get("OBBW_CONTROLLER_NAME") or "").strip().lower(),
        "mdns_publish": enabled(setting(env, "MDNS_PUBLISH") or "true"),
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


def upstream(target):
    return target[1][0] + ("" if target[1][1] == 80 else f":{target[1][1]}") if target else "127.0.0.1:9"


def qr_svg(text):
    try:
        return subprocess.run(["qrencode", "-t", "SVG", "--inline", "-m", "1", "-o", "-", text],
                              capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        log(f"setup page shows no QR code: {error}")
        return ""


def write_site(cfg, data, run, target):
    """Render nginx.conf and the setup page, in every language, for the current controller."""
    www = run / "www"
    www.mkdir(parents=True, exist_ok=True)
    www.chmod(0o755)
    ca_pem = (data / f"{CA_NAME}.crt").read_text()
    ca_der = ssl.PEM_cert_to_DER_cert(ca_pem)
    fingerprint = hashlib.sha256(ca_der).hexdigest().upper()
    setup = site_url("http", cfg, cfg["http_port"], 80)
    values = {
        "SECURE_URL": html.escape(site_url("https", cfg, cfg["https_port"], 443)),
        "NAME": html.escape(cfg["name"]),
        "HOSTNAME": html.escape(cfg["hostname"]),
        "CA_NAME": CA_NAME,
        "FINGERPRINT": ":".join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2)),
        "QR": qr_svg(setup),
        "QR_IOS": qr_svg(f"{setup}/{CA_NAME}.mobileconfig"),
        "QR_ANDROID": qr_svg(f"{setup}/{CA_NAME}.crt"),
    }
    files = {f"{CA_NAME}.crt": ca_pem.encode(), f"{CA_NAME}.mobileconfig": mobileconfig(ca_der, cfg["hostname"])}
    for lang, strings in json.loads((HERE / "strings.json").read_text()).items():
        controller = strings["found"].format(name=target[0], address=upstream(target)) if target else strings["looking"]
        page = fill((HERE / "setup.html").read_text(), {
            "T_" + key.upper(): "".join(f"<li>{item}</li>" for item in text) if isinstance(text, list) else text
            for key, text in strings.items()})
        files[f"index.{lang}.html"] = fill(page, {**values, "CONTROLLER": html.escape(controller)}).encode()
    for name, content in files.items():
        (www / name).write_bytes(content)
        (www / name).chmod(0o644)
    (run / "nginx.conf").write_text(fill((HERE / "nginx.conf.in").read_text(), {
        "RUN": run, "DATA": data, "HTTP_PORT": cfg["http_port"], "HTTPS_PORT": cfg["https_port"],
        "UPSTREAM": upstream(target), "OFFLINE": "" if target else "return 503;",
    }))


def write_status(cfg, data, run, target, source, seen):
    """Publish the gateway's state at /__companion/gateway for ./setup, health checks and monitoring."""
    expires = openssl("x509", "-in", str(data / "server.crt"), "-noout", "-enddate").strip().split("=", 1)[1]
    status = {
        "name": cfg["name"], "hostname": cfg["hostname"], "ip": cfg["ip"], "mdns_publish": cfg["mdns_publish"],
        "setup_url": site_url("http", cfg, cfg["http_port"], 80),
        "secure_url": site_url("https", cfg, cfg["https_port"], 443),
        "controller": {"name": target[0], "ip": target[1][0], "port": target[1][1], "source": source}
        if target else None,
        "seen": seen, "certificate_expires": expires,
    }
    temporary = run / "status.json.tmp"
    temporary.write_text(json.dumps(status, indent=2))
    temporary.chmod(0o644)
    temporary.replace(run / "status.json")


def controller_filter(cfg):
    return f"{cfg['controller']}|{cfg['controller_name']}"


def remembered_controller(cfg, data):
    """Controller last found over mDNS with the same settings, used at start until mDNS confirms it."""
    try:
        saved = json.loads((data / CONTROLLER_FILE).read_text())
        return (saved["name"], (saved["ip"], saved["port"])) if saved["filter"] == controller_filter(cfg) else None
    except (OSError, ValueError, KeyError):
        return None


def remember_controller(cfg, data, target):
    (data / CONTROLLER_FILE).write_text(json.dumps(
        {"name": target[0], "ip": target[1][0], "port": target[1][1], "filter": controller_filter(cfg)}))


def https_get(cfg, data, path):
    """GET path through the gateway's own HTTPS server, verifying it against the gateway CA."""
    context = ssl.create_default_context(cafile=str(data / f"{CA_NAME}.crt"))
    with socket.create_connection(("127.0.0.1", cfg["https_port"]), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname=cfg["hostname"]) as tls:
            tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {cfg['hostname']}\r\nConnection: close\r\n\r\n".encode())
            return int(tls.recv(64).split()[1])


def check(cfg, data, through_controller):
    """Probe the running gateway from inside its container: one line per finding, exit 1 on a problem.

    Without --controller nothing reaches the controller, so Docker health checks add no Wi-Fi traffic.
    """
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{cfg['http_port']}/__companion/gateway", timeout=5) as reply:
            status = json.load(reply)
        print("ok setup-page")
        print(f"ok https {https_get(cfg, data, '/__companion/ping')}")
        with urllib.request.urlopen(f"http://127.0.0.1:{cfg['http_port']}/__companion/status", timeout=5) as reply:
            print(f"ok companion link {json.load(reply)['link']}")
    except (OSError, ValueError, IndexError) as error:
        print(f"fail gateway {error}")
        return 1
    for name, seen in status["seen"].items():
        print(f"seen {'controller' if seen['controller'] else 'other'} {name}: {seen['note']}")
    controller = status["controller"]
    if not controller:
        print("fail controller not found yet")
        return 1
    print(f"ok controller {controller['name']} {controller['ip']}:{controller['port']} {controller['source']}")
    if through_controller:
        try:
            code = https_get(cfg, data, "/")
        except (OSError, ValueError, IndexError) as error:
            code = error
        print(f"{'ok' if code in range(200, 400) else 'fail'} web-ui {code}")
        return 0 if code in range(200, 400) else 1
    return 0


def main():
    from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, ServiceStateChange, Zeroconf

    sys.path.insert(0, str(HERE.parent))
    from companion.service import start as start_companion

    cfg = load_config(os.environ)
    if sys.argv[1:2] == ["check"]:
        raise SystemExit(check(cfg, DATA, "--controller" in sys.argv))
    target, source = static_controller(cfg), "manual"
    if not target and (target := remembered_controller(cfg, DATA)):
        source = "remembered"
    ensure_certificates(cfg, DATA)
    write_site(cfg, DATA, RUN, target)
    seen = {}
    write_status(cfg, DATA, RUN, target, source, seen)
    nginx = subprocess.Popen(["nginx", "-c", str(RUN / "nginx.conf"), "-g", "daemon off;"])
    events = queue.Queue()
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    threading.Thread(target=lambda: (nginx.wait(), events.put(("nginx",))), daemon=True).start()
    companion = start_companion(cfg, DATA, RUN, lambda: events.put(("companion",)))
    companion.controller(target)

    zc = Zeroconf(interfaces=[cfg["ip"]], ip_version=IPVersion.V4Only)
    if cfg["mdns_publish"]:
        zc.register_service(ServiceInfo(
            "_https._tcp.local.", f"{cfg['hostname'].removesuffix('.local')}._https._tcp.local.",
            addresses=[socket.inet_aton(cfg["ip"])], port=cfg["https_port"],
            server=cfg["hostname"] + ".", properties={"path": "/"}), allow_name_change=True)
        log(f"publishing {cfg['hostname']} at {cfg['ip']}")

    def on_change(zeroconf, service_type, name, state_change):
        if state_change is ServiceStateChange.Removed:
            return  # Keep the last address; a restarting controller announces itself again.
        instance = name.removesuffix("." + service_type)
        info = zeroconf.get_service_info(service_type, name, timeout=INFO_TIMEOUT_MS)
        found, reason = match_controller(
            cfg, instance, info.server, info.properties, info.parsed_addresses(IPVersion.V4Only),
            info.port) if info and info.server else (None, "no answer yet")
        is_controller = bool(info and info.properties.get(b"obbw") == b"1")
        events.put(("found", found) if found else ("skip", instance, is_controller, reason))

    def note(instance, is_controller, reason):
        """Record what discovery made of a device; return True when that changed."""
        if seen.get(instance) == {"controller": is_controller, "note": reason}:
            return False
        seen[instance] = {"controller": is_controller, "note": reason}
        return True

    browser = None
    if source != "manual" or not target:
        browser = ServiceBrowser(zc, HTTP_SERVICE, handlers=[on_change])
        log("looking for " + (cfg["controller"][0] if cfg["controller"] else "the controller") + " over mDNS")
    if target:
        log(f"using the {source} controller at {target[1][0]}:{target[1][1]}")
    retries = iter(RETRY_S)
    status = 0
    try:
        while True:
            searching = browser and source != "mdns"
            try:
                event = events.get(timeout=next(retries, RETRY_S[-1]) if searching else CERT_CHECK_S)
            except queue.Empty:
                event = ("tick",)
                if searching:
                    log("no controller confirmed yet; asking the network again")
                    browser.cancel()
                    browser = ServiceBrowser(zc, HTTP_SERVICE, handlers=[on_change])
            site_changed = status_changed = False
            if event[0] == "nginx":
                log(f"nginx exited with status {nginx.returncode}")
                status = 1
                break
            if event[0] == "companion":
                log("the companion service stopped")
                status = 1
                break
            if event[0] == "skip" and note(*event[1:]):
                log(f"skipping {event[1]}: {event[3]}")
                status_changed = True
            elif event[0] == "found" and source == "mdns" and event[1][0] != target[0] \
                    and not cfg["controller_name"]:
                reason = "another controller; set OBBW_CONTROLLER_NAME to choose"
                if note(event[1][0], True, reason):
                    log(f"ignoring {event[1][0]}: {reason}")
                    status_changed = True
            elif event[0] == "found" and (event[1], "mdns") != (target, source):
                target, source = event[1], "mdns"
                note(target[0], True, "in use")
                remember_controller(cfg, DATA, target)
                log(f"controller {target[0]} at {target[1][0]}:{target[1][1]}")
                site_changed = True
            elif event[0] == "tick" and ensure_certificates(cfg, DATA):
                site_changed = True
            if event[0] == "found" and event[1] == target:
                companion.controller(target)  # Every announcement: reconnect now if the link is down.
            if site_changed:
                write_site(cfg, DATA, RUN, target)
                nginx.send_signal(signal.SIGHUP)
            if site_changed or status_changed:
                write_status(cfg, DATA, RUN, target, source, seen)
    except KeyboardInterrupt:
        pass
    finally:
        companion.stop()
        zc.close()  # Sends mDNS goodbyes for the published name.
        if nginx.poll() is None:
            nginx.terminate()
            nginx.wait()
    raise SystemExit(status)


if __name__ == "__main__":
    main()
