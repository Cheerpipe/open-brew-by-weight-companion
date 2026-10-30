#!/usr/bin/env python3
"""Supervisor of Open Brew by Weight Companion and its HTTPS gateway.

Finds the controller over mDNS, publishes the companion's own `.local` name,
keeps a name-constrained local CA and its server certificate current, and runs
nginx as a reverse proxy plus a plain-HTTP setup page. Discovery relies on mDNS
announcements and the browser's own schedule; only when mDNS finds no controller
does it search the companion's own network, once per host, for the controller's
identity route (see fallback()).
"""

import hashlib
import html
import http.client
import ipaddress
import json
import math
import os
import plistlib
import queue
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
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
# Network search, when mDNS finds no controller: the controller's unauthenticated identity route.
SCAN_PATH = "/api/v1/integration/info"
SCAN_TIMEOUT_S = 1
SCAN_WORKERS = 32
SCAN_MAX_PREFIX = 22  # At most 1022 hosts, about 33 s.
SCAN_AFTER_S = (120, 300, 600, 1800)  # Without a controller answering; then every 30 minutes at most.
STORED_TIMEOUT_S = 3  # A single probe of the stored controller may wait out a Wi-Fi power-save beacon.
PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
ROUTES = Path("/proc/net/route")
OPENSSL_CNF = "[req]\ndistinguished_name=dn\n[dn]\n"


def instance_name(value):
    """COMPANION_NAME as the controller accepts it (1 to 32 bytes, no control characters)."""
    name = "".join(c for c in value if c.isprintable()).strip()
    if not name:
        host = socket.gethostname().split(".")[0]
        name = "Companion" if re.fullmatch(r"[0-9a-f]{12}", host) else host  # A container id says nothing.
    return name.encode()[:32].decode(errors="ignore").strip() or "Companion"


def log(message):
    try:
        from companion import gateway_logger
    except ImportError:  # Before the path is set up, or in standalone tests: plain stdout.
        print(f"gateway: {message}", flush=True)
        return
    gateway_logger.info("%s", message)


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
        "log_retention_days": _bounded(env.get("COMPANION_LOG_RETENTION_DAYS"), 1, 3650, 30),
        "log_retention_mb": _bounded(env.get("COMPANION_LOG_RETENTION_MB"), 1, 10240, 50),
    }


def _bounded(value, low, high, default):
    """A positive whole setting within bounds, or the default."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return min(max(parsed, low), high)


def static_controller(cfg):
    """Return the configured controller when its address needs no mDNS lookup."""
    if cfg["controller"] and cfg["controller"][0].replace(".", "").isdigit():
        return cfg["controller"][0], cfg["controller"]
    return None


def wanted(cfg, *names):
    """True without OBBW_CONTROLLER_NAME, or when it is one of these names (a space matches a hyphen)."""
    want = cfg["controller_name"].replace(" ", "-")
    return not want or want in {name.lower().replace(" ", "-") for name in names}


def match_controller(cfg, instance, server, properties, addresses, port):
    """Map one `_http._tcp` service to ((label, (ip, port)), None), or (None, why it was skipped)."""
    host = server.rstrip(".").lower()
    ipv4 = [a for a in addresses if ":" not in a]
    if cfg["controller"]:
        if host != cfg["controller"][0]:
            return None, f"not {cfg['controller'][0]}"
    elif properties.get(b"obbw") != b"1":
        return None, "not an Open Brew by Weight controller"
    elif not wanted(cfg, instance, host.removesuffix(".local")):
        return None, "not the controller named in OBBW_CONTROLLER_NAME"
    if not ipv4:
        return None, "no IPv4 address"
    return (instance, (ipv4[0], port)), None


def controller_identity(body):
    """The controller's /api/v1/integration/info answer as {name, firmware}, or None for anything else."""
    try:
        info = json.loads(body)
    except ValueError:
        return None
    if not (isinstance(info, dict) and type(info.get("apiVersion")) is int and info["apiVersion"] == 1
            and isinstance(info.get("name"), str) and isinstance(info.get("firmwareVersion"), str)
            and isinstance(info.get("authRequired"), bool)):
        return None
    clean = lambda text: "".join(c for c in text if c.isprintable() and not c.isspace())[:48] or "?"
    return {"name": "".join(c for c in info["name"] if c.isprintable()).strip()[:32] or "?",
            "firmware": clean(info["firmwareVersion"])}


def probe_controller(ip, port=80, timeout=SCAN_TIMEOUT_S):
    """One GET of the identity route: {name, firmware, ip, port}, or None. No redirect, proxy or retry."""
    connection = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        connection.request("GET", SCAN_PATH, headers={"Accept": "application/json"})
        reply = connection.getresponse()
        info = controller_identity(reply.read(1024)) if reply.status == 200 else None
    except (OSError, http.client.HTTPException, ValueError):
        return None
    finally:
        connection.close()
    return info and {**info, "ip": ip, "port": port}


def lan_network(ip, routes=ROUTES):
    """The companion's own IPv4 network: the most specific on-link route that holds its address."""
    best, address = None, ipaddress.ip_address(ip)
    try:
        lines = routes.read_text().splitlines()[1:]
    except OSError:
        return None
    for fields in (line.split() for line in lines):
        if len(fields) < 8 or int(fields[2], 16):  # Reached through a router: not this link.
            continue
        destination, mask = (socket.inet_ntoa(struct.pack("=I", int(fields[i], 16))) for i in (1, 7))
        network = ipaddress.ip_network(f"{destination}/{mask}", strict=False)
        if network.prefixlen and address in network and (not best or network.prefixlen > best.prefixlen):
            best = network
    return best


def scan_plan(cfg, routes=ROUTES):
    """(network, hosts to probe, None), or (network or None, [], why the network is not searched)."""
    network = lan_network(cfg["ip"], routes)
    if network is None:
        return None, [], f"no network interface of its own holds {cfg['ip']}"
    if not any(network.subnet_of(private) for private in PRIVATE):
        return network, [], f"{network} is not a private home network"
    if network.prefixlen < SCAN_MAX_PREFIX:  # Docker's own bridges (/16, /20) end here too.
        return network, [], f"{network} is larger than /{SCAN_MAX_PREFIX}"
    return network, [str(host) for host in network.hosts() if str(host) != cfg["ip"]], None


def scan_seconds(hosts):
    return math.ceil(len(hosts) / SCAN_WORKERS) * SCAN_TIMEOUT_S + 1


def scan_hosts(cfg, hosts, probe=probe_controller):
    """Probe each host once, SCAN_WORKERS at a time: the matching controllers, in address order."""
    with ThreadPoolExecutor(SCAN_WORKERS) as pool:
        return [found for found in pool.map(probe, hosts) if found and wanted(cfg, found["name"])]


def scan_target(found):
    return found["name"], (found["ip"], found["port"])


def scan(cfg, data, probe=probe_controller, routes=ROUTES):
    """`gateway.py scan`, for ./setup: one line per step and controller; stores the controller when one answers."""
    if cfg["controller"]:
        print("skip OBBW_CONTROLLER_URL chooses the controller")
        return 1
    network, hosts, why = scan_plan(cfg, routes)
    if why:
        print(f"skip {why}")
        return 1
    print(f"range {network} {len(hosts)} {scan_seconds(hosts)}", flush=True)
    found = scan_hosts(cfg, hosts, probe)
    for controller in found:
        print(f"controller {controller['ip']} {controller['firmware']} {controller['name']}")
    if len(found) == 1:
        remember_controller(cfg, data, scan_target(found[0]), "scan")
    return 0 if found else 1


def fallback(cfg, current, events, stop, probe=probe_controller, routes=ROUTES, delays=SCAN_AFTER_S):
    """Search the network for the controller while mDNS has not found it and none answers.

    Runs on its own thread unless OBBW_CONTROLLER_URL is set. The first search comes delays[0] s
    after start; later ones only when no controller answers, backing off to one per delays[-1] s.
    A controller found by searching is checked with one request per delays[-1] s and searched for
    again only when it stops answering. It ends as soon as mDNS finds the controller.
    """
    backoff, delay = iter(delays[1:]), delays[0]
    while not stop.wait(delay):
        target, source = current()
        if source == "mdns":
            return
        if target and (found := probe(*target[1], timeout=STORED_TIMEOUT_S)) and wanted(cfg, found["name"]):
            events.put(("scanned", [found]))
            delay = delays[-1]
            continue
        network, hosts, why = scan_plan(cfg, routes)
        if why:
            log(f"not searching the network for the controller: {why}")
            return
        started = time.monotonic()
        log((f"the controller at {target[1][0]} does not answer" if target else "mDNS has not found the controller")
            + f"; searching {network} ({len(hosts)} addresses)")
        found = scan_hosts(cfg, hosts, probe)
        if found:
            events.put(("scanned", found))
            backoff, delay = iter(delays[1:]), delays[-1]
        else:
            delay = next(backoff, delays[-1])
            log(f"no controller answered in {network} ({time.monotonic() - started:.0f} s); "
                f"searching again in {delay // 60} minutes")


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
        "VERSION": html.escape(companion_version()),
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


def companion_version():
    """The companion's version for the page footer, read from its package without importing it."""
    sys.path.insert(0, str(HERE.parent))
    from companion import VERSION
    return VERSION


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
    """(controller, source) found last with the same settings, used at start until mDNS confirms it.

    The source is "remembered" for one found over mDNS and "scan" for one found by searching.
    """
    try:
        saved = json.loads((data / CONTROLLER_FILE).read_text())
        if saved["filter"] != controller_filter(cfg):
            return None
        return (saved["name"], (saved["ip"], saved["port"])), "scan" if saved.get("via") == "scan" else "remembered"
    except (OSError, ValueError, KeyError):
        return None


def remember_controller(cfg, data, target, via="mdns"):
    (data / CONTROLLER_FILE).write_text(json.dumps(
        {"name": target[0], "ip": target[1][0], "port": target[1][1], "filter": controller_filter(cfg), "via": via}))


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


def mdns_check(cfg, host="openbrewbyweight.local", wait_s=3):
    """`gateway.py mdns-check [name.local]`: show where mDNS answers about the controller reach this container.

    Prints the interfaces, their flags and multicast groups, then asks for host's address and the
    `_http._tcp` services three ways, printing every packet that arrives and on which interface:
    legacy unicast (from a random port, so the answer comes back unicast), QM from port 5353 (the
    answer goes to the multicast group) and QU from port 5353 (unicast to port 5353, which the running
    companion may receive instead of this check). It changes nothing in the running companion.
    """
    from zeroconf import DNSAddress, DNSIncoming, DNSOutgoing, DNSPointer, DNSQuestion, const

    addresses = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True).stdout.splitlines()
    for line in addresses:
        flags = int((Path("/sys/class/net") / line.split()[1] / "flags").read_text(), 16)
        print(" ".join(line.split()[1:4]), " ".join(f for bit, f in (
            (0x1000, "MULTICAST"), (0x200, "ALLMULTI"), (0x100, "PROMISC")) if flags & bit))
    print("Multicast groups (FB0000E0 is mDNS, 224.0.0.251):\n" + Path("/proc/net/igmp").read_text().rstrip())
    host, group, results = host.rstrip(".").lower() + ".", ("224.0.0.251", 5353), {}
    for label, port, unicast in (("legacy unicast", 0, False), ("QM", 5353, False), ("QU", 5353, True)):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("", port))
            if port:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                socket.inet_aton(group[0]) + socket.inet_aton(cfg["ip"]))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(cfg["ip"]))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
            query = DNSOutgoing(const._FLAGS_QR_QUERY)
            for name, kind in ((host, const._TYPE_A), ("_http._tcp.local.", const._TYPE_PTR)):
                question = DNSQuestion(name, kind, const._CLASS_IN)
                question.unicast = unicast
                query.add_question(question)
            sock.sendto(query.packets()[0], group)
            print(f"\n{label}: asked for {host} and _http._tcp.local. from {cfg['ip']}:{sock.getsockname()[1]}")
            deadline, results[label] = time.monotonic() + wait_s, None
            while (left := deadline - time.monotonic()) > 0:
                sock.settimeout(left)
                try:
                    data, ancillary, _, source = sock.recvmsg(9000, 64)
                except TimeoutError:
                    break
                interface, _, destination = struct.unpack("I4s4s", ancillary[0][2])
                message = DNSIncoming(data, source)
                records = [f"{r.name} A {ipaddress.ip_address(r.address)}" if isinstance(r, DNSAddress) else f"{r.name} PTR {r.alias}" if isinstance(r, DNSPointer)
                           else f"{r.name} {const._TYPES.get(r.type, r.type)}" for r in message.answers()]
                what = "query" if message.is_query() else "; ".join(records) or "empty answer"
                print(f"  {source[0]}:{source[1]} -> {socket.inet_ntoa(destination)} on "
                      f"{socket.if_indextoname(interface)}: {what}")
                if any(r.lower().startswith(host + " a ") for r in records):
                    results[label] = results[label] or f"{source[0]} -> {socket.inet_ntoa(destination)}"
    print("\n" + "\n".join(f"{label}: " + (f"answered ({how})" if how else "no answer about " + host)
                            for label, how in results.items()))
    return 0 if all(results.values()) else 1


def main():
    from zeroconf import (DNSAddress, IPVersion, RecordUpdateListener, ServiceBrowser, ServiceInfo,
                          ServiceStateChange, Zeroconf)

    sys.path.insert(0, str(HERE.parent))
    from companion.service import start as start_companion

    cfg = load_config(os.environ)
    if sys.argv[1:2] == ["check"]:
        raise SystemExit(check(cfg, DATA, "--controller" in sys.argv))
    if sys.argv[1:2] == ["scan"]:
        raise SystemExit(scan(cfg, DATA))
    if sys.argv[1:2] == ["mdns-check"]:
        raise SystemExit(mdns_check(cfg, *sys.argv[2:3]))
    from companion import configure_logging, stop_logging
    configure_logging(DATA)  # The supervisor only: check/scan never share the rotating file.
    target, source = static_controller(cfg), "manual"
    if not target and (saved := remembered_controller(cfg, DATA)):
        target, source = saved
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
    heard, heard_lock = set(), threading.Lock()  # Devices whose mDNS address records reached the companion.

    class Heard(RecordUpdateListener):
        def async_update_records(self, zc, now, records):
            with heard_lock:
                heard.update(r.new.name for r in records if isinstance(r.new, DNSAddress))

    zc.add_listener(Heard(), None)
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
        log(f"using the controller at {target[1][0]}:{target[1][1]} ({source})")
    stop = threading.Event()
    if not cfg["controller"] and (not target or source == "scan"):
        threading.Thread(target=fallback, args=(cfg, lambda: (target, source), events, stop), daemon=True).start()
    retries = iter(RETRY_S)
    status = 0
    unhandled = 0
    try:
        while True:
            searching = browser and source != "mdns"
            try:
                event = events.get(timeout=next(retries, RETRY_S[-1]) if searching else CERT_CHECK_S)
            except queue.Empty:
                event = ("tick",)
            try:
                if event[0] == "tick" and searching:
                    with heard_lock:
                        others = sorted(n.removesuffix(".local.") for n in heard - {cfg["hostname"] + "."})
                    log("no controller confirmed yet; asking the network again (" + (
                        f"mDNS reaches the companion from {len(others)} devices: {', '.join(others[:5])}"
                        if others else f"no mDNS answer from any device has reached {cfg['ip']}") + ")")
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
                elif event[0] == "scanned" and source != "mdns":
                    found = scan_target(event[1][0])
                    for other in event[1][1:]:
                        status_changed |= note(other["name"], True, f"another controller, at {other['ip']}; "
                                                                    "set OBBW_CONTROLLER_NAME to choose")
                    if found != target:
                        remember_controller(cfg, DATA, found, "scan")
                        log(f"controller {found[0]} at {found[1][0]}:{found[1][1]}, found by searching the network "
                            f"(firmware {event[1][0]['firmware']})")
                        note(found[0], True, "in use")
                        site_changed = True
                    status_changed |= source != "scan"
                    target, source = found, "scan"
                elif event[0] == "tick" and ensure_certificates(cfg, DATA):
                    site_changed = True
                if (event[0] == "found" and event[1] == target) or (event[0] == "scanned" and source == "scan"):
                    companion.controller(target)  # Every announcement: reconnect now if the link is down.
                if site_changed:
                    write_site(cfg, DATA, RUN, target)
                    nginx.send_signal(signal.SIGHUP)
                if site_changed or status_changed:
                    write_status(cfg, DATA, RUN, target, source, seen)
                unhandled = 0
            except Exception:
                # One bad event must not end the supervisor; ten in a row is a state a
                # restart clears better than a limp.
                unhandled += 1
                log("an event was not handled:\n" + traceback.format_exc())
                if unhandled >= 10:
                    status = 1
                    break
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        companion.stop()
        zc.close()  # Sends mDNS goodbyes for the published name.
        if nginx.poll() is None:
            nginx.terminate()
            nginx.wait()
        stop_logging()  # Last: the companion's shutdown lines still get written.
    raise SystemExit(status)


if __name__ == "__main__":
    main()
