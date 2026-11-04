"""Supervisor of Open Brew by Weight Companion and its HTTPS gateway.

Finds the controller over mDNS, publishes the companion's own `.local` name,
keeps a name-constrained local CA and its server certificate current, and keeps
the configuration of nginx (a reverse proxy plus a plain-HTTP setup page, run
beside it by gateway/entrypoint.sh) current. Discovery relies on mDNS
announcements and the browser's own schedule; only when mDNS finds no controller
does it search the companion's own network, once per host, for the controller's
identity route (see fallback()).
"""

import datetime as dt
import hashlib
import html
import http.client
import ipaddress
import json
import logging
import math
import os
import plistlib
import queue
import re
import signal
import socket
import ssl
import struct
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, TypedDict, cast, override
from urllib.parse import urlsplit

import ifaddr
import segno
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from zeroconf import Error as ZeroconfError
from zeroconf import (
    IPVersion,
    RecordUpdate,
    RecordUpdateListener,
    ServiceBrowser,
    ServiceInfo,
    ServiceStateChange,
    Zeroconf,
    const,
)
from zeroconf._dns import DNSAddress, DNSPointer, DNSQuestion
from zeroconf._protocol.incoming import DNSIncoming
from zeroconf._protocol.outgoing import DNSOutgoing

# The image runs this file as /opt/gateway/gateway.py; the companion package sits beside it.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from companion import VERSION, configure_logging, stop_logging
from companion.service import start as start_companion

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence

# Under the companion's "obbw" logger, so its persistent log carries the supervisor's lines too.
logger = logging.getLogger("obbw.gateway")

HERE = Path(__file__).resolve().parent
# Settings are COMPANION_<name>; the HTTPS gateway's earlier names still work.
LEGACY = {
    "HOSTNAME": "GATEWAY_HOSTNAME",
    "IP": "GATEWAY_IP",
    "HTTP_PORT": "HTTP_PORT",
    "HTTPS_PORT": "HTTPS_PORT",
    "MDNS_PUBLISH": "MDNS_PUBLISH",
    "DATA_DIR": "GATEWAY_DATA_DIR",
    "RUN_DIR": "GATEWAY_RUN_DIR",
}


def setting(env: Mapping[str, str], name: str) -> str:
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
DISCOVERY_MAX = 256  # Devices remembered from discovery; announcements are unauthenticated.
SCAN_TIMEOUT_S = 1
SCAN_WORKERS = 32
SCAN_MAX_PREFIX = 22  # At most 1022 hosts, about 33 s.
SCAN_AFTER_S = (
    120,
    300,
    600,
    1800,
)  # Without a controller answering; then every 30 minutes at most.
STORED_TIMEOUT_S = (
    3  # A single probe of the stored controller may wait out a Wi-Fi power-save beacon.
)
PRIVATE = tuple(ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
ROUTES = Path("/proc/net/route")

type Address = tuple[str, int]
type Target = tuple[str, Address]  # (name, (ip, port))


class Config(TypedDict):
    name: str
    hostname: str
    ip: str
    http_port: int
    https_port: int
    controller: Address | None
    controller_name: str
    mdns_publish: bool
    log_retention_days: int
    log_retention_mb: int


class Identity(TypedDict):
    name: str
    firmware: str


class Found(TypedDict):
    name: str
    firmware: str
    ip: str
    port: int


class Probe(Protocol):
    def __call__(
        self, ip: str, port: int = 80, timeout: float = SCAN_TIMEOUT_S
    ) -> Found | None: ...


class Seen(TypedDict):
    controller: bool
    note: str


class ControllerStatus(TypedDict):
    name: str
    ip: str
    port: int
    source: str


class Status(TypedDict):
    """status.json, as write_status publishes it and check reads it."""

    name: str
    hostname: str
    ip: str
    mdns_publish: bool
    setup_url: str
    secure_url: str
    controller: ControllerStatus | None
    seen: dict[str, Seen]
    certificate_expires: str


class CompanionStatus(TypedDict):
    link: str


type Event = (
    tuple[Literal["tick", "companion"]]
    | tuple[Literal["found"], Target]
    | tuple[Literal["skip"], str, bool, str]
    | tuple[Literal["scanned"], list[Found]]
    | tuple[Literal["proved"], bool, tuple[str, int], Event]
)


def instance_name(value: str) -> str:
    """COMPANION_NAME as the controller accepts it (1 to 32 bytes, no control characters)."""
    name = "".join(c for c in value if c.isprintable()).strip()
    if not name:
        host = socket.gethostname().split(".")[0]
        name = (
            "Companion" if re.fullmatch(r"[0-9a-f]{12}", host) else host
        )  # A container id says nothing.
    return name.encode()[:32].decode(errors="ignore").strip() or "Companion"


def log(message: str) -> None:
    logger.info("%s", message)


def local_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(
            ("192.0.2.1", 9)
        )  # UDP connect sends nothing; it only picks the default-route address.
        address: str = probe.getsockname()[0]  # (host, port) for AF_INET
        return address


def enabled(value: str) -> bool:
    return value.strip().lower() not in {"0", "false", "no", "off"}


def load_config(env: Mapping[str, str]) -> Config:
    host = (setting(env, "HOSTNAME") or "openbrewbyweight-secure").lower().rstrip(".")
    controller = None
    if url := (env.get("OBBW_CONTROLLER_URL") or "").strip():
        parts = urlsplit(url if "://" in url else "http://" + url)
        if parts.scheme != "http" or not parts.hostname:
            raise SystemExit(
                "OBBW_CONTROLLER_URL must look like http://192.168.1.50 or http://name.local"
            )
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


def _bounded(value: str | None, low: int, high: int, default: int) -> int:
    """A positive whole setting within bounds, or the default."""
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return min(max(parsed, low), high)


def static_controller(cfg: Config) -> Target | None:
    """Return the configured controller when its address needs no mDNS lookup."""
    if cfg["controller"] and cfg["controller"][0].replace(".", "").isdigit():
        return cfg["controller"][0], cfg["controller"]
    return None


def wanted(cfg: Config, *names: str) -> bool:
    """True without OBBW_CONTROLLER_NAME, or when it is one of these names.

    A space matches a hyphen.
    """
    want = cfg["controller_name"].replace(" ", "-")
    return not want or want in {name.lower().replace(" ", "-") for name in names}


def on_link(cfg: Config, address: str) -> bool:
    """Whether an mDNS answer's address can be a controller: not this host, nor another network."""
    ip, network = ipaddress.ip_address(address), lan_network(cfg["ip"])
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast) and (
        network is None or ip in network
    )


def match_controller(
    cfg: Config,
    instance: str,
    server: str,
    properties: Mapping[bytes, bytes | None],
    addresses: Sequence[str],
    port: int,
) -> tuple[Target, None] | tuple[None, str]:
    """Map one `_http._tcp` service to ((label, (ip, port)), None), or (None, why it is skipped)."""
    host = server.rstrip(".").lower()
    ipv4 = [a for a in addresses if ":" not in a and on_link(cfg, a)]
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


def controller_identity(body: str | bytes) -> Identity | None:
    """The controller's /api/v1/integration/info answer as {name, firmware}, or None otherwise."""
    try:
        info = json.loads(body)
    except ValueError:
        return None
    if not (
        isinstance(info, dict)
        and type(info.get("apiVersion")) is int
        and info["apiVersion"] == 1
        and isinstance(info.get("name"), str)
        and isinstance(info.get("firmwareVersion"), str)
        and isinstance(info.get("authRequired"), bool)
    ):
        return None

    def clean(text: str) -> str:
        return "".join(c for c in text if c.isprintable() and not c.isspace())[:48] or "?"

    return {
        "name": "".join(c for c in info["name"] if c.isprintable()).strip()[:32] or "?",
        "firmware": clean(info["firmwareVersion"]),
    }


def probe_controller(ip: str, port: int = 80, timeout: float = SCAN_TIMEOUT_S) -> Found | None:
    """One GET of the identity route: {name, firmware, ip, port}, or None.

    No redirect, proxy or retry.
    """
    connection = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        connection.request("GET", SCAN_PATH, headers={"Accept": "application/json"})
        reply = connection.getresponse()
        info = controller_identity(reply.read(1024)) if reply.status == 200 else None
    except OSError, http.client.HTTPException, ValueError:
        return None
    finally:
        connection.close()
    return None if info is None else {**info, "ip": ip, "port": port}


def lan_network(ip: str, routes: Path = ROUTES) -> ipaddress.IPv4Network | None:
    """The companion's own IPv4 network: the most specific on-link route that holds its address."""
    best, address = None, ipaddress.ip_address(ip)
    try:
        lines = routes.read_text().splitlines()[1:]
    except OSError:
        return None
    for fields in (line.split() for line in lines):
        if len(fields) < 8 or int(fields[2], 16):  # Reached through a router: not this link.
            continue
        destination, mask = (
            socket.inet_ntoa(struct.pack("=I", int(fields[i], 16))) for i in (1, 7)
        )
        network = ipaddress.IPv4Network(f"{destination}/{mask}", strict=False)
        if (
            network.prefixlen
            and address in network
            and (not best or network.prefixlen > best.prefixlen)
        ):
            best = network
    return best


def scan_plan(
    cfg: Config, routes: Path = ROUTES
) -> tuple[ipaddress.IPv4Network | None, list[str], str | None]:
    """(network, hosts to probe, None), or (network or None, [], why it is not searched)."""
    network = lan_network(cfg["ip"], routes)
    if network is None:
        return None, [], f"no network interface of its own holds {cfg['ip']}"
    if not any(network.subnet_of(private) for private in PRIVATE):
        return network, [], f"{network} is not a private home network"
    if network.prefixlen < SCAN_MAX_PREFIX:  # Docker's own bridges (/16, /20) end here too.
        return network, [], f"{network} is larger than /{SCAN_MAX_PREFIX}"
    return network, [str(host) for host in network.hosts() if str(host) != cfg["ip"]], None


def scan_seconds(hosts: Sequence[str]) -> int:
    return math.ceil(len(hosts) / SCAN_WORKERS) * SCAN_TIMEOUT_S + 1


def scan_hosts(cfg: Config, hosts: Iterable[str], probe: Probe = probe_controller) -> list[Found]:
    """Probe each host once, SCAN_WORKERS at a time: the matching controllers, in address order."""
    with ThreadPoolExecutor(SCAN_WORKERS) as pool:
        return [found for found in pool.map(probe, hosts) if found and wanted(cfg, found["name"])]


def scan_target(found: Found) -> Target:
    return found["name"], (found["ip"], found["port"])


def scan(cfg: Config, data: Path, probe: Probe = probe_controller, routes: Path = ROUTES) -> int:
    """`gateway.py scan`, for ./setup: one line per step and controller.

    Stores the controller when one answers.
    """
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


def fallback(
    cfg: Config,
    current: Callable[[], tuple[Target | None, str]],
    events: queue.Queue[Event],
    stop: threading.Event,
    probe: Probe = probe_controller,
    routes: Path = ROUTES,
    delays: Sequence[float] = SCAN_AFTER_S,
) -> None:
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
        if (
            target
            and (stored := probe(*target[1], timeout=STORED_TIMEOUT_S))
            and wanted(cfg, stored["name"])
        ):
            events.put(("scanned", [stored]))
            delay = delays[-1]
            continue
        network, hosts, why = scan_plan(cfg, routes)
        if why:
            log(f"not searching the network for the controller: {why}")
            return
        started = time.monotonic()
        log(
            (
                f"the controller at {target[1][0]} does not answer"
                if target
                else "mDNS has not found the controller"
            )
            + f"; searching {network} ({len(hosts)} addresses)"
        )
        found = scan_hosts(cfg, hosts, probe)
        if found:
            events.put(("scanned", found))
            backoff, delay = iter(delays[1:]), delays[-1]
        else:
            delay = next(backoff, delays[-1])
            log(
                f"no controller answered in {network} ({time.monotonic() - started:.0f} s); "
                f"searching again in {delay // 60} minutes"
            )


def certificate(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    days: int,
    extensions: Sequence[tuple[x509.ExtensionType, bool]],
    issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
) -> x509.Certificate:
    """An X.509 v3 certificate for key, valid from now: self-signed, or signed by issuer."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer_name, signer = (issuer[0].subject, issuer[1]) if issuer else (name, key)
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False
        )
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(signer, hashes.SHA256())


def save(
    key: ec.EllipticCurvePrivateKey, key_path: Path, cert: x509.Certificate, path: Path
) -> None:
    """Write a key (PKCS #8, unencrypted, owner-only) and its certificate as PEM, each whole or
    not at all, so a kill or a full disk never leaves half a file."""
    for target, body, mode in (
        (
            key_path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            0o600,
        ),
        (path, cert.public_bytes(serialization.Encoding.PEM), 0o644),
    ):
        temporary = target.with_name(target.name + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(descriptor, "wb") as file:
            file.write(body)
            file.flush()
            os.fsync(file.fileno())
        temporary.replace(target)


def covers(ca: x509.Certificate, host: str) -> bool:
    """Whether the CA's name constraints permit host."""
    try:
        constraints = ca.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return False
    return x509.DNSName(host) in (constraints.permitted_subtrees or [])


def leaf_current(ca: x509.Certificate, leaf: Path, host: str) -> bool:
    """Whether the server certificate chains to the CA for host and is not due for renewal."""
    try:
        cert = x509.load_pem_x509_certificate(leaf.read_bytes())
        PolicyBuilder().store(Store([ca])).build_server_verifier(x509.DNSName(host)).verify(
            cert, []
        )
    except OSError, ValueError, VerificationError:
        return False
    renew_at = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=RENEW_BEFORE_S)
    return cert.not_valid_after_utc > renew_at


def leaf_matches(leaf: Path, key: Path) -> bool:
    """Whether the server key belongs to the server certificate: a kill between writing the two
    leaves a pair nginx refuses."""
    try:
        cert = x509.load_pem_x509_certificate(leaf.read_bytes())
        private = serialization.load_pem_private_key(key.read_bytes(), None)
    except OSError, ValueError, TypeError:
        return False
    return private.public_key() == cert.public_key()


def read_ca(path: Path) -> x509.Certificate | None:
    """The CA certificate, or None when there is none or it cannot be read: a new CA costs setting
    the devices up again, a crash loop costs the setup page that does it."""
    if not path.exists():
        return None
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except ValueError:
        log(
            "the CA certificate cannot be read; creating a new one, "
            "so every device must be set up again"
        )
        return None


def ensure_certificates(cfg: Config, data: Path) -> bool:
    """Create or renew the CA and server certificate; return True when files changed."""
    host, ca_path, ca_key_path = cfg["hostname"], data / f"{CA_NAME}.crt", data / f"{CA_NAME}.key"
    leaf, leaf_key = data / "server.crt", data / "server.key"
    data.mkdir(parents=True, exist_ok=True)
    changed = False
    ca = read_ca(ca_path)
    if ca is None or not covers(ca, host):
        if ca is not None:
            log(
                f"the CA does not cover {host}; creating a new one, "
                "so every device must be set up again"
            )
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca = certificate(
            f"Open Brew by Weight local CA ({host})",
            ca_key,
            3650,
            [
                (x509.BasicConstraints(ca=True, path_length=0), True),
                (
                    x509.KeyUsage(
                        digital_signature=False,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    True,
                ),
                (x509.NameConstraints([x509.DNSName(host)], None), True),
            ],
        )
        save(ca_key, ca_key_path, ca, ca_path)
        changed = True
    if changed or not leaf_current(ca, leaf, host) or not leaf_matches(leaf, leaf_key):
        signer = serialization.load_pem_private_key(ca_key_path.read_bytes(), None)
        if not isinstance(signer, ec.EllipticCurvePrivateKey):
            raise TypeError(f"{ca_key_path} does not hold the CA's elliptic-curve key")
        key = ec.generate_private_key(ec.SECP256R1())
        cert = certificate(
            host,
            key,
            LEAF_DAYS,
            [
                (x509.SubjectAlternativeName([x509.DNSName(host)]), False),
                (x509.BasicConstraints(ca=False, path_length=None), True),
                (
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    True,
                ),
                (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
            ],
            (ca, signer),
        )
        save(key, leaf_key, cert, leaf)
        log(f"issued the server certificate for {host}")
        changed = True
    for key_path in (ca_key_path, leaf_key):
        key_path.chmod(0o600)
    return changed


def mobileconfig(ca_der: bytes, host: str) -> bytes:
    """Apple configuration profile that installs the CA as a trusted root."""
    digest = hashlib.sha256(ca_der).hexdigest()
    ident = f"org.openbrewbyweight.gateway.{host}"
    return plistlib.dumps(
        {
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": ident,
            "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, digest)).upper(),
            "PayloadDisplayName": "Open Brew by Weight secure access",
            "PayloadDescription": f"Lets this device open https://{host} without warnings.",
            "PayloadContent": [
                {
                    "PayloadType": "com.apple.security.root",
                    "PayloadVersion": 1,
                    "PayloadIdentifier": ident + ".ca",
                    "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, digest + ".ca")).upper(),
                    "PayloadDisplayName": "Open Brew by Weight local CA",
                    "PayloadCertificateFileName": f"{CA_NAME}.cer",
                    "PayloadContent": ca_der,
                }
            ],
        }
    )


def fill(template: str, values: Mapping[str, object]) -> str:
    for key, value in values.items():
        template = template.replace(f"@{key}@", str(value))
    return template


def site_url(scheme: str, cfg: Config, port: int, default: int) -> str:
    return f"{scheme}://{cfg['hostname']}" + ("" if port == default else f":{port}")


def upstream(target: Target | None) -> str:
    return (
        target[1][0] + ("" if target[1][1] == 80 else f":{target[1][1]}")
        if target
        else "127.0.0.1:9"
    )


def qr_svg(text: str) -> str:
    """The QR code of text as inline SVG, one module of margin; the page's CSS sizes it."""
    code = segno.make(text, error="l", boost_error=False)
    return code.svg_inline(border=1, omitsize=True, svgclass=None, lineclass=None)


def setup_pages(values: dict[str, str], target: Target | None) -> dict[str, str]:
    """The setup page in each language of strings.json, filled with values (HTML-escaped)."""
    pages: dict[str, str] = {}
    for lang, strings in json.loads((HERE / "strings.json").read_text()).items():
        controller = (
            strings["found"].format(name=target[0], address=upstream(target))
            if target
            else strings["looking"]
        )
        page = fill(
            (HERE / "setup.html").read_text(),
            {
                "T_" + key.upper(): "".join(f"<li>{item}</li>" for item in text)
                if isinstance(text, list)
                else text
                for key, text in strings.items()
            },
        )
        pages[lang] = fill(page, {**values, "CONTROLLER": html.escape(controller)})
    return pages


def write_site(cfg: Config, data: Path, run: Path, target: Target | None) -> None:
    """Render nginx.conf and the setup page for the current controller."""
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
        "VERSION": html.escape(VERSION),
        "HOSTNAME": html.escape(cfg["hostname"]),
        "CA_NAME": CA_NAME,
        "FINGERPRINT": ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)),
        "QR": qr_svg(setup),
        "QR_IOS": qr_svg(f"{setup}/{CA_NAME}.mobileconfig"),
        "QR_ANDROID": qr_svg(f"{setup}/{CA_NAME}.crt"),
    }
    files = {
        f"{CA_NAME}.crt": ca_pem.encode(),
        f"{CA_NAME}.mobileconfig": mobileconfig(ca_der, cfg["hostname"]),
    }
    for lang, page in setup_pages(values, target).items():
        files[f"index.{lang}.html"] = page.encode()
    for name, content in files.items():
        (www / name).write_bytes(content)
        (www / name).chmod(0o644)
    (run / "nginx.conf").write_text(
        fill(
            (HERE / "nginx.conf.in").read_text(),
            {
                "RUN": run,
                "DATA": data,
                "HTTP_PORT": cfg["http_port"],
                "HTTPS_PORT": cfg["https_port"],
                "UPSTREAM": upstream(target),
                "OFFLINE": "" if target else "return 503;",
            },
        )
    )


MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def openssl_time(moment: dt.datetime) -> str:
    """A UTC time as OpenSSL prints it (`Nov  3 14:05:09 2027 GMT`), whatever the locale."""
    month = MONTHS[moment.month - 1]
    return f"{month} {moment.day:2d} {moment:%H:%M:%S} {moment.year} GMT"


def reload_nginx(run: Path) -> None:
    """Make nginx, which the entrypoint runs beside this supervisor, reread its configuration."""
    try:
        os.kill(int((run / "nginx.pid").read_text()), signal.SIGHUP)
    except (OSError, ValueError) as error:
        log(f"nginx did not reload its configuration: {error}")


def write_status(
    cfg: Config, data: Path, run: Path, target: Target | None, source: str, seen: dict[str, Seen]
) -> None:
    """Publish the gateway's state at /__companion/gateway.

    For ./setup, health checks and monitoring.
    """
    expires = openssl_time(
        x509.load_pem_x509_certificate((data / "server.crt").read_bytes()).not_valid_after_utc
    )
    status: Status = {
        "name": cfg["name"],
        "hostname": cfg["hostname"],
        "ip": cfg["ip"],
        "mdns_publish": cfg["mdns_publish"],
        "setup_url": site_url("http", cfg, cfg["http_port"], 80),
        "secure_url": site_url("https", cfg, cfg["https_port"], 443),
        "controller": {
            "name": target[0],
            "ip": target[1][0],
            "port": target[1][1],
            "source": source,
        }
        if target
        else None,
        "seen": seen,
        "certificate_expires": expires,
    }
    temporary = run / "status.json.tmp"
    temporary.write_text(json.dumps(status, indent=2))
    temporary.chmod(0o644)
    temporary.replace(run / "status.json")


def controller_filter(cfg: Config) -> str:
    return f"{cfg['controller']}|{cfg['controller_name']}"


def remembered_controller(cfg: Config, data: Path) -> tuple[Target, str] | None:
    """(controller, source) found last with the same settings, used at start until mDNS confirms it.

    The source is "remembered" for one found over mDNS and "scan" for one found by searching.
    """
    try:
        saved = json.loads((data / CONTROLLER_FILE).read_text())
        if saved["filter"] != controller_filter(cfg):
            return None
        return (saved["name"], (saved["ip"], saved["port"])), "scan" if saved.get(
            "via"
        ) == "scan" else "remembered"
    except OSError, ValueError, KeyError:
        return None


def remember_controller(cfg: Config, data: Path, target: Target, via: str = "mdns") -> None:
    (data / CONTROLLER_FILE).write_text(
        json.dumps(
            {
                "name": target[0],
                "ip": target[1][0],
                "port": target[1][1],
                "filter": controller_filter(cfg),
                "via": via,
            }
        )
    )


def https_get(cfg: Config, data: Path, path: str) -> int:
    """GET path through the gateway's own HTTPS server, verifying it against the gateway CA."""
    context = ssl.create_default_context(cafile=str(data / f"{CA_NAME}.crt"))
    with (
        socket.create_connection(("127.0.0.1", cfg["https_port"]), timeout=15) as raw,
        context.wrap_socket(raw, server_hostname=cfg["hostname"]) as tls,
    ):
        tls.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {cfg['hostname']}\r\nConnection: close\r\n\r\n".encode()
        )
        return int(tls.recv(64).split()[1])


def http_json(cfg: Config, path: str) -> object:
    """GET path from the gateway's own plain-HTTP server: its JSON answer; OSError if not 2xx."""
    connection = http.client.HTTPConnection("127.0.0.1", cfg["http_port"], timeout=5)
    try:
        connection.request("GET", path)
        reply = connection.getresponse()
        if not 200 <= reply.status < 300:
            raise OSError(f"HTTP Error {reply.status}: {reply.reason}")
        return json.load(reply)
    finally:
        connection.close()


def check(cfg: Config, data: Path, through_controller: bool) -> int:
    """Probe the running gateway from inside its container: one line per finding.

    Exits 1 on a problem. Without --controller nothing reaches the controller, so Docker health
    checks add no Wi-Fi traffic.
    """
    try:
        # Both answers come from this gateway's own nginx and companion.
        status = cast("Status", http_json(cfg, "/__companion/gateway"))
        print("ok setup-page")
        print(f"ok https {https_get(cfg, data, '/__companion/ping')}")
        companion = cast("CompanionStatus", http_json(cfg, "/__companion/status"))
        print(f"ok companion link {companion['link']}")
    except (OSError, ValueError, IndexError) as error:
        print(f"fail gateway {error}")
        return 1
    for name, seen in status["seen"].items():
        print(f"seen {'controller' if seen['controller'] else 'other'} {name}: {seen['note']}")
    controller = status["controller"]
    if not controller:
        print("fail controller not found yet")
        return 1
    print(
        f"ok controller {controller['name']} {controller['ip']}:{controller['port']} "
        f"{controller['source']}"
    )
    if through_controller:
        code: int | Exception
        try:
            code = https_get(cfg, data, "/")
        except (OSError, ValueError, IndexError) as error:
            code = error
        print(f"{'ok' if code in range(200, 400) else 'fail'} web-ui {code}")
        return 0 if code in range(200, 400) else 1
    return 0


def mdns_check(cfg: Config, host: str = "openbrewbyweight.local", *, wait_s: float = 3) -> int:
    """`gateway.py mdns-check [name.local]`: where mDNS answers reach this container.

    Shows where answers about the controller arrive. Prints the interfaces, their flags and
    multicast groups, then asks for host's address and the `_http._tcp` services three ways,
    printing every packet that arrives and on which interface: legacy unicast (from a random port,
    so the answer comes back unicast), QM from port 5353 (the answer goes to the multicast group)
    and QU from port 5353 (unicast to port 5353, which the running companion may receive instead
    of this check). It changes nothing in the running companion.
    """
    addresses = [
        (adapter.nice_name, f"{ip.ip}/{ip.network_prefix}")
        for adapter in ifaddr.get_adapters()
        for ip in adapter.ips
        if ip.is_IPv4
    ]
    for interface, address in addresses:
        flags = int((Path("/sys/class/net") / interface / "flags").read_text(), 16)
        print(
            f"{interface} inet {address}",
            " ".join(
                f
                for bit, f in ((0x1000, "MULTICAST"), (0x200, "ALLMULTI"), (0x100, "PROMISC"))
                if flags & bit
            ),
        )
    print(
        "Multicast groups (FB0000E0 is mDNS, 224.0.0.251):\n"
        + Path("/proc/net/igmp").read_text().rstrip()
    )
    results: dict[str, str | None] = {}
    host, group = host.rstrip(".").lower() + ".", ("224.0.0.251", 5353)
    for label, port, unicast in (
        ("legacy unicast", 0, False),
        ("QM", 5353, False),
        ("QU", 5353, True),
    ):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("", port))
            if port:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton(group[0]) + socket.inet_aton(cfg["ip"]),
                )
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
            print(
                f"\n{label}: asked for {host} and _http._tcp.local. "
                f"from {cfg['ip']}:{sock.getsockname()[1]}"
            )
            deadline, results[label] = time.monotonic() + wait_s, None
            while (left := deadline - time.monotonic()) > 0:
                sock.settimeout(left)
                try:
                    data, ancillary, _, source = sock.recvmsg(9000, 64)
                except TimeoutError:
                    break
                interface, _, destination = struct.unpack("I4s4s", ancillary[0][2])
                message = DNSIncoming(data, source)
                records = [
                    f"{r.name} A {ipaddress.ip_address(r.address)}"
                    if isinstance(r, DNSAddress)
                    else f"{r.name} PTR {r.alias}"
                    if isinstance(r, DNSPointer)
                    else f"{r.name} {const._TYPES.get(r.type, r.type)}"
                    for r in message.answers()
                ]
                what = "query" if message.is_query() else "; ".join(records) or "empty answer"
                print(
                    f"  {source[0]}:{source[1]} -> {socket.inet_ntoa(destination)} on "
                    f"{socket.if_indextoname(interface)}: {what}"
                )
                if any(r.lower().startswith(host + " a ") for r in records):
                    results[label] = (
                        results[label] or f"{source[0]} -> {socket.inet_ntoa(destination)}"
                    )
    print(
        "\n"
        + "\n".join(
            f"{label}: " + (f"answered ({how})" if how else "no answer about " + host)
            for label, how in results.items()
        )
    )
    return 0 if all(results.values()) else 1


def main() -> None:
    cfg = load_config(os.environ)
    if sys.argv[1:2] == ["check"]:
        raise SystemExit(check(cfg, DATA, "--controller" in sys.argv))
    if sys.argv[1:2] == ["scan"]:
        raise SystemExit(scan(cfg, DATA))
    if sys.argv[1:2] == ["mdns-check"]:
        raise SystemExit(mdns_check(cfg, *sys.argv[2:3]))
    configure_logging(DATA)  # The supervisor only: check/scan never share the rotating file.
    target, source = static_controller(cfg), "manual"
    if not target and (saved := remembered_controller(cfg, DATA)):
        target, source = saved
    ensure_certificates(cfg, DATA)
    write_site(cfg, DATA, RUN, target)
    seen: dict[str, Seen] = {}
    write_status(cfg, DATA, RUN, target, source, seen)
    if sys.argv[1:2] == ["prepare"]:
        # gateway/entrypoint.sh starts nginx on what this rendered, then this supervisor.
        stop_logging()
        raise SystemExit(0)
    events: queue.Queue[Event] = queue.Queue()
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    companion = start_companion(cfg, DATA, RUN, lambda: events.put(("companion",)))
    companion.controller(target)

    zc = Zeroconf(interfaces=[cfg["ip"]], ip_version=IPVersion.V4Only)
    heard: set[str] = set()  # Devices whose mDNS address records reached the companion.
    heard_lock = threading.Lock()

    class Heard(RecordUpdateListener):
        @override
        def async_update_records(
            self, zc: Zeroconf, now: float, records: list[RecordUpdate]
        ) -> None:
            with heard_lock:
                for record in records:
                    if isinstance(record.new, DNSAddress) and len(heard) < DISCOVERY_MAX:
                        heard.add(record.new.name)

    zc.add_listener(Heard(), None)
    if cfg["mdns_publish"]:
        zc.register_service(
            ServiceInfo(
                "_https._tcp.local.",
                f"{cfg['hostname'].removesuffix('.local')}._https._tcp.local.",
                addresses=[socket.inet_aton(cfg["ip"])],
                port=cfg["https_port"],
                server=cfg["hostname"] + ".",
                properties={"path": "/"},
            ),
            allow_name_change=True,
        )
        log(f"publishing {cfg['hostname']} at {cfg['ip']}")

    def on_change(
        zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
    ) -> None:
        if state_change is ServiceStateChange.Removed:
            return  # Keep the last address; a restarting controller announces itself again.
        instance = name.removesuffix("." + service_type)
        try:
            info = zeroconf.get_service_info(service_type, name, timeout=INFO_TIMEOUT_MS)
        except ZeroconfError as error:  # One malformed packet must not end the browser's thread.
            events.put(("skip", instance, False, f"unreadable announcement ({error})"))
            return
        matched = (
            match_controller(
                cfg,
                instance,
                info.server,
                info.properties,
                info.parsed_addresses(IPVersion.V4Only),
                info.port,
            )
            # The service record sets the server and port together.
            if info and info.server and info.port is not None
            else (None, "no answer yet")
        )
        is_controller = bool(info and info.properties.get(b"obbw") == b"1")
        events.put(
            ("found", matched[0]) if matched[0] else ("skip", instance, is_controller, matched[1])
        )

    def note(instance: str, is_controller: bool, reason: str) -> bool:
        """Record what discovery made of a device; return True when that changed."""
        if seen.get(instance) == {"controller": is_controller, "note": reason} or (
            instance not in seen and len(seen) >= DISCOVERY_MAX
        ):
            return False
        seen[instance] = {"controller": is_controller, "note": reason}
        return True

    browser: ServiceBrowser | None = None
    if source != "manual" or not target:
        browser = ServiceBrowser(zc, HTTP_SERVICE, handlers=[on_change])
        log(
            "looking for "
            + (cfg["controller"][0] if cfg["controller"] else "the controller")
            + " over mDNS"
        )
    if target:
        log(f"using the controller at {target[1][0]}:{target[1][1]} ({source})")
    stop = threading.Event()
    if not cfg["controller"] and (not target or source == "scan"):
        threading.Thread(
            target=fallback, args=(cfg, lambda: (target, source), events, stop), daemon=True
        ).start()
    retries = iter(RETRY_S)
    status = 0
    unhandled = 0
    proving: set[tuple[str, int]] = set()

    def new_address(event: Event) -> Target | None:
        """The controller this event would move to, when it names a new address."""
        moved = (
            event[1]
            if event[0] == "found"
            else scan_target(event[1][0])
            if event[0] == "scanned" and source != "mdns"
            else None
        )
        return moved if moved and (target is None or moved[1] != target[1]) else None

    def ask_proof(moved: Target, asked: Event) -> None:
        def answered(ok: bool) -> None:
            events.put(("proved", ok, moved[1], asked))

        proving.add(moved[1])
        companion.prove(moved, answered)

    try:
        while True:
            searching = browser and source != "mdns"
            try:
                event = events.get(
                    timeout=next(retries, RETRY_S[-1]) if searching else CERT_CHECK_S
                )
            except queue.Empty:
                event = ("tick",)
            try:
                proved = None
                if event[0] == "proved":
                    proving.discard(event[2])
                    if not event[1]:
                        continue
                    proved, event = event[2], event[3]
                if event[0] == "tick" and searching and browser:
                    with heard_lock:
                        others = sorted(
                            n.removesuffix(".local.") for n in heard - {cfg["hostname"] + "."}
                        )
                    log(
                        "no controller confirmed yet; asking the network again ("
                        + (
                            f"mDNS reaches the companion from {len(others)} devices: "
                            f"{', '.join(others[:5])}"
                            if others
                            else f"no mDNS answer from any device has reached {cfg['ip']}"
                        )
                        + ")"
                    )
                    browser.cancel()
                    browser = ServiceBrowser(zc, HTTP_SERVICE, handlers=[on_change])
                site_changed = status_changed = False
                if event[0] == "companion":
                    log("the companion service stopped")
                    status = 1
                    break
                if event[0] == "skip" and note(*event[1:]):
                    log(f"skipping {event[1]}: {event[3]}")
                    status_changed = True
                elif (
                    event[0] == "found"
                    and source == "mdns"
                    and target is not None
                    and event[1][0] != target[0]
                    and not cfg["controller_name"]
                ):
                    reason = "another controller; set OBBW_CONTROLLER_NAME to choose"
                    if note(event[1][0], True, reason):
                        log(f"ignoring {event[1][0]}: {reason}")
                        status_changed = True
                elif (moved := new_address(event)) and moved[1] != proved:
                    # Discovery is unauthenticated: paired, a new address must prove the pairing.
                    if moved[1] not in proving:
                        ask_proof(moved, event)
                elif event[0] == "found" and (event[1], "mdns") != (target, source):
                    target, source = event[1], "mdns"
                    note(target[0], True, "in use")
                    remember_controller(cfg, DATA, target)
                    log(f"controller {target[0]} at {target[1][0]}:{target[1][1]}")
                    site_changed = True
                elif event[0] == "scanned" and source != "mdns":
                    found = scan_target(event[1][0])
                    for other in event[1][1:]:
                        status_changed |= note(
                            other["name"],
                            True,
                            f"another controller, at {other['ip']}; "
                            "set OBBW_CONTROLLER_NAME to choose",
                        )
                    if found != target:
                        remember_controller(cfg, DATA, found, "scan")
                        log(
                            f"controller {found[0]} at {found[1][0]}:{found[1][1]}, "
                            f"found by searching the network (firmware {event[1][0]['firmware']})"
                        )
                        note(found[0], True, "in use")
                        site_changed = True
                    status_changed |= source != "scan"
                    target, source = found, "scan"
                elif event[0] == "tick" and ensure_certificates(cfg, DATA):
                    site_changed = True
                if (event[0] == "found" and event[1] == target) or (
                    event[0] == "scanned" and source == "scan"
                ):
                    companion.controller(
                        target
                    )  # Every announcement: reconnect now if the link is down.
                if site_changed:
                    write_site(cfg, DATA, RUN, target)
                    reload_nginx(RUN)
                if site_changed or status_changed:
                    write_status(cfg, DATA, RUN, target, source, seen)
                unhandled = 0
            except Exception:
                # One bad event must not end the supervisor; ten in a row is a state a
                # restart clears better than a limp.
                unhandled += 1
                logger.info("an event was not handled:", exc_info=True)
                if unhandled >= 10:
                    status = 1
                    break
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        companion.stop()
        zc.close()  # Sends mDNS goodbyes for the published name.
        stop_logging()  # Last: the companion's shutdown lines still get written.
    raise SystemExit(status)


if __name__ == "__main__":
    main()
