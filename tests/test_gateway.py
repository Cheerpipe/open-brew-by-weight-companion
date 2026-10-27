#!/usr/bin/env python3
"""Contract tests for the HTTPS gateway supervisor (no network, no Docker)."""

import importlib.util
import json
import plistlib
import re
import ssl
import subprocess
import tempfile
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gateway", ROOT / "gateway/gateway.py")
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)
gateway.qr_svg = lambda text: f"<svg data-text='{text}'></svg>"  # qrencode lives in the image only.

BASE = {"GATEWAY_IP": "192.168.1.240"}

cfg = gateway.load_config(BASE)
assert cfg["hostname"] == "openbrewbyweight-secure.local"
assert (cfg["http_port"], cfg["https_port"], cfg["mdns_publish"]) == (80, 443, True)
assert gateway.load_config({**BASE, "GATEWAY_HOSTNAME": "Brew.Local."})["hostname"] == "brew.local"
assert gateway.load_config({**BASE, "MDNS_PUBLISH": "off"})["mdns_publish"] is False
manual = gateway.load_config({**BASE, "OBBW_CONTROLLER_URL": "192.168.1.50:8080"})
assert gateway.static_controller(manual) == ("192.168.1.50", ("192.168.1.50", 8080))
named = gateway.load_config({**BASE, "OBBW_CONTROLLER_URL": "http://Cafe-Bar.local"})
assert named["controller"] == ("cafe-bar.local", 80) and gateway.static_controller(named) is None
try:
    gateway.load_config({**BASE, "OBBW_CONTROLLER_URL": "https://192.168.1.50"})
    raise AssertionError("an https controller URL must be rejected")
except SystemExit:
    pass

TXT = {b"obbw": b"1"}
found = gateway.match_controller(cfg, "Cafe Bar", "cafe-bar.local.", TXT, ["fe80::1", "192.168.1.50"], 80)
assert found == (("Cafe Bar", ("192.168.1.50", 80)), None)
assert gateway.match_controller(cfg, "Printer", "printer.local.", {}, ["192.168.1.9"], 80) == (
    None, "not an Open Brew by Weight controller")
assert gateway.match_controller(cfg, "Cafe Bar", "cafe-bar.local.", TXT, ["fe80::1"], 80) == (
    None, "no IPv4 address")
for wanted in ("cafe bar", "cafe-bar"):
    chosen = {**cfg, "controller_name": wanted}
    assert gateway.match_controller(chosen, "Cafe Bar", "cafe-bar.local.", TXT, ["192.168.1.50"], 80)[0]
    assert gateway.match_controller(chosen, "Other", "other.local.", TXT, ["192.168.1.51"], 80) == (
        None, "not the controller named in OBBW_CONTROLLER_NAME")
assert gateway.match_controller(named, "Cafe Bar", "cafe-bar.local.", {}, ["192.168.1.50"], 80)[0]
assert gateway.match_controller(named, "Other", "other.local.", TXT, ["192.168.1.51"], 80) == (
    None, "not cafe-bar.local")

def verify(ca, leaf, host):
    return subprocess.run(["openssl", "verify", "-CAfile", str(ca), "-verify_hostname", host, str(leaf)],
                          capture_output=True).returncode == 0


with tempfile.TemporaryDirectory(prefix="openbrewbyweight-gateway-") as temporary:
    data, run = Path(temporary) / "data", Path(temporary) / "run"
    ca, leaf = data / f"{gateway.CA_NAME}.crt", data / "server.crt"
    assert gateway.ensure_certificates(cfg, data) is True
    assert gateway.ensure_certificates(cfg, data) is False, "valid certificates must be kept"
    assert verify(ca, leaf, cfg["hostname"]) and not verify(ca, leaf, "other.local")
    assert (data / "server.key").stat().st_mode & 0o077 == 0
    ca_pem = ca.read_text()

    gateway.write_site(cfg, data, run, ("Cafe Bar", ("192.168.1.50", 8080)))
    conf = (run / "nginx.conf").read_text()
    assert "proxy_pass http://192.168.1.50:8080;" in conf
    assert "proxy_set_header Origin http://192.168.1.50:8080;" in conf
    assert "return 503;" not in conf
    pages = {lang: (run / f"www/index.{lang}.html").read_text() for lang in ("en", "es")}
    assert "Found Cafe Bar at 192.168.1.50:8080" in pages["en"] and '<html lang="en">' in pages["en"]
    assert "Controlador Cafe Bar encontrado" in pages["es"] and "Ajustes de confianza" in pages["es"]
    assert "data-text='http://openbrewbyweight-secure.local'" in pages["es"]
    assert "data-text='http://openbrewbyweight-secure.local/openbrewbyweight-ca.mobileconfig'" in pages["en"]
    assert "data-text='http://openbrewbyweight-secure.local/openbrewbyweight-ca.crt'" in pages["en"]
    assert "index.es.html" in conf and "location = /__gateway/status" in conf
    assert f"proxy_cache_path {run}/cache " in conf
    api = conf.split("    location / {", 1)[1].split("\n    }", 1)[0]
    assert "proxy_pass" in api and "proxy_cache" not in api, "API and WebSocket traffic is never cached"
    assert conf.count("proxy_cache webui;") == 2
    for rendered in (conf, *pages.values()):
        assert not re.search(r"@[A-Z_]+@", rendered), "unfilled placeholder"
    profile = plistlib.loads((run / f"www/{gateway.CA_NAME}.mobileconfig").read_bytes())
    assert profile["PayloadContent"][0]["PayloadContent"] == ssl.PEM_cert_to_DER_cert(ca_pem)

    gateway.write_site({**cfg, "https_port": 8443}, data, run, None)
    assert "return 503;" in (run / "nginx.conf").read_text()
    assert "https://openbrewbyweight-secure.local:8443/" in (run / "www/index.en.html").read_text()

    target = ("Cafe Bar", ("192.168.1.50", 80))
    gateway.write_status(cfg, data, run, target, "mdns", {"Printer": {"controller": False, "note": "x"}})
    status = json.loads((run / "status.json").read_text())
    assert status["controller"] == {"name": "Cafe Bar", "ip": "192.168.1.50", "port": 80, "source": "mdns"}
    assert status["seen"]["Printer"]["note"] == "x" and status["certificate_expires"]
    assert status["setup_url"] == "http://openbrewbyweight-secure.local"

    assert gateway.remembered_controller(cfg, data) is None
    gateway.remember_controller(cfg, data, target)
    assert gateway.remembered_controller(cfg, data) == target
    assert gateway.remembered_controller({**cfg, "controller_name": "other"}, data) is None, \
        "a different controller choice must not reuse the remembered one"

    renamed = {**cfg, "hostname": "brew.local"}
    assert gateway.ensure_certificates(renamed, data) is True
    assert ca.read_text() != ca_pem, "a new name needs a CA constrained to it"
    assert verify(ca, leaf, "brew.local") and not verify(ca, leaf, cfg["hostname"])

print("HTTPS gateway: config, discovery match, certificates and rendering OK")
