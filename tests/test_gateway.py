"""Contract tests for the companion's HTTPS gateway supervisor (no network, no Docker)."""

import json
import plistlib
import re
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path

import pytest

import companion
import gateway

# The test image's OpenSSL command line checks what the gateway issues.
OPENSSL = "/usr/bin/openssl"

ROOT = Path(__file__).resolve().parents[1]
BASE = {"COMPANION_IP": "192.168.1.240", "COMPANION_NAME": "Kitchen server"}
TXT = {b"obbw": b"1"}


def test_load_config() -> None:
    cfg = gateway.load_config(BASE)
    assert cfg["hostname"] == "openbrewbyweight-secure.local"
    assert cfg["ip"] == "192.168.1.240"
    assert (cfg["http_port"], cfg["https_port"], cfg["mdns_publish"]) == (80, 443, True)
    assert (
        gateway.load_config({**BASE, "COMPANION_HOSTNAME": "Brew.Local."})["hostname"]
        == "brew.local"
    )
    assert gateway.load_config({**BASE, "COMPANION_MDNS_PUBLISH": "off"})["mdns_publish"] is False
    # The log retention settings, as compose passes them: empty means the default.
    retention = gateway.load_config(
        {**BASE, "COMPANION_LOG_RETENTION_DAYS": "90", "COMPANION_LOG_RETENTION_MB": ""}
    )
    assert (retention["log_retention_days"], retention["log_retention_mb"]) == (90, 50)
    compose = (ROOT / "compose.yaml").read_text()
    assert all(
        f"{key}: ${{{key}:-}}" in compose
        for key in ("COMPANION_LOG_RETENTION_DAYS", "COMPANION_LOG_RETENTION_MB")
    ), "compose passes the retention settings to the container"


def test_legacy_setting_names() -> None:
    """The HTTPS gateway's setting names keep working; the companion's names win."""
    legacy = gateway.load_config(
        {
            "GATEWAY_IP": "192.168.1.241",
            "GATEWAY_HOSTNAME": "espresso",
            "HTTP_PORT": "8080",
            "HTTPS_PORT": "8443",
            "MDNS_PUBLISH": "false",
        }
    )
    assert (
        legacy["ip"],
        legacy["hostname"],
        legacy["http_port"],
        legacy["https_port"],
        legacy["mdns_publish"],
    ) == ("192.168.1.241", "espresso.local", 8080, 8443, False)
    assert gateway.load_config({**BASE, "GATEWAY_IP": "192.168.1.9"})["ip"] == "192.168.1.240"


def test_instance_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """Instance name: printable, at most 32 bytes, never a container id."""
    assert gateway.load_config(BASE)["name"] == "Kitchen server"
    assert gateway.instance_name("Café \x07bar " + "é" * 20) == "Café bar " + "é" * 11
    monkeypatch.setattr(socket, "gethostname", lambda: "3f2a9c81d7e0")
    assert gateway.instance_name("") == "Companion"
    monkeypatch.setattr(socket, "gethostname", lambda: "nas.lan")
    assert gateway.instance_name(" ") == "nas"


def test_controller_url() -> None:
    manual = gateway.load_config({**BASE, "OBBW_CONTROLLER_URL": "192.168.1.50:8080"})
    assert gateway.static_controller(manual) == ("192.168.1.50", ("192.168.1.50", 8080))
    named = gateway.load_config({**BASE, "OBBW_CONTROLLER_URL": "http://Cafe-Bar.local"})
    assert named["controller"] == ("cafe-bar.local", 80)
    assert gateway.static_controller(named) is None
    with pytest.raises(SystemExit):
        gateway.load_config({**BASE, "OBBW_CONTROLLER_URL": "https://192.168.1.50"})


def test_match_controller() -> None:
    cfg = gateway.load_config(BASE)
    found = gateway.match_controller(
        cfg, "Cafe Bar", "cafe-bar.local.", TXT, ["fe80::1", "192.168.1.50"], 80
    )
    assert found == (("Cafe Bar", ("192.168.1.50", 80)), None)
    assert gateway.match_controller(cfg, "Printer", "printer.local.", {}, ["192.168.1.9"], 80) == (
        None,
        "not an Open Brew by Weight controller",
    )
    assert gateway.match_controller(cfg, "Cafe Bar", "cafe-bar.local.", TXT, ["fe80::1"], 80) == (
        None,
        "no IPv4 address",
    )
    for wanted in ("cafe bar", "cafe-bar"):
        chosen: gateway.Config = {**cfg, "controller_name": wanted}
        assert gateway.match_controller(
            chosen, "Cafe Bar", "cafe-bar.local.", TXT, ["192.168.1.50"], 80
        )[0]
        assert gateway.match_controller(
            chosen, "Other", "other.local.", TXT, ["192.168.1.51"], 80
        ) == (
            None,
            "not the controller named in OBBW_CONTROLLER_NAME",
        )
    named = gateway.load_config({**BASE, "OBBW_CONTROLLER_URL": "http://Cafe-Bar.local"})
    assert gateway.match_controller(named, "Cafe Bar", "cafe-bar.local.", {}, ["192.168.1.50"], 80)[
        0
    ]
    assert gateway.match_controller(named, "Other", "other.local.", TXT, ["192.168.1.51"], 80) == (
        None,
        "not cafe-bar.local",
    )


def verify(ca: Path, leaf: Path, host: str) -> bool:
    return (
        subprocess.run(
            [OPENSSL, "verify", "-CAfile", str(ca), "-verify_hostname", host, str(leaf)],
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


def test_certificates_rendering_and_status(monkeypatch: pytest.MonkeyPatch) -> None:
    # qr_svg is replaced so the page shows which text each QR code carries.
    monkeypatch.setattr(gateway, "qr_svg", lambda text: f"<svg data-text='{text}'></svg>")
    cfg = gateway.load_config(BASE)
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-gateway-") as temporary:
        data, run = Path(temporary) / "data", Path(temporary) / "run"
        ca, leaf = data / f"{gateway.CA_NAME}.crt", data / "server.crt"
        assert gateway.ensure_certificates(cfg, data) is True
        assert gateway.ensure_certificates(cfg, data) is False, "valid certificates must be kept"
        assert verify(ca, leaf, cfg["hostname"])
        assert not verify(ca, leaf, "other.local")
        assert (data / "server.key").stat().st_mode & 0o077 == 0
        ca_pem = ca.read_text()

        gateway.write_site(cfg, data, run, ("Cafe Bar", ("192.168.1.50", 8080)))
        conf = (run / "nginx.conf").read_text()
        assert "proxy_pass http://192.168.1.50:8080;" in conf
        assert "proxy_set_header Origin http://192.168.1.50:8080;" in conf
        assert "return 503;" not in conf
        page = (run / "www/index.en.html").read_text()
        assert "Found Cafe Bar at 192.168.1.50:8080" in page
        assert '<html lang="en">' in page
        assert "data-text='http://openbrewbyweight-secure.local'" in page
        assert (
            "data-text='http://openbrewbyweight-secure.local/openbrewbyweight-ca.mobileconfig'"
            in page
        )
        assert "data-text='http://openbrewbyweight-secure.local/openbrewbyweight-ca.crt'" in page
        assert "index.en.html" in conf
        assert conf.count("location = /__companion/gateway") == 2
        plain = conf.split("ssl default_server", 1)[0]
        assert "location ^~ /__companion/log {" in plain, "the stored log never goes in clear"
        assert "HTTPS_REQUIRED" in plain, "the stored log never goes in clear"
        assert conf.count("location ^~ /__companion/log {") == 1
        assert "location ^~ /__companion/push {" in plain, "notifications never go in clear"
        assert conf.count("location ^~ /__companion/push {") == 1
        assert "location = /__companion/erase {" in plain, "erasing the pairing never goes in clear"
        assert conf.count("location = /__companion/erase {") == 1, (
            "erasing the pairing never goes in clear"
        )
        assert "location ^~ /__companion/archive {" in plain, (
            "the archive never goes in clear either"
        )
        assert conf.count("location ^~ /__companion/archive {") == 1, (
            "the archive never goes in clear either"
        )
        assert conf.count("return 301 /__companion/gateway;") == 2, (
            "the gateway's earlier status address redirects"
        )
        assert "Open Brew by Weight Companion · Kitchen server" in page
        assert 'fetch("https://openbrewbyweight-secure.local/__companion/ping"' in page
        assert f"proxy_cache_path {run}/cache " in conf
        api = conf.split("    location / {", 1)[1].split("\n    }", 1)[0]
        assert "proxy_pass" in api, "API and WebSocket traffic is never cached"
        assert "proxy_cache" not in api, "API and WebSocket traffic is never cached"
        assert conf.count("proxy_cache webui;") == 2
        for rendered in (conf, page):
            assert not re.search(r"@[A-Z_]+@", rendered), "unfilled placeholder"
        profile = plistlib.loads((run / f"www/{gateway.CA_NAME}.mobileconfig").read_bytes())
        assert profile["PayloadContent"][0]["PayloadContent"] == ssl.PEM_cert_to_DER_cert(ca_pem)

        gateway.write_site({**cfg, "https_port": 8443}, data, run, None)
        assert "return 503;" in (run / "nginx.conf").read_text()
        assert (
            "https://openbrewbyweight-secure.local:8443/" in (run / "www/index.en.html").read_text()
        )

        target = ("Cafe Bar", ("192.168.1.50", 80))
        gateway.write_status(
            cfg, data, run, target, "mdns", {"Printer": {"controller": False, "note": "x"}}
        )
        status = json.loads((run / "status.json").read_text())
        assert status["controller"] == {
            "name": "Cafe Bar",
            "ip": "192.168.1.50",
            "port": 80,
            "source": "mdns",
        }
        assert status["seen"]["Printer"]["note"] == "x"
        assert status["certificate_expires"]
        assert status["setup_url"] == "http://openbrewbyweight-secure.local"
        assert status["name"] == "Kitchen server"

        assert gateway.remembered_controller(cfg, data) is None
        gateway.remember_controller(cfg, data, target)
        assert gateway.remembered_controller(cfg, data) == (target, "remembered")
        gateway.remember_controller(cfg, data, target, "scan")
        assert gateway.remembered_controller(cfg, data) == (target, "scan"), (
            "a searched controller is checked again"
        )
        assert gateway.remembered_controller({**cfg, "controller_name": "other"}, data) is None, (
            "a different controller choice must not reuse the remembered one"
        )

        renamed: gateway.Config = {**cfg, "hostname": "brew.local"}
        assert gateway.ensure_certificates(renamed, data) is True
        assert ca.read_text() != ca_pem, "a new name needs a CA constrained to it"
        assert verify(ca, leaf, "brew.local")
        assert not verify(ca, leaf, cfg["hostname"])


def test_persistent_log() -> None:
    """The persistent log: timestamped lines, rotation, and stdout-only degradation."""
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-log-") as temporary:
        data = Path(temporary)
        companion.configure_logging(data, max_bytes=300, backups=2)
        for index in range(20):
            companion.log(f"line {index}")
        companion.stop_logging()
        folder = data / "log"
        kept = sorted(path.name for path in folder.iterdir())
        assert kept == ["companion.log", "companion.log.1", "companion.log.2"], kept
        first = (folder / "companion.log").read_text().splitlines()[0]
        assert re.fullmatch(
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} INFO obbw\.companion: line \d+", first
        ), first
        denied = data / "denied"
        denied.mkdir()
        denied.chmod(0o500)
        companion.configure_logging(denied)  # One warning, stdout only, nothing raised.
        companion.log("still here")
        companion.stop_logging()
        denied.chmod(0o700)
