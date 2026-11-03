"""The network search for the controller when mDNS does not find it (offline: localhost only)."""

import contextlib
import io
import json
import queue
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, override

import pytest

import gateway

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

INFO = {
    "apiVersion": 1,
    "name": "openbrewbyweight",
    "firmwareVersion": "1.1.0+abc",
    "authRequired": True,
}
INFO_BODY = json.dumps(INFO).encode()
CONTROLLERS = {"192.168.4.194": "openbrewbyweight", "192.168.4.20": "Cafe Bar"}
# At runtime the delays are minutes; these scale them down.
DELAYS = (0.05, 0.1, 0.2, 0.3)


@pytest.fixture
def logged(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The gateway's log lines, captured instead of written."""
    lines: list[str] = []
    monkeypatch.setattr(gateway, "log", lines.append)
    return lines


def test_controller_identity() -> None:
    identity = gateway.controller_identity
    assert identity(json.dumps(INFO)) == {"name": "openbrewbyweight", "firmware": "1.1.0+abc"}
    assert identity(json.dumps({**INFO, "authRequired": False, "extra": 1}))
    for wrong in (
        {**INFO, "apiVersion": 2},
        {**INFO, "apiVersion": True},
        {**INFO, "apiVersion": "1"},
        {**INFO, "apiVersion": 1.0},
        {**INFO, "authRequired": "yes"},
        {**INFO, "name": 7},
        {k: v for k, v in INFO.items() if k != "firmwareVersion"},
        [INFO],
        "openbrewbyweight",
    ):
        assert identity(json.dumps(wrong)) is None, wrong
    for body in (b"", b"<html>router</html>", INFO_BODY[:-1], b"\xff\xfe"):
        assert identity(body) is None, body
    odd = identity(json.dumps({**INFO, "name": " Café\x07 bar ", "firmwareVersion": "1.0 beta\n"}))
    assert odd == {"name": "Café bar", "firmware": "1.0beta"}, (
        "names and versions are safe to print"
    )


class Server(ThreadingHTTPServer):
    """Counts the requests it answers and keeps the last path."""

    hits = 0
    path = ""


def serve(handler: type[BaseHTTPRequestHandler]) -> Server:
    server = Server(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def answering(
    status: int = 200, body: bytes = INFO_BODY, delay: float = 0, location: str | None = None
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server: Server

        def do_GET(self) -> None:
            self.server.hits += 1
            self.server.path = self.path
            time.sleep(delay)
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        @override
        def log_message(self, format: str, *args: object) -> None:
            pass

    return Handler


def test_probe_controller() -> None:
    controller = serve(answering())
    probe = gateway.probe_controller
    assert probe("127.0.0.1", controller.server_port) == {
        "name": "openbrewbyweight",
        "firmware": "1.1.0+abc",
        "ip": "127.0.0.1",
        "port": controller.server_port,
    }
    assert (controller.hits, controller.path) == (1, "/api/v1/integration/info"), (
        "exactly one request per host"
    )
    elsewhere = serve(answering())
    for server in (
        serve(answering(404)),
        serve(answering(body=b"<html>NAS</html>")),
        serve(answering(body=json.dumps({**INFO, "apiVersion": 2}).encode())),
        serve(answering(body=b"{" + b" " * 5000 + b"}")),
        serve(
            answering(
                302, location=f"http://127.0.0.1:{elsewhere.server_port}/api/v1/integration/info"
            )
        ),
    ):
        assert probe("127.0.0.1", server.server_port) is None
        assert server.hits == 1
    assert elsewhere.hits == 0, "a redirect is never followed to another host"
    slow = serve(answering(delay=3))
    started = time.monotonic()
    assert probe("127.0.0.1", slow.server_port) is None, "1 s timeout"
    assert time.monotonic() - started < 2, "1 s timeout"
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    assert probe("127.0.0.1", closed.getsockname()[1]) is None, (
        "a refused connection is no controller"
    )
    closed.close()


def route(destination: str, mask: str, gateway_ip: str = "0.0.0.0", interface: str = "eth0") -> str:
    def hex_ip(ip: str) -> str:
        return f"{struct.unpack('=I', socket.inet_aton(ip))[0]:08X}"

    return (
        f"{interface}\t{hex_ip(destination)}\t{hex_ip(gateway_ip)}\t0001\t0\t0\t0\t"
        f"{hex_ip(mask)}\t0\t0\t0"
    )


def routes(folder: Path, *lines: str) -> Path:
    path = folder / f"route{len(list(folder.glob('route*')))}"
    path.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        + "\n".join(lines)
        + "\n"
    )
    return path


def home_routes(folder: Path) -> Path:
    return routes(
        folder,
        route("0.0.0.0", "0.0.0.0", "192.168.4.1"),
        route("192.168.0.0", "255.255.0.0"),
        route("192.168.4.0", "255.255.255.0"),
        route("172.17.0.0", "255.255.0.0", interface="docker0"),
    )


def test_scan_plan(tmp_path: Path) -> None:
    cfg = gateway.load_config({"COMPANION_IP": "192.168.4.240"})
    home = home_routes(tmp_path)
    network, hosts, why = gateway.scan_plan(cfg, home)
    assert (str(network), why, len(hosts)) == ("192.168.4.0/24", None, 253), (
        "the most specific on-link route"
    )
    assert "192.168.4.240" not in hosts
    assert hosts[0] == "192.168.4.1"
    assert hosts[-1] == "192.168.4.254"
    assert gateway.scan_seconds(hosts) == 9
    network, hosts, why = gateway.scan_plan(
        cfg, routes(tmp_path, route("192.168.4.0", "255.255.252.0"))
    )
    assert why is None, "a /22 is the largest network searched"
    assert len(hosts) == 1021, "a /22 is the largest network searched"
    for lines, reason in (
        ([route("192.168.0.0", "255.255.248.0")], "192.168.0.0/21 is larger than /22"),
        ([route("192.168.4.0", "255.255.255.0", "192.168.4.1")], "no network interface"),
        ([route("10.0.0.0", "255.255.255.0")], "no network interface"),
        ([], "no network interface"),
    ):
        network, hosts, why = gateway.scan_plan(cfg, routes(tmp_path, *lines))
        assert hosts == [], (lines, why)
        assert why is not None, (lines, why)
        assert why.startswith(reason), (lines, why)
    docker = gateway.load_config({"COMPANION_IP": "172.17.0.3"})
    assert gateway.scan_plan(docker, home)[2] == "172.17.0.0/16 is larger than /22", (
        "Docker's bridge is skipped"
    )
    public = gateway.load_config({"COMPANION_IP": "203.0.113.7"})
    assert (
        gateway.scan_plan(public, routes(tmp_path, route("203.0.113.0", "255.255.255.0")))[2]
        == "203.0.113.0/24 is not a private home network"
    )
    missing = gateway.scan_plan(cfg, tmp_path / "missing")[2]
    assert missing is not None
    assert missing.startswith("no network interface")


class FakeLan:
    """Answers like controllers at the given addresses; counts probes and how many run at once."""

    def __init__(self, controllers: dict[str, str], delay: float = 0.0) -> None:
        self.controllers, self.delay, self.lock = controllers, delay, threading.Lock()
        self.calls: list[tuple[str, int, float]] = []
        self.running, self.peak = 0, 0

    def __call__(
        self, ip: str, port: int = 80, timeout: float = gateway.SCAN_TIMEOUT_S
    ) -> gateway.Found | None:
        with self.lock:
            self.calls.append((ip, port, timeout))
            self.running += 1
            self.peak = max(self.peak, self.running)
        time.sleep(self.delay)
        with self.lock:
            self.running -= 1
        name = self.controllers.get(ip)
        if not name:
            return None
        return {"name": name, "firmware": "1.1.0", "ip": ip, "port": port}


def test_scan_hosts(tmp_path: Path) -> None:
    cfg = gateway.load_config({"COMPANION_IP": "192.168.4.240"})
    lan = FakeLan(CONTROLLERS, delay=0.02)
    _, hosts, _ = gateway.scan_plan(cfg, home_routes(tmp_path))
    found = gateway.scan_hosts(cfg, hosts, lan)
    assert [f["ip"] for f in found] == ["192.168.4.20", "192.168.4.194"], (
        "every controller, in address order"
    )
    assert sorted(ip for ip, _, _ in lan.calls) == sorted(hosts), "each host once"
    assert len(lan.calls) == 253, "each host once"
    assert lan.peak == gateway.SCAN_WORKERS, (
        f"at most {gateway.SCAN_WORKERS} probes at a time, not {lan.peak}"
    )
    named: gateway.Config = {**cfg, "controller_name": "cafe bar"}
    assert [f["ip"] for f in gateway.scan_hosts(named, hosts, FakeLan(CONTROLLERS))] == [
        "192.168.4.20"
    ]


def scan(
    cfg: gateway.Config, lan: FakeLan, folder: Path, route_file: Path
) -> tuple[int, list[str]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        status = gateway.scan(cfg, folder, lan, route_file)
    return status, out.getvalue().splitlines()


def test_scan_command(tmp_path: Path) -> None:
    """`gateway.py scan`, as ./setup reads it."""
    cfg = gateway.load_config({"COMPANION_IP": "192.168.4.240"})
    home = home_routes(tmp_path)
    (tmp_path / gateway.CONTROLLER_FILE).unlink(missing_ok=True)
    status, lines = scan(cfg, FakeLan({"192.168.4.194": "openbrewbyweight"}), tmp_path, home)
    assert status == 0
    assert lines == [
        "range 192.168.4.0/24 253 9",
        "controller 192.168.4.194 1.1.0 openbrewbyweight",
    ]
    assert gateway.remembered_controller(cfg, tmp_path) == (
        ("openbrewbyweight", ("192.168.4.194", 80)),
        "scan",
    )
    (tmp_path / gateway.CONTROLLER_FILE).unlink()
    status, lines = scan(cfg, FakeLan(CONTROLLERS), tmp_path, home)
    assert status == 0
    assert lines[1:] == [
        "controller 192.168.4.20 1.1.0 Cafe Bar",
        "controller 192.168.4.194 1.1.0 openbrewbyweight",
    ]
    assert not (tmp_path / gateway.CONTROLLER_FILE).exists(), "with several, ./setup asks which one"
    status, lines = scan(cfg, FakeLan({}), tmp_path, home)
    assert status == 1
    assert lines == ["range 192.168.4.0/24 253 9"]
    manual = gateway.load_config(
        {"COMPANION_IP": "192.168.4.240", "OBBW_CONTROLLER_URL": "http://192.168.4.194"}
    )
    nothing = FakeLan({})
    assert scan(manual, nothing, tmp_path, home) == (
        1,
        ["skip OBBW_CONTROLLER_URL chooses the controller"],
    )
    assert not nothing.calls
    docker = gateway.load_config({"COMPANION_IP": "172.17.0.3"})
    assert scan(docker, nothing, tmp_path, home) == (1, ["skip 172.17.0.0/16 is larger than /22"])
    assert not nothing.calls


def small_routes(folder: Path) -> Path:
    """At runtime: a /29 keeps the fake network small."""
    return routes(folder, route("192.168.4.240", "255.255.255.248"))


def run_fallback(
    cfg: gateway.Config,
    lan: FakeLan,
    current: Callable[[], tuple[gateway.Target | None, str]],
    events_wanted: int,
    route_file: Path,
    timeout: float = 3,
) -> list[gateway.Event]:
    events: queue.Queue[gateway.Event] = queue.Queue()
    stop = threading.Event()
    thread = threading.Thread(
        target=gateway.fallback, args=(cfg, current, events, stop, lan, route_file, DELAYS)
    )
    thread.start()
    got: list[gateway.Event] = []
    try:
        while len(got) < events_wanted:
            got.append(events.get(timeout=timeout))
    finally:
        stop.set()
        thread.join(2)
    assert not thread.is_alive()
    return got


def scanned(event: gateway.Event) -> list[gateway.Found]:
    """The controllers a fallback event reports."""
    assert event[0] == "scanned", event
    return event[1]


def test_fallback_searches_without_mdns(tmp_path: Path, logged: list[str]) -> None:
    cfg = gateway.load_config({"COMPANION_IP": "192.168.4.240"})
    lan = FakeLan({"192.168.4.242": "openbrewbyweight"})
    got = run_fallback(cfg, lan, lambda: (None, "manual"), 1, small_routes(tmp_path))
    assert got == [
        (
            "scanned",
            [{"name": "openbrewbyweight", "firmware": "1.1.0", "ip": "192.168.4.242", "port": 80}],
        )
    ]
    assert sorted(ip for ip, _, _ in lan.calls) == [
        f"192.168.4.{n}" for n in (241, 242, 243, 244, 245, 246)
    ]
    assert logged == [
        "mDNS has not found the controller; searching 192.168.4.240/29 (6 addresses)"
    ], logged


def test_fallback_checks_the_stored_controller(tmp_path: Path, logged: list[str]) -> None:
    cfg = gateway.load_config({"COMPANION_IP": "192.168.4.240"})
    small = small_routes(tmp_path)
    target = ("openbrewbyweight", ("192.168.4.242", 80))
    lan = FakeLan({"192.168.4.242": "openbrewbyweight"})
    got = run_fallback(cfg, lan, lambda: (target, "scan"), 2, small)
    assert [scanned(event)[0]["ip"] for event in got] == ["192.168.4.242"] * 2
    assert lan.calls == [("192.168.4.242", 80, gateway.STORED_TIMEOUT_S)] * 2, (
        "a stored controller that answers is checked with one request, no search"
    )

    logged.clear()
    moved = FakeLan({"192.168.4.245": "openbrewbyweight"})
    got = run_fallback(cfg, moved, lambda: (target, "scan"), 1, small)
    assert scanned(got[0])[0]["ip"] == "192.168.4.245"
    assert moved.calls[:1] == [("192.168.4.242", 80, gateway.STORED_TIMEOUT_S)]
    assert logged == [
        "the controller at 192.168.4.242 does not answer; searching 192.168.4.240/29 (6 addresses)"
    ]


def test_fallback_backs_off(tmp_path: Path, logged: list[str]) -> None:
    cfg = gateway.load_config({"COMPANION_IP": "192.168.4.240"})
    empty, stop = FakeLan({}), threading.Event()
    events: queue.Queue[gateway.Event] = queue.Queue()
    thread = threading.Thread(
        target=gateway.fallback,
        args=(cfg, lambda: (None, "manual"), events, stop, empty, small_routes(tmp_path), DELAYS),
    )
    thread.start()
    time.sleep(0.05 + 0.1 + 0.2 + 0.1)  # Three searches, at backed-off intervals.
    stop.set()
    thread.join(2)
    assert events.empty(), len(empty.calls)
    assert len(empty.calls) == 18, len(empty.calls)
    assert (
        len(
            [
                line
                for line in logged
                if line.startswith("no controller answered in 192.168.4.240/29")
            ]
        )
        == 3
    )


def test_fallback_stops(tmp_path: Path, logged: list[str]) -> None:
    """mDNS works, or the network is too large: no search."""
    cfg = gateway.load_config({"COMPANION_IP": "192.168.4.240"})
    small = small_routes(tmp_path)
    target = ("openbrewbyweight", ("192.168.4.242", 80))
    currents: tuple[Callable[[], tuple[gateway.Target | None, str]], ...] = (
        lambda: (target, "mdns"),
        lambda: (None, "manual"),
    )
    for current in currents:
        lan = FakeLan({})
        route_file = (
            small
            if current()[1] == "mdns"
            else routes(tmp_path, route("192.168.0.0", "255.255.0.0"))
        )
        events: queue.Queue[gateway.Event] = queue.Queue()
        stop = threading.Event()
        logged.clear()
        thread = threading.Thread(
            target=gateway.fallback, args=(cfg, current, events, stop, lan, route_file, DELAYS)
        )
        thread.start()
        thread.join(2)
        assert not thread.is_alive(), "mDNS works, or the network is too large"
        assert not lan.calls, "mDNS works, or the network is too large"
        assert events.empty(), "mDNS works, or the network is too large"
    assert logged == [
        "not searching the network for the controller: 192.168.0.0/16 is larger than /22"
    ], logged
