#!/usr/bin/env python3
"""The network search for the controller when mDNS does not find it (offline: localhost only)."""

import contextlib
import importlib.util
import io
import json
import queue
import socket
import struct
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gateway", ROOT / "gateway/gateway.py")
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)
logged = []
gateway.log = logged.append

INFO = {"apiVersion": 1, "name": "openbrewbyweight", "firmwareVersion": "1.1.0+abc", "authRequired": True}
identity = gateway.controller_identity
assert identity(json.dumps(INFO)) == {"name": "openbrewbyweight", "firmware": "1.1.0+abc"}
assert identity(json.dumps({**INFO, "authRequired": False, "extra": 1}))
for wrong in ({**INFO, "apiVersion": 2}, {**INFO, "apiVersion": True}, {**INFO, "apiVersion": "1"},
              {**INFO, "apiVersion": 1.0}, {**INFO, "authRequired": "yes"}, {**INFO, "name": 7},
              {k: v for k, v in INFO.items() if k != "firmwareVersion"}, [INFO], "openbrewbyweight"):
    assert identity(json.dumps(wrong)) is None, wrong
for wrong in (b"", b"<html>router</html>", json.dumps(INFO).encode()[:-1], b"\xff\xfe"):
    assert identity(wrong) is None, wrong
odd = identity(json.dumps({**INFO, "name": " Café\x07 bar ", "firmwareVersion": "1.0 beta\n"}))
assert odd == {"name": "Café bar", "firmware": "1.0beta"}, "names and versions are safe to print"


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.hits = 0
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def answering(status=200, body=json.dumps(INFO).encode(), delay=0, location=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.hits += 1
            self.server.path = self.path
            time.sleep(delay)
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    return Handler


controller = serve(answering())
probe = gateway.probe_controller
assert probe("127.0.0.1", controller.server_port) == {
    "name": "openbrewbyweight", "firmware": "1.1.0+abc", "ip": "127.0.0.1", "port": controller.server_port}
assert (controller.hits, controller.path) == (1, "/api/v1/integration/info"), "exactly one request per host"
elsewhere = serve(answering())
for server in (serve(answering(404)), serve(answering(body=b"<html>NAS</html>")),
               serve(answering(body=json.dumps({**INFO, "apiVersion": 2}).encode())),
               serve(answering(body=b"{" + b" " * 5000 + b"}")),
               serve(answering(302, location=f"http://127.0.0.1:{elsewhere.server_port}/api/v1/integration/info"))):
    assert probe("127.0.0.1", server.server_port) is None and server.hits == 1
assert elsewhere.hits == 0, "a redirect is never followed to another host"
slow = serve(answering(delay=3))
started = time.monotonic()
assert probe("127.0.0.1", slow.server_port) is None and time.monotonic() - started < 2, "1 s timeout"
closed = socket.socket()
closed.bind(("127.0.0.1", 0))
assert probe("127.0.0.1", closed.getsockname()[1]) is None, "a refused connection is no controller"
closed.close()


def route(destination, mask, gateway_ip="0.0.0.0", interface="eth0"):
    hex_ip = lambda ip: "%08X" % struct.unpack("=I", socket.inet_aton(ip))[0]
    return f"{interface}\t{hex_ip(destination)}\t{hex_ip(gateway_ip)}\t0001\t0\t0\t0\t{hex_ip(mask)}\t0\t0\t0"


temporary = tempfile.TemporaryDirectory(prefix="openbrewbyweight-scan-")
folder = Path(temporary.name)


def routes(*lines):
    path = folder / f"route{len(list(folder.glob('route*')))}"
    path.write_text("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
                    + "\n".join(lines) + "\n")
    return path


cfg = gateway.load_config({"COMPANION_IP": "192.168.4.240"})
home = routes(route("0.0.0.0", "0.0.0.0", "192.168.4.1"), route("192.168.0.0", "255.255.0.0"),
              route("192.168.4.0", "255.255.255.0"), route("172.17.0.0", "255.255.0.0", interface="docker0"))
network, hosts, why = gateway.scan_plan(cfg, home)
assert (str(network), why, len(hosts)) == ("192.168.4.0/24", None, 253), "the most specific on-link route"
assert "192.168.4.240" not in hosts and hosts[0] == "192.168.4.1" and hosts[-1] == "192.168.4.254"
assert gateway.scan_seconds(hosts) == 9
network, hosts, why = gateway.scan_plan(cfg, routes(route("192.168.4.0", "255.255.252.0")))
assert why is None and len(hosts) == 1021, "a /22 is the largest network searched"
for lines, reason in (([route("192.168.0.0", "255.255.248.0")], "192.168.0.0/21 is larger than /22"),
                      ([route("192.168.4.0", "255.255.255.0", "192.168.4.1")], "no network interface"),
                      ([route("10.0.0.0", "255.255.255.0")], "no network interface"),
                      ([], "no network interface")):
    network, hosts, why = gateway.scan_plan(cfg, routes(*lines))
    assert hosts == [] and why.startswith(reason), (lines, why)
docker = gateway.load_config({"COMPANION_IP": "172.17.0.3"})
assert gateway.scan_plan(docker, home)[2] == "172.17.0.0/16 is larger than /22", "Docker's bridge is skipped"
public = gateway.load_config({"COMPANION_IP": "203.0.113.7"})
assert gateway.scan_plan(public, routes(route("203.0.113.0", "255.255.255.0")))[2] == \
    "203.0.113.0/24 is not a private home network"
assert gateway.scan_plan(cfg, folder / "missing")[2].startswith("no network interface")


class FakeLan:
    """Answers like controllers at the given addresses; counts probes and how many run at once."""

    def __init__(self, controllers, delay=0.0):
        self.controllers, self.delay, self.lock = controllers, delay, threading.Lock()
        self.calls, self.running, self.peak = [], 0, 0

    def __call__(self, ip, port=80, timeout=gateway.SCAN_TIMEOUT_S):
        with self.lock:
            self.calls.append((ip, port, timeout))
            self.running += 1
            self.peak = max(self.peak, self.running)
        time.sleep(self.delay)
        with self.lock:
            self.running -= 1
        name = self.controllers.get(ip)
        return name and {"name": name, "firmware": "1.1.0", "ip": ip, "port": port}


lan = FakeLan({"192.168.4.194": "openbrewbyweight", "192.168.4.20": "Cafe Bar"}, delay=0.02)
_, hosts, _ = gateway.scan_plan(cfg, home)
found = gateway.scan_hosts(cfg, hosts, lan)
assert [f["ip"] for f in found] == ["192.168.4.20", "192.168.4.194"], "every controller, in address order"
assert sorted(ip for ip, _, _ in lan.calls) == sorted(hosts) and len(lan.calls) == 253, "each host once"
assert lan.peak == gateway.SCAN_WORKERS, f"at most {gateway.SCAN_WORKERS} probes at a time, not {lan.peak}"
named = {**cfg, "controller_name": "cafe bar"}
assert [f["ip"] for f in gateway.scan_hosts(named, hosts, FakeLan(lan.controllers))] == ["192.168.4.20"]


def scan(cfg, lan, route_file=home):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        status = gateway.scan(cfg, folder, lan, route_file)
    return status, out.getvalue().splitlines()


(folder / gateway.CONTROLLER_FILE).unlink(missing_ok=True)
status, lines = scan(cfg, FakeLan({"192.168.4.194": "openbrewbyweight"}))
assert status == 0 and lines == ["range 192.168.4.0/24 253 9", "controller 192.168.4.194 1.1.0 openbrewbyweight"]
assert gateway.remembered_controller(cfg, folder) == (("openbrewbyweight", ("192.168.4.194", 80)), "scan")
(folder / gateway.CONTROLLER_FILE).unlink()
status, lines = scan(cfg, FakeLan(lan.controllers))
assert status == 0 and lines[1:] == ["controller 192.168.4.20 1.1.0 Cafe Bar",
                                     "controller 192.168.4.194 1.1.0 openbrewbyweight"]
assert not (folder / gateway.CONTROLLER_FILE).exists(), "with several, ./setup asks which one"
status, lines = scan(cfg, FakeLan({}))
assert status == 1 and lines == ["range 192.168.4.0/24 253 9"]
manual = gateway.load_config({"COMPANION_IP": "192.168.4.240", "OBBW_CONTROLLER_URL": "http://192.168.4.194"})
nothing = FakeLan({})
assert scan(manual, nothing) == (1, ["skip OBBW_CONTROLLER_URL chooses the controller"]) and not nothing.calls
assert scan(docker, nothing) == (1, ["skip 172.17.0.0/16 is larger than /22"]) and not nothing.calls

# At runtime: a /29 keeps the fake network small; the delays are scaled down from minutes.
small = routes(route("192.168.4.240", "255.255.255.248"))
DELAYS = (0.05, 0.1, 0.2, 0.3)


def run_fallback(cfg, lan, current, events_wanted, timeout=3):
    events, stop = queue.Queue(), threading.Event()
    thread = threading.Thread(target=gateway.fallback, args=(cfg, current, events, stop, lan, small, DELAYS))
    thread.start()
    got = []
    try:
        while len(got) < events_wanted:
            got.append(events.get(timeout=timeout))
    finally:
        stop.set()
        thread.join(2)
    assert not thread.is_alive()
    return got


logged.clear()
lan = FakeLan({"192.168.4.242": "openbrewbyweight"})
got = run_fallback(cfg, lan, lambda: (None, "manual"), 1)
assert got == [("scanned", [{"name": "openbrewbyweight", "firmware": "1.1.0", "ip": "192.168.4.242", "port": 80}])]
assert sorted(ip for ip, _, _ in lan.calls) == [f"192.168.4.{n}" for n in (241, 242, 243, 244, 245, 246)]
assert logged == ["mDNS has not found the controller; searching 192.168.4.240/29 (6 addresses)"], logged

target = ("openbrewbyweight", ("192.168.4.242", 80))
lan = FakeLan({"192.168.4.242": "openbrewbyweight"})
got = run_fallback(cfg, lan, lambda: (target, "scan"), 2)
assert [event[1][0]["ip"] for event in got] == ["192.168.4.242"] * 2
assert lan.calls == [("192.168.4.242", 80, gateway.STORED_TIMEOUT_S)] * 2, "a stored controller that answers is " \
                                                                           "checked with one request, no search"

logged.clear()
moved = FakeLan({"192.168.4.245": "openbrewbyweight"})
got = run_fallback(cfg, moved, lambda: (target, "scan"), 1)
assert got[0][1][0]["ip"] == "192.168.4.245" and moved.calls[0] == ("192.168.4.242", 80, gateway.STORED_TIMEOUT_S)
assert logged == ["the controller at 192.168.4.242 does not answer; searching 192.168.4.240/29 (6 addresses)"]

logged.clear()
empty, events, stop = FakeLan({}), queue.Queue(), threading.Event()
thread = threading.Thread(target=gateway.fallback, args=(cfg, lambda: (None, "manual"), events, stop, empty, small,
                                                         DELAYS))
thread.start()
time.sleep(0.05 + 0.1 + 0.2 + 0.1)  # Three searches, at backed-off intervals.
stop.set()
thread.join(2)
assert events.empty() and len(empty.calls) == 18, len(empty.calls)
assert len([line for line in logged if line.startswith("no controller answered in 192.168.4.240/29")]) == 3

for current in (lambda: (target, "mdns"), lambda: (None, "manual")):
    lan = FakeLan({})
    route_file = small if current()[1] == "mdns" else routes(route("192.168.0.0", "255.255.0.0"))
    events, stop = queue.Queue(), threading.Event()
    logged.clear()
    thread = threading.Thread(target=gateway.fallback, args=(cfg, current, events, stop, lan, route_file, DELAYS))
    thread.start()
    thread.join(2)
    assert not thread.is_alive() and not lan.calls and events.empty(), "mDNS works, or the network is too large"
assert logged == ["not searching the network for the controller: 192.168.0.0/16 is larger than /22"], logged

temporary.cleanup()
print("Network search: identity, probe, range limits, concurrency, setup command and runtime fallback OK")
