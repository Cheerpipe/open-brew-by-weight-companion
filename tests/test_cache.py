"""Web UI cache and routing against a real nginx, a fake controller and a stand-in companion socket.

Needs the image's nginx, so it runs inside the test image (./scripts/dev test).
"""

import asyncio
import base64
import gzip
import hashlib
import http.client
import http.server
import json
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict, cast, override

import aiohttp
from aiohttp import web

import gateway
from companion.assets import UNREGISTER, Assets

if TYPE_CHECKING:
    import pytest

    from companion.service import Companion

NGINX = "/usr/sbin/nginx"  # The image's nginx, run against the rendered configuration.

TAG = "abcd1234"
ASSETS = {"/app.js", "/icons/icon-512.png", "/js/launch.js", "/js/runtime.js", "/js/settings.js"}
SHELLS = {"/", "/stats"}


class State(TypedDict):
    release: str
    requests: list[tuple[str, str | None, str | None]]  # (path, Host, If-None-Match)
    companion: list[tuple[str, str, dict[str, str]]]  # (method, path, headers)
    ui: bool
    tampered: set[str]


state: State = {"release": "1.0.0", "requests": [], "companion": [], "ui": True, "tampered": set()}
lock = threading.Lock()


def shell_body() -> bytes:
    return gzip.compress(f'<html data-fw="{state["release"]}">'.encode(), mtime=0)


def asset_body(path: str) -> bytes:
    return gzip.compress(path.encode(), mtime=0)


def digest(body: bytes) -> str:
    return base64.b64encode(hashlib.sha256(body).digest()).decode()


def asset_list() -> dict[str, object]:
    """What the firmware's generated list says, for its current release."""
    return {
        "v": 1,
        "tag": TAG,
        "etag": f'"{state["release"]}.{TAG}"',
        "csp": "default-src 'self'",
        "shell": [digest(shell_body()), len(shell_body())],
        "shellPaths": sorted(SHELLS),
        "assets": [
            [path, digest(asset_body(path)), len(asset_body(path)), "text/javascript", True]
            for path in sorted(ASSETS)
        ]
        + [["/sw.js", digest(shell_body()), len(shell_body()), "text/javascript", True]],
    }


class Controller(http.server.BaseHTTPRequestHandler):
    """Answers like the firmware's rootHandler and serveWebAsset, with headers worth ignoring."""

    protocol_version = "HTTP/1.1"

    @override
    def log_message(self, format: str, *args: object) -> None:
        pass

    def reply(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", "0" if status == 304 else str(len(body)))
        self.end_headers()
        if status != 304:
            self.wfile.write(body)

    def do_GET(self) -> None:
        with lock:
            state["requests"].append(
                (self.path, self.headers.get("Host"), self.headers.get("If-None-Match"))
            )
        path = self.path.partition("?")[0]
        gzipped = {
            "Content-Encoding": "gzip",
            "Vary": "Accept-Encoding",
            "Cache-Control": "public, max-age=99",
            "Service-Worker-Allowed": "/",
        }
        if path in SHELLS or path == "/sw.js":
            self.reply(200, shell_body(), {**gzipped, "Content-Type": "text/html"})
        elif path in ASSETS:
            time.sleep(0.3)  # Long enough for concurrent misses to overlap.
            body = asset_body(path)
            if path in state["tampered"]:
                body = gzip.compress(b"steal(password)", mtime=0)
            self.reply(200, body, gzipped)
        else:
            self.reply(404, b"", {})


class Reply:
    """A relayed answer, opened: what Relay.request returns."""

    status = 200

    def __init__(self, data: bytes) -> None:
        self.data = data

    def release(self) -> None:
        pass


class StubRelay:
    """The relay as the assets module sees it; its seal is covered by test_relay."""

    client_id = "abcdefabcdefabcd"

    def __init__(self) -> None:
        self.key: bytes | None = b"session 1"
        self.body_key: bytes | None = b"session 1"
        self.mode, self.features, self.is_paired, self.answers = "ready", 1, True, True
        self.http: aiohttp.ClientSession | None = None

    def session(self) -> aiohttp.ClientSession:
        if self.http is None:
            self.http = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(force_close=True), auto_decompress=False
            )
        return self.http

    async def paired(self) -> bool:
        return self.is_paired

    async def renew(self) -> str:
        return self.mode

    async def request(self, *_: object) -> Reply | None:
        return Reply(json.dumps(asset_list()).encode()) if self.answers else None


class StubCompanion:
    def __init__(self, port: int) -> None:
        self.relay, self.port = StubRelay(), port

    def pairing_required(self) -> bool:
        return not self.relay.is_paired

    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


class Standin:
    """The companion service's socket: real assets, with its other routes stood in for."""

    def __init__(self, port: int) -> None:
        self.companion = StubCompanion(port)
        self.assets = Assets(cast("Companion", self.companion))

    async def record(self, request: web.Request) -> None:
        with lock:
            state["companion"].append((request.method, request.path, dict(request.headers)))

    async def gate(self, request: web.Request) -> web.Response:
        await self.record(request)
        if self.companion.pairing_required() and request.headers["X-Original-URI"] != "/sw.js":
            return web.Response(status=401)
        return web.Response(status=204 if state["ui"] else 403)

    async def notice(self, request: web.Request) -> web.Response:
        await self.record(request)
        return web.Response(text="notice", content_type="text/html")

    async def stream(self, request: web.Request) -> web.StreamResponse:
        await self.record(request)
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.close()
        return ws

    async def api(self, request: web.Request) -> web.Response:
        await self.record(request)
        if request.path == "/api/v1/history":
            body = (
                b'{"shots":['
                + b",".join(b'{"id":%d,"doseG":360,"timeMs":28000}' % i for i in range(80))
                + b"]}"
            )
            return web.Response(
                body=body, content_type="application/json", headers={"Cache-Control": "no-store"}
            )
        if request.path == "/api/v1/ota/image":
            return web.Response(body=b"\0" * 4096, content_type="application/octet-stream")
        return web.json_response({"ok": True}, headers={"Cache-Control": "public, max-age=60"})

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/__companion/ui-gate", self.gate)
        app.router.add_get("/__companion/ui-off", self.notice)
        app.router.add_get("/api/v1/ui/ui-stream", self.stream)
        app.router.add_route("*", "/api/{tail:.*}", self.api)
        app.router.add_route("*", "/{tail:.*}", self.assets.serve)
        return app


class Served:
    """The stand-in on the companion's socket, on its own thread and loop."""

    def __init__(self, standin: Standin, socket_path: Path) -> None:
        self.standin, self.socket_path = standin, socket_path
        self.loop = asyncio.new_event_loop()
        self.runner = web.AppRunner(standin.app())
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        asyncio.run_coroutine_threadsafe(self.start(), self.loop).result(5)

    async def start(self) -> None:
        await self.runner.setup()
        await web.UnixSite(self.runner, str(self.socket_path)).start()
        await asyncio.to_thread(self.socket_path.chmod, 0o666)

    async def finish(self) -> None:
        await self.runner.cleanup()
        http = self.standin.companion.relay.http
        if http is not None:
            await http.close()

    def stop(self) -> None:
        asyncio.run_coroutine_threadsafe(self.finish(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]  # (host, port) for AF_INET
        return port


def upstream(path: str) -> list[tuple[str, str | None, str | None]]:
    with lock:
        return [request for request in state["requests"] if request[0] == path]


def test_web_ui_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Web UI cache against nginx."""
    assert Path(NGINX).exists(), "nginx is missing; run this inside the test image"
    monkeypatch.setattr(gateway, "qr_svg", lambda _text: "")
    controller = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Controller)
    controller_port = controller.server_address[1]
    threading.Thread(target=controller.serve_forever, daemon=True).start()

    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-cache-") as temporary:
        Path(temporary).chmod(0o755)  # nginx workers run as the nginx user inside the image.
        data, run = Path(temporary) / "data", Path(temporary) / "run"
        https_port = free_port()
        cfg = gateway.load_config(
            {
                "GATEWAY_IP": "127.0.0.1",
                "HTTP_PORT": str(free_port()),
                "HTTPS_PORT": str(https_port),
            }
        )
        gateway.ensure_certificates(cfg, data)
        gateway.write_site(cfg, data, run, ("Fake", ("127.0.0.1", controller_port)))
        standin = Standin(controller_port)
        relay = standin.companion.relay
        served = Served(standin, run / "companion.sock")
        nginx = subprocess.Popen([NGINX, "-c", str(run / "nginx.conf"), "-g", "daemon off;"])
        try:
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", https_port), timeout=0.1).close()
                    break
                except OSError:
                    time.sleep(0.1)
            context = ssl.create_default_context(cafile=str(data / f"{gateway.CA_NAME}.crt"))
            # The certificate names the gateway, the test dials 127.0.0.1.
            context.check_hostname = False

            def get(path: str, **headers: str) -> tuple[int, dict[str, str], bytes]:
                connection = http.client.HTTPSConnection(
                    "127.0.0.1", https_port, context=context, timeout=15
                )
                connection.request("GET", path, headers={"Accept-Encoding": "gzip", **headers})
                response = connection.getresponse()
                body = response.read()
                connection.close()
                return response.status, {k.lower(): v for k, v in response.getheaders()}, body

            # Current assets: fetched once, then served by the gateway whatever the Accept-Encoding.
            status, headers, body = get(f"/app.js?v={TAG}")
            assert (status, headers["x-gateway-cache"]) == (200, "MISS")
            assert headers["content-encoding"] == "gzip"
            assert gzip.decompress(body) == b"/app.js"
            assert "service-worker-allowed" not in headers, "headers come from the list"
            assert headers["cache-control"] == "public, max-age=31536000, immutable"
            status, headers, body = get(
                f"/app.js?v={TAG}", **{"Accept-Encoding": "gzip, deflate, br, zstd"}
            )
            assert (status, headers["x-gateway-cache"], gzip.decompress(body)) == (
                200,
                "HIT",
                b"/app.js",
            )
            assert len(upstream("/app.js")) == 1
            assert get(f"/app.js?v={TAG}", **{"If-None-Match": f'"{TAG}"'})[0] == 304
            assert len(upstream("/app.js")) == 1, (
                "a browser revalidation is answered by the gateway"
            )

            # Phones loading at once after an OTA: one request reaches the controller.
            results: list[tuple[int, dict[str, str], bytes]] = []
            threads = [
                threading.Thread(target=lambda: results.append(get(f"/js/runtime.js?v={TAG}")))
                for _ in range(5)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            assert [result[0] for result in results] == [200] * 5
            assert len(upstream("/js/runtime.js")) == 1

            # URLs the controller marks no-store are never kept: bare paths and other asset tags.
            for path in ("/app.js", "/app.js?v=old"):
                before = len(upstream("/app.js"))
                assert [get(path)[1]["x-gateway-cache"] for _ in range(2)] == ["MISS", "MISS"]
                assert len(upstream("/app.js")) == before + 2

            # A file only the controller's list names is kept like any other.
            path = f"/icons/icon-512.png?v={TAG}"
            assert [get(path)[1]["x-gateway-cache"] for _ in range(2)] == ["MISS", "HIT"]
            assert len(upstream("/icons/icon-512.png")) == 1

            # Anything else goes to the Web UI each time, and nothing reaches the controller for it.
            for _ in range(2):
                status, headers, _ = get("/evil.js")
                assert (status, headers["location"], headers["x-gateway-cache"]) == (
                    302,
                    "/",
                    "MISS",
                )
            assert not upstream("/evil.js")

            # A changed file never reaches a browser, nor the cache.
            state["tampered"].add("/js/settings.js")
            for _ in range(2):
                status, headers, body = get(f"/js/settings.js?v={TAG}")
                assert status == 502
                assert b"steal" not in body
                assert b"Do not sign in" in body
            assert standin.assets.refused == 2
            assert standin.assets.last_refused == "/js/settings.js"
            state["tampered"].clear()
            status, _, body = get(f"/js/settings.js?v={TAG}")
            assert (status, gzip.decompress(body)) == (200, b"/js/settings.js")

            # A worker left behind is told to go, even at a cached URL; the real one is not.
            worker = {"Service-Worker": "script"}
            status, headers, body = get(f"/app.js?v={TAG}", **worker)
            assert status == 200
            assert body == UNREGISTER
            assert headers["service-worker-allowed"] == "/"
            assert headers["x-gateway-cache"] == "BYPASS"
            assert get(f"/app.js?v={TAG}")[2] != UNREGISTER, "the cache is untouched"
            assert get("/evil.js", **worker)[2] == UNREGISTER
            assert get("/api/v1/x.js", **worker)[0] == 200, "the API is not a place for a worker"
            assert get("/sw.js", **worker)[2] == shell_body()

            # The API goes to the companion with the browser's address, never cached; its own
            # routes never do.
            for _ in range(2):
                status, headers, _ = get("/api/v1/status", **{"X-Real-IP": "6.6.6.6"})
                assert status == 200
                assert "x-gateway-cache" not in headers
            api = [request for request in state["companion"] if request[1] == "/api/v1/status"]
            assert len(api) == 2
            assert api[0][2]["X-Real-IP"] == "127.0.0.1"
            assert not upstream("/api/v1/status")

            # Dynamic JSON answers leave compressed for screens that accept it; a
            # screen that does not, and firmware update bytes, stay untouched.
            history = (
                b'{"shots":['
                + b",".join(b'{"id":%d,"doseG":360,"timeMs":28000}' % i for i in range(80))
                + b"]}"
            )
            status, headers, body = get("/api/v1/history")
            assert status == 200
            assert headers["content-encoding"] == "gzip"
            assert gzip.decompress(body) == history
            assert headers["vary"] == "Accept-Encoding"
            assert len(body) < len(history) / 4
            status, headers, body = get("/api/v1/history", **{"Accept-Encoding": "identity"})
            assert status == 200
            assert "content-encoding" not in headers
            assert body == history
            status, headers, body = get("/api/v1/ota/image")
            assert status == 200
            assert "content-encoding" not in headers
            assert body == b"\0" * 4096
            assert get("/api/v1/companion/pair")[0] == 404
            assert get("/api/v1/companion/relay")[0] == 404
            assert get("/api/v1/companion/admin")[0] == 200, (
                "Admin → Companion's actions are relayed"
            )
            assert not [
                request
                for request in state["companion"]
                if request[1].startswith("/api/v1/companion/p")
            ]

            # Live updates: the upgrade reaches the companion.
            connection = http.client.HTTPSConnection(
                "127.0.0.1", https_port, context=context, timeout=15
            )
            connection.request(
                "GET",
                "/api/v1/ui/ui-stream",
                headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Key": base64.b64encode(b"0123456789abcdef").decode(),
                },
            )
            assert connection.getresponse().status == 101
            connection.close()
            stream = [
                request for request in state["companion"] if request[1] == "/api/v1/ui/ui-stream"
            ]
            assert stream
            assert stream[0][2]["Upgrade"] == "websocket"
            assert stream[0][2]["X-Real-IP"] == "127.0.0.1"

            # The shell is revalidated on every load, without the controller when unchanged...
            status, headers, body = get("/")
            assert (status, headers["x-gateway-cache"]) == (200, "MISS")
            assert b"1.0.0" in gzip.decompress(body)
            assert headers["content-security-policy"] == "default-src 'self'"
            assert headers["cache-control"] == "public, max-age=86400, stale-if-error=604800"
            assert "x-accel-expires" not in headers
            get("/sw.js")
            fetched = len(upstream("/"))
            time.sleep(2.1)  # Past the 1 s validity, counted in whole seconds.
            status, headers, body = get("/")
            assert (status, headers["x-gateway-cache"]) == (200, "REVALIDATED")
            assert b"1.0.0" in gzip.decompress(body)
            assert len(upstream("/")) == fetched
            # ...and the new copy right after an OTA, whose reboot starts a new relay session.
            state["release"] = "1.1.0"
            relay.body_key = b"session 2"
            time.sleep(2.1)  # Past the 1 s validity, counted in whole seconds.
            status, headers, body = get("/")
            assert status == 200
            assert b"1.1.0" in gzip.decompress(body)
            assert headers["etag"] == f'"1.1.0.{TAG}"'

            # The Web UI through the companion turned off: pages show the companion's notice
            # instead.
            state["ui"] = False
            shells = len(upstream("/stats"))
            status, _, body = get("/stats")
            assert (status, body) == (200, b"notice")
            assert len(upstream("/stats")) == shells
            gates = [
                request for request in state["companion"] if request[1] == "/__companion/ui-gate"
            ]
            assert gates[-1][2]["X-Original-URI"] == "/stats"
            state["ui"] = True

            # A controller from before the list works, unverified, and still with known headers.
            relay.features = 0
            status, headers, body = get("/stats?legacy=1")
            assert (status, gzip.decompress(body)[:5]) == (200, b"<html")
            assert "service-worker-allowed" not in headers
            shells = len(upstream("/stats?legacy=1"))
            for path in ("/stats?legacy=1", "/stats?legacy=1", f"/app.js?v={TAG}new"):
                status, headers, _ = get(path)
                assert (status, headers["x-gateway-cache"]) == (200, "MISS"), path
            assert len(upstream("/stats?legacy=1")) == shells + 2, "nginx keeps nothing unverified"
            relay.features = 1

            # Before pairing every page leads to the companion's, even one nginx holds in its
            # cache, nothing reaches the controller, and a worker from an earlier pairing goes.
            relay.is_paired = False
            before = len(state["requests"])
            for path in ("/", "/stats", "/settings", "/app.js?v=old", "/evil.js"):
                status, headers, _ = get(path)
                assert (status, headers["location"]) == (302, "/__companion/?pair=1"), path
                assert headers["cache-control"] == "no-store", path
            for path in ("/sw.js", "/evil.js", f"/app.js?v={TAG}"):
                status, _, body = get(path, **worker)
                assert (status, body) == (200, UNREGISTER), path
            assert len(state["requests"]) == before
            relay.is_paired = True
            status, _, body = get("/")
            assert status == 200, "pairing again opens it, from the same cache"

            # Controller off: the last shell, worker and assets still load; nothing else does.
            controller.shutdown()
            controller.server_close()
            relay.body_key, relay.answers = None, False
            time.sleep(2.1)  # Past the 1 s validity, counted in whole seconds.
            status, headers, body = get("/")
            assert (status, headers["x-gateway-cache"]) == (200, "REVALIDATED")
            assert b"1.1.0" in gzip.decompress(body)
            assert get(f"/app.js?v={TAG}")[1]["x-gateway-cache"] == "HIT"
            standin.assets.listing = None  # A restarted companion: only its cache still knows.
            time.sleep(2.1)
            status, headers, body = get("/")
            assert (status, headers["x-gateway-cache"]) == (200, "STALE")
            assert b"1.1.0" in gzip.decompress(body)
            assert get("/sw.js")[1]["x-gateway-cache"] == "STALE"
            assert get("/stats")[0] == 503, "a page never loaded through the gateway has no copy"

            assert {host for _, host, _ in state["requests"]} == {f"127.0.0.1:{controller_port}"}
        finally:
            nginx.terminate()
            nginx.wait()
            served.stop()
