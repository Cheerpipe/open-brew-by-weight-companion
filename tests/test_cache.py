"""Web UI cache and routing against a real nginx, a fake controller and a stand-in companion socket.

Needs the image's nginx, so it runs inside the test image (./scripts/dev test).
"""

import base64
import gzip
import hashlib
import http.client
import http.server
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict, override

import gateway

if TYPE_CHECKING:
    import pytest

TAG = "abcd1234"
ASSETS = {"/app.js", "/js/runtime.js"}
SHELLS = {"/", "/stats"}


class State(TypedDict):
    release: str
    requests: list[tuple[str, str | None, str | None]]  # (path, Host, If-None-Match)
    companion: list[tuple[str, str, dict[str, str]]]  # (method, path, headers)
    ui: bool


state: State = {"release": "1.0.0", "requests": [], "companion": [], "ui": True}
lock = threading.Lock()


def shell_body() -> bytes:
    return gzip.compress(f'<html data-fw="{state["release"]}">'.encode())


class Controller(http.server.BaseHTTPRequestHandler):
    """Answers like the firmware's rootHandler and serveWebAsset, plus one API route."""

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
        path, _, query = self.path.partition("?")
        gzipped = {"Content-Encoding": "gzip", "Vary": "Accept-Encoding"}
        if path == "/api/v1/status":
            self.reply(
                200,
                b'{"ok":true}',
                {"Content-Type": "application/json", "Cache-Control": "public, max-age=60"},
            )
        elif path in SHELLS or path == "/sw.js":
            etag = f'"{state["release"]}.{TAG}"'
            control = (
                "no-cache" if path == "/sw.js" else "public, max-age=86400, stale-if-error=604800"
            )
            status = 304 if self.headers.get("If-None-Match") == etag else 200
            self.reply(status, shell_body(), {**gzipped, "Cache-Control": control, "ETag": etag})
        elif path in ASSETS:
            time.sleep(0.3)  # Long enough for concurrent misses to overlap.
            current = query == f"v={TAG}"
            headers = {
                **gzipped,
                "Cache-Control": "public, max-age=31536000, immutable" if current else "no-store",
            }
            if current:
                headers["ETag"] = f'"{TAG}"'
            self.reply(200, gzip.compress(path.encode()), headers)
        else:
            self.reply(404, b"", {})


class Companion(http.server.BaseHTTPRequestHandler):
    """The companion service's socket: the Web UI gate and notice, the API and the live updates."""

    protocol_version = "HTTP/1.1"

    @override
    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        with lock:
            state["companion"].append((self.command, self.path, dict(self.headers)))
        if self.path == "/__companion/ui-gate":
            self.send_response(204 if state["ui"] else 403)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.headers.get("Upgrade", "").lower() == "websocket":
            accept = base64.b64encode(
                hashlib.sha1(
                    (
                        self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                    ).encode()
                ).digest()
            )
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept.decode())
            self.end_headers()
            self.close_connection = True
        elif self.path == "/api/v1/history":
            body = (
                b'{"shots":['
                + b",".join(b'{"id":%d,"doseG":360,"timeMs":28000}' % i for i in range(80))
                + b"]}"
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/v1/ota/image":
            body = b"\0" * 4096
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"notice" if self.path == "/__companion/ui-off" else b'{"ok":true}'
            self.send_response(200)
            self.send_header(
                "Content-Type", "text/html" if body == b"notice" else "application/json"
            )
            self.send_header("Cache-Control", "public, max-age=60")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self) -> None:
        self.do_GET()


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
    assert Path(gateway.NGINX).exists(), "nginx is missing; run this inside the test image"
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
        companion = socketserver.ThreadingUnixStreamServer(str(run / "companion.sock"), Companion)
        (run / "companion.sock").chmod(0o666)
        threading.Thread(target=companion.serve_forever, daemon=True).start()
        nginx = subprocess.Popen(
            [gateway.NGINX, "-c", str(run / "nginx.conf"), "-g", "daemon off;"]
        )
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
            status, headers, body = get(
                f"/app.js?v={TAG}", **{"Accept-Encoding": "gzip, deflate, br, zstd"}
            )
            assert (status, headers["x-gateway-cache"], gzip.decompress(body)) == (
                200,
                "HIT",
                b"/app.js",
            )
            assert len(upstream(f"/app.js?v={TAG}")) == 1
            assert get(f"/app.js?v={TAG}", **{"If-None-Match": f'"{TAG}"'})[0] == 304
            assert len(upstream(f"/app.js?v={TAG}")) == 1, (
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
            assert len(upstream(f"/js/runtime.js?v={TAG}")) == 1

            # URLs the controller marks no-store are never kept: bare paths and other asset tags.
            for path in ("/app.js", "/app.js?v=old"):
                assert [get(path)[1]["x-gateway-cache"] for _ in range(2)] == ["MISS", "MISS"]
                assert len(upstream(path)) == 2

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

            # The shell is revalidated on every load: a 304 from the controller when unchanged...
            status, headers, body = get("/")
            assert (status, headers["x-gateway-cache"]) == (200, "MISS")
            assert b"1.0.0" in gzip.decompress(body)
            get("/sw.js")
            time.sleep(2.1)  # Past the 1 s validity, counted in whole seconds.
            status, headers, body = get("/")
            assert (status, headers["x-gateway-cache"]) == (200, "REVALIDATED")
            assert b"1.0.0" in gzip.decompress(body)
            assert upstream("/")[-1][2] == f'"1.0.0.{TAG}"'
            # ...and the new copy right after an OTA.
            state["release"] = "1.1.0"
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

            # Controller off: the last shell, worker and assets still load; nothing else does.
            controller.shutdown()
            controller.server_close()
            time.sleep(2.1)  # Past the 1 s validity, counted in whole seconds.
            status, headers, body = get("/")
            assert (status, headers["x-gateway-cache"]) == (200, "STALE")
            assert b"1.1.0" in gzip.decompress(body)
            assert get("/sw.js")[1]["x-gateway-cache"] == "STALE"
            assert get(f"/app.js?v={TAG}")[1]["x-gateway-cache"] == "HIT"
            assert get("/stats")[0] == 502, "a page never loaded through the gateway has no copy"

            assert {host for _, host, _ in state["requests"]} == {f"127.0.0.1:{controller_port}"}
        finally:
            nginx.terminate()
            nginx.wait()
            companion.shutdown()
            companion.server_close()
