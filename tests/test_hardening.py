"""What a device on the LAN or a malformed answer must not be able to do: erase a pairing, stand in
for the controller, read past a size limit, end a background task, or leave half a certificate."""

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography import x509
from cryptography.exceptions import InvalidTag
from test_gateway import BASE, TXT
from test_relay import ID, SECRET, Idle, V
from zeroconf import BadTypeInNameException, ServiceStateChange

import fake_controller
import gateway
from companion import crypto, lamarzocco, service
from companion import relay as relay_module
from companion.assets import UNREGISTER, parse_listing
from companion.lamarzocco import Installation, LaMarzocco, stomp_frame
from companion.service import OPEN_ACCESS, Companion, web_app
from companion.store import Store

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).resolve().parents[1]
CLIENT = {"X-WebUI-Client": "abcdefabcdefabcd", "X-WebUI-Session": "attacker"}
type Target = tuple[str, tuple[str, int]]


class Info:
    """What Zeroconf answers about a service."""

    server = "micra.local."
    properties = TXT

    def __init__(self, address: str, port: int) -> None:
        self.address, self.port = address, port

    def parsed_addresses(self, _version: object) -> list[str]:
        return [self.address]


def target_of(server: TestServer) -> Target:
    assert server.port is not None
    return ("Cafe Bar", ("127.0.0.1", server.port))


def dead_target() -> Target:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return ("Cafe Bar", ("127.0.0.1", port))


class Rig:
    """A paired companion, with its pages served, and the fake controller it talks to."""

    def __init__(self, data: Path) -> None:
        self.data = data
        self.fake = fake_controller.Controller(SECRET, ID)
        self.server = TestServer(self.fake.app(), host="127.0.0.1")

    async def __aenter__(self) -> Rig:
        store = Store(self.data)
        store.write("identity", {"id": ID, "key": "11" * 32})
        store.save_pairing(SECRET, "Cafe Bar")
        await self.server.start_server()
        self.http = aiohttp.ClientSession()
        self.companion = Companion("Kitchen server", self.data, self.http, Idle)
        await self.companion.open_log()
        self.companion.set_controller(target_of(self.server))
        await self.companion.relay.handshake()
        await asyncio.sleep(0.05)  # The handshake set_controller started has ended too.
        self.client = TestClient(TestServer(web_app(self.companion)))
        await self.client.start_server()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.client.close()
        await self.server.close()
        await self.http.close()
        await self.companion.relay.close()
        await self.companion.logs.close()


def test_anonymous_pair_keeps_a_working_pairing(tmp_path: Path) -> None:
    """F-01: the page's Pair and Erase cannot end a pairing, even with the controller off."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            companion = rig.companion
            companion.set_controller(dead_target())
            reply = await rig.client.post("/__companion/pair", json={})
            assert reply.status == 409, "a working pairing is not asked for again"
            assert companion.pairing.state == "paired"
            reply = await rig.client.post("/__companion/erase", json={})
            assert reply.status == 409
            assert companion.store.pairing() is not None
            reply = await rig.client.get("/__companion/")
            assert reply.headers["X-Frame-Options"] == "DENY", "never inside another page's frame"
            companion.pairing.state = "not_recognized"  # The one pairing the page may end.
            reply = await rig.client.post("/__companion/erase", json={})
            assert reply.status == 200
            assert companion.store.pairing() is None

    asyncio.run(scenario())


def test_each_pairing_attempt_has_its_own_key(tmp_path: Path) -> None:
    """F-06: a key seen in one attempt says nothing about the next. F-22: a request's time is
    bounded whatever the answer claims."""

    async def scenario() -> None:
        requests: list[dict[str, str]] = []
        controller_key = crypto.b64(crypto.public_point(crypto.new_key()))

        async def post(request: web.Request) -> web.Response:
            requests.append(await request.json())
            return web.json_response(
                {"state": "pending", "controllerKey": controller_key, "expiresInS": 1e300},
                status=202,
            )

        async def get(_request: web.Request) -> web.Response:
            return web.json_response({"state": "denied"})

        app = web.Application()
        app.router.add_post("/api/v1/companion/pair", post)
        app.router.add_get("/api/v1/companion/pair", get)
        server = TestServer(app, host="127.0.0.1")
        await server.start_server()
        Store(tmp_path).write("identity", {"id": ID, "key": "11" * 32})
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", tmp_path, http, Idle)
            companion.controller = target_of(server)
            for _ in range(2):
                assert companion.pairing.start(manual=True)
                await asyncio.sleep(0.2)
                assert companion.pairing.expires_at - time.monotonic() <= 600
                task = companion.pairing.task
                assert task is not None
                await task
            await companion.relay.close()
        await server.close()
        commitments = [r["commitment"] for r in requests if "commitment" in r]
        reveals = [r["publicKey"] for r in requests if "publicKey" in r]
        assert len(set(commitments)) == 2
        assert len(set(reveals)) == 2

    asyncio.run(scenario())


def test_a_new_address_must_prove_the_pairing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-02: an impostor at a new address is never adopted, and its answers open nothing."""

    async def scenario() -> None:
        monkeypatch.setattr(service, "PROVE_RETRY_S", (0,))
        async with Rig(tmp_path) as rig:
            companion, answers = rig.companion, list[bool]()

            async def busy(_request: web.Request) -> web.Response:
                return web.json_response({"error": "BUSY"}, status=503)

            async def forged(_request: web.Request) -> web.Response:
                return web.json_response(
                    {"loginRequired": False, "signedIn": True, "adminUnlocked": True}
                )

            app = web.Application()
            app.router.add_get("/api/v1/companion/relay", busy)
            app.router.add_route("*", "/api/{tail:.*}", forged)
            impostor = TestServer(app, host="127.0.0.1")
            await impostor.start_server()
            await companion.prove(target_of(impostor), answers.append)
            await companion.prove(target_of(rig.server), answers.append)
            await companion.prove(dead_target(), answers.append)
            assert answers == [False, True, False]

            await companion.relay.handshake()
            companion.set_controller(target_of(impostor))
            assert companion.relay.key is None, "the old keys never sign for a new address"
            await asyncio.sleep(0.1)
            reply = await rig.client.get("/__companion/log", headers=CLIENT)
            assert reply.status == 401
            assert not await companion.logs.grants()
            await impostor.close()

    asyncio.run(scenario())


def test_prove_answers_for_a_forgotten_companion(tmp_path: Path) -> None:
    """A controller that forgot this companion still proves the secret, so the erase can arrive."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            base = rig.companion.base_url()
            rig.fake.mode = "forgotten"
            assert await rig.companion.relay.proves(base)
            rig.fake.mode = "bad_erase"
            assert not await rig.companion.relay.proves(base)
            rig.fake.mode = "bad_proof"
            assert not await rig.companion.relay.proves(base)
            rig.fake.mode = "ok"
            assert await rig.companion.relay.proves(base)

    asyncio.run(scenario())


def test_prove_needs_nothing_before_pairing(tmp_path: Path) -> None:
    async def scenario() -> None:
        Store(tmp_path).write("identity", {"id": ID, "key": "11" * 32})
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", tmp_path, http, Idle)
            assert await companion.relay.proves("http://127.0.0.1:9")
            await companion.relay.close()

    asyncio.run(scenario())


def test_a_relayed_success_must_be_sealed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """F-02: whole JSON that claims success without a seal is refused; a refusal passes."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:

            def plain(
                _identity: fake_controller.Identity | None, payload: object, status: int = 200
            ) -> web.Response:
                return web.json_response(payload, status=status)

            monkeypatch.setattr(rig.fake, "answer", plain)
            reply = await rig.client.get("/api/v1/status/admin", headers=CLIENT)
            assert reply.status == 409, "a refusal grants nothing and passes as it came"
            rig.fake.active = CLIENT["X-WebUI-Client"]
            reply = await rig.client.get("/api/v1/status/admin", headers=CLIENT)
            assert reply.status == 502
            assert rig.companion.relay.key is None, "the next request makes a new session"

    asyncio.run(scenario())


def test_a_sealed_answer_opens_once() -> None:
    """F-02: the replay window, across its floor."""

    relay = relay_module.Relay(cast("Companion", None))
    key = bytes(32)
    relay.body_key = key
    assert relay._fresh(key, 1)
    assert not relay._fresh(key, 1), "the same answer again"
    assert relay._fresh(bytes(31) + b"\1", 1), "the session before this one is not tracked"
    for counter in range(2, relay_module.ANSWER_WINDOW + 3):
        assert relay._fresh(key, counter)
    assert not relay._fresh(key, 1), "below the window is old, not late"
    assert not relay._fresh(key, relay.answers_floor)


def test_answers_are_read_up_to_a_limit(tmp_path: Path) -> None:
    """F-09: chunked JSON has no length to check, so the read itself stops. Streamed JSON from the
    controller still passes through."""

    async def scenario() -> None:
        async def endless(request: web.Request) -> web.StreamResponse:
            answer = web.StreamResponse(headers={"Content-Type": "application/json"})
            answer.enable_chunked_encoding()
            await answer.prepare(request)
            for _ in range(8):
                await answer.write(b" " * (32 * 1024))
            await answer.write_eof()
            return answer

        app = web.Application()
        app.router.add_get("/endless", endless)
        server = TestServer(app, host="127.0.0.1")
        await server.start_server()
        url = f"http://127.0.0.1:{server.port}/endless"
        Store(tmp_path).write("identity", {"id": ID, "key": "11" * 32})
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", tmp_path, http, Idle)
            assert await companion.controller_request("GET", url) == (200, {})
            async with http.get(url) as reply:
                with pytest.raises(ValueError, match="too large"):
                    await relay_module.read_capped(reply)
            async with http.get(url) as reply:
                assert len(await relay_module.read_capped(reply, 1 << 20)) == 8 * 32 * 1024
            await companion.relay.close()
        await server.close()

    asyncio.run(scenario())


class Quiet:
    def account(self, _ok: bool) -> None: ...
    def upstream(self) -> None: ...
    def subscribed(self) -> None: ...
    def pushed(self, *_: object) -> None: ...
    def polled(self, *_: object) -> None: ...
    def renewed(self) -> None: ...


@pytest.mark.parametrize("body", ["[" * 200000, "x" * 4096])
def test_a_malformed_cloud_message_ends_only_its_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    """F-20: too deep to parse, or a frame that never ends: reconnect, never stop following."""

    async def scenario() -> None:
        monkeypatch.setattr(lamarzocco, "RETRY_S", (0,))
        monkeypatch.setattr(lamarzocco, "MAX_ANSWER_BYTES", 1024)
        connections = [0]

        async def socket(request: web.Request) -> web.WebSocketResponse:
            connections[0] += 1
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            await ws.receive()
            await ws.send_str(stomp_frame("CONNECTED", {"version": "1.2"}))
            await ws.receive()
            if body[0] == "[":
                await ws.send_str(
                    stomp_frame(
                        "MESSAGE",
                        {"destination": "/ws/sn/SER/dashboard", "subscription": "companion"},
                        body,
                    )
                )
            else:
                await ws.send_str(body)
            await asyncio.sleep(1)
            return ws

        app = web.Application()
        app.router.add_get("/ws", socket)
        server = TestServer(app, host="127.0.0.1")
        await server.start_server()
        async with aiohttp.ClientSession() as http:
            follower = LaMarzocco(
                Store(tmp_path),
                http,
                cast("lamarzocco.Events", Quiet()),
                api_root=f"http://127.0.0.1:{server.port}",
                ws_url=f"ws://127.0.0.1:{server.port}/ws",
            )
            follower.configure({"email": "e", "password": "p", "serial": "SER"}, "ws", True)
            follower.access, follower.issued_at = "token", time.monotonic()
            follower.installation = Installation(crypto.new_key())
            for _ in range(200):
                if connections[0] >= 2:
                    break
                await asyncio.sleep(0.02)
            follower.stop()
        await server.close()
        assert connections[0] >= 2

    asyncio.run(scenario())


def test_open_access_is_one_grant_that_ends_with_the_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-21: with the login off nothing per browser is kept, and the login ends what it allowed."""

    async def scenario() -> None:
        monkeypatch.setattr(service, "LOG_ACCESS_RECHECK_S", 0)
        async with Rig(tmp_path) as rig:
            sealed, auth = rig.fake.answer, {"loginRequired": False}

            def answer(
                identity: fake_controller.Identity | None, payload: object, status: int = 200
            ) -> web.Response:
                return sealed(identity, auth if payload == {"login": False} else payload, status)

            monkeypatch.setattr(rig.fake, "answer", answer)
            companion = rig.companion
            companion.device_id = "device"
            for number in range(3):
                reply = await rig.client.get(
                    "/__companion/log/boots", headers={"X-WebUI-Session": f"browser{number}"}
                )
                assert reply.status == 200
            assert set(await companion.logs.grants()) == {OPEN_ACCESS}

            auth.clear()
            auth.update(loginRequired=True, signedIn=False)
            reply = await rig.client.get(
                "/__companion/log/boots", headers={"X-WebUI-Session": "browser0"}
            )
            assert reply.status == 401
            assert not await companion.logs.grants()

            # With the controller off, what it last said stands: login off opens the history...
            companion.log_grants[OPEN_ACCESS] = 0
            companion.log_unreachable = 0
            companion.set_controller(dead_target())
            await asyncio.sleep(0.05)
            reply = await rig.client.get("/__companion/log/boots")
            assert reply.status == 200
            # ...and turning the login on through the companion ends that at once.
            await companion.forget_open_access()
            companion.log_unreachable = time.time()
            reply = await rig.client.get("/__companion/log/boots")
            assert reply.status == 401

    asyncio.run(scenario())


def test_discovery_answers_stay_on_this_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-02: an mDNS answer never moves the controller to this host or another network."""
    cfg = gateway.load_config(BASE)
    monkeypatch.setattr(gateway, "lan_network", lambda _ip: None)
    assert gateway.on_link(cfg, "10.1.2.3")
    assert not gateway.on_link(cfg, "127.0.0.1")
    assert not gateway.on_link(cfg, str(ipaddress.IPv4Address(0)))
    network = ipaddress.IPv4Network("192.168.1.0/24")
    monkeypatch.setattr(gateway, "lan_network", lambda _ip: network)
    assert gateway.on_link(cfg, "192.168.1.50")
    assert not gateway.on_link(cfg, "10.1.2.3")
    assert gateway.match_controller(cfg, "Cafe Bar", "cafe-bar.local.", TXT, ["127.0.0.1"], 80) == (
        None,
        "no IPv4 address",
    )


def test_certificates_survive_a_kill(tmp_path: Path) -> None:
    """F-25: half a CA certificate starts over instead of a crash loop; a key that does not match
    its certificate is issued again; nothing temporary stays behind."""
    cfg = gateway.load_config(BASE)
    assert gateway.ensure_certificates(cfg, tmp_path) is True
    assert not list(tmp_path.glob("*.tmp"))
    leaf, key = tmp_path / "server.crt", tmp_path / "server.key"
    assert gateway.leaf_matches(leaf, key)
    assert (key.stat().st_mode & 0o077) == 0
    key.write_bytes((tmp_path / f"{gateway.CA_NAME}.key").read_bytes())
    assert not gateway.leaf_matches(leaf, key)
    assert gateway.ensure_certificates(cfg, tmp_path) is True
    assert gateway.leaf_matches(leaf, key)
    assert not gateway.leaf_matches(tmp_path / "missing.crt", key)

    ca = tmp_path / f"{gateway.CA_NAME}.crt"
    ca.write_bytes(ca.read_bytes()[:40])
    assert gateway.read_ca(ca) is None
    assert gateway.ensure_certificates(cfg, tmp_path) is True
    assert isinstance(gateway.read_ca(ca), x509.Certificate)


def test_a_device_name_stays_on_one_env_line(tmp_path: Path) -> None:
    """F-24: a name with a literal backslash-n is text, not a second setting."""
    bash = shutil.which("bash")
    assert bash
    (tmp_path / ".env").write_text("A=1\n# OBBW_CONTROLLER_NAME=\n")
    script = (
        f'eval "$(sed -n "/^env_set()/,/^}}/p" "{ROOT / "setup"}")"; '
        'env_set OBBW_CONTROLLER_NAME "$NAME"; env_set NEW "x y"'
    )
    subprocess.run(
        [bash, "-c", script],
        cwd=tmp_path,
        check=True,
        env={**os.environ, "NAME": "Kitchen\\nCOMPANION_DATA=/"},
    )
    assert (tmp_path / ".env").read_text() == (
        "A=1\nOBBW_CONTROLLER_NAME=Kitchen\\nCOMPANION_DATA=/\nNEW=x y\n"
    )


def test_the_supervisor_moves_only_to_a_proved_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-02, F-10: discovery's answers go through the proof, and a malformed one is only skipped."""
    told: list[Target | None] = []
    asked: list[tuple[str, int]] = []
    infos: dict[str, Info | Exception] = {}
    handlers: list[Callable[..., None]] = []
    type_name = "_http._tcp.local."

    class Handle:
        def controller(self, target: Target | None) -> None:
            told.append(target)

        def prove(self, target: Target, done: Callable[[bool], object]) -> None:
            asked.append(target[1])
            done(target[1][0] != "192.168.1.66")

        def stop(self) -> None: ...

    class Zeroconf:
        def __init__(self, **_: object) -> None: ...
        def add_listener(self, *_: object) -> None: ...
        def close(self) -> None: ...

        def get_service_info(self, _type: str, name: str, timeout: int = 0) -> Info:
            assert timeout
            info = infos[name]
            if isinstance(info, Exception):
                raise info
            return info

    class Browser:
        def __init__(self, _zc: object, _type: str, handlers: list[Callable[..., None]]) -> None:
            outer.extend(handlers)

        def cancel(self) -> None: ...

    outer = handlers
    data, run = tmp_path / "data", tmp_path / "run"
    data.mkdir()
    run.mkdir()
    monkeypatch.setattr(gateway, "DATA", data)
    monkeypatch.setattr(gateway, "RUN", run)
    monkeypatch.setattr(gateway, "start_companion", lambda *_: Handle())
    monkeypatch.setattr(gateway, "Zeroconf", Zeroconf)
    monkeypatch.setattr(gateway, "ServiceBrowser", Browser)
    monkeypatch.setattr(gateway, "lan_network", lambda _ip: None)
    monkeypatch.setattr(sys, "argv", ["gateway.py"])
    monkeypatch.setenv("COMPANION_IP", BASE["COMPANION_IP"])
    monkeypatch.setenv("COMPANION_MDNS_PUBLISH", "false")

    def announce(address: str | Exception, port: int = 80) -> None:
        name = "Micra." + type_name
        infos[name] = address if isinstance(address, Exception) else Info(address, port)
        handlers[0](Zeroconf(), type_name, name, ServiceStateChange.Updated)
        time.sleep(0.2)

    def upstream() -> str:
        return (run / "status.json").read_text()

    def drive() -> None:
        while not handlers:
            time.sleep(0.01)
        announce("192.168.1.50")
        checks["adopted"] = told[-1] == ("Micra", ("192.168.1.50", 80))
        checks["nginx"] = "192.168.1.50" in upstream()
        announce("192.168.1.66")
        checks["impostor"] = told[-1][1][0] == "192.168.1.50" if told[-1] else False
        checks["kept"] = "192.168.1.66" not in upstream()
        announce("127.0.0.1", 8123)
        checks["loopback"] = ("127.0.0.1", 8123) not in asked
        announce(BadTypeInNameException("x._ipp._tcp.local."))
        announce("192.168.1.51")
        checks["moved"] = told[-1] == ("Micra", ("192.168.1.51", 80))
        os.kill(os.getpid(), signal.SIGTERM)

    checks: dict[str, bool] = {}
    previous = signal.getsignal(signal.SIGTERM)
    threading.Thread(target=drive, daemon=True).start()
    try:
        with pytest.raises(SystemExit):
            gateway.main()
    finally:
        signal.signal(signal.SIGTERM, previous)
    assert checks == dict.fromkeys(
        ("adopted", "nginx", "impostor", "kept", "loopback", "moved"), True
    )
    assert ("192.168.1.66", 80) in asked


def test_api_answers_cannot_become_pages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """F-35: HTML from the controller's address never reaches a browser; only known headers do."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            rig.fake.active = CLIENT["X-WebUI-Client"]
            sealed = rig.fake.answer

            def html(
                _identity: fake_controller.Identity | None, _payload: object, status: int = 200
            ) -> web.Response:
                return web.Response(status=status, text="<script>", content_type="text/html")

            monkeypatch.setattr(rig.fake, "answer", html)
            reply = await rig.client.get("/api/v1/status/admin", headers=CLIENT)
            assert reply.status == 502
            assert "<script>" not in await reply.text()

            def planted(
                identity: fake_controller.Identity | None, payload: object, status: int = 200
            ) -> web.Response:
                answer = sealed(identity, payload, status)
                answer.headers["Service-Worker-Allowed"] = "/"
                answer.headers["Clear-Site-Data"] = '"*"'
                return answer

            monkeypatch.setattr(rig.fake, "answer", planted)
            reply = await rig.client.get("/api/v1/status/admin", headers=CLIENT)
            assert reply.status == 200
            assert "Service-Worker-Allowed" not in reply.headers
            assert "Clear-Site-Data" not in reply.headers
            assert reply.headers["X-Content-Type-Options"] == "nosniff"
            assert reply.headers["Content-Security-Policy"] == "sandbox"
            assert reply.headers["Cache-Control"] == "no-store"

            reply = await rig.client.get("/api/v1/debug/export", headers=CLIENT)
            assert reply.status == 200, "a download keeps its name and its encoding"
            assert "attachment" in reply.headers["Content-Disposition"]
            assert reply.headers["Content-Encoding"] == "gzip"
            assert "Content-Security-Policy" not in reply.headers

    asyncio.run(scenario())


def test_an_answer_held_back_opens_for_no_other_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-34: someone in the middle keeps a victim's sealed sign-in answer and delivers it for their
    own request: under relay version 3 it opens for nobody, so the token stays sealed."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            assert rig.companion.relay.version == 3
            sealed, held = rig.fake.answer, list[web.Response]()

            def middle(
                identity: fake_controller.Identity | None, payload: object, status: int = 200
            ) -> web.Response:
                answer = sealed(identity, payload, status)
                if not held:
                    held.append(answer)
                    return web.Response(status=503, text="lost")
                return web.Response(
                    content_type="application/json",
                    body=held[0].body,
                    headers={"X-OBBW-Enc": held[0].headers["X-OBBW-Enc"]},
                )

            monkeypatch.setattr(rig.fake, "answer", middle)
            victim = {"X-WebUI-Client": "aaaaaaaaaaaaaaaa", "X-Real-IP": "192.168.1.20"}
            attacker = {"X-WebUI-Client": "bbbbbbbbbbbbbbbb", "X-Real-IP": "192.168.1.66"}
            reply = await rig.client.post("/api/v1/auth/login", json={}, headers=victim)
            assert reply.status == 503
            reply = await rig.client.post("/api/v1/auth/login", json={}, headers=attacker)
            assert reply.status == 502
            assert "token" not in await reply.text()

    asyncio.run(scenario())


def test_an_older_controller_keeps_working_on_version_2(tmp_path: Path) -> None:
    """Any update order: a sealed info answer without the field is a controller from before it."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            rig.fake.features = 0
            assert await rig.companion.relay.handshake() == "ready"
            assert rig.companion.relay.version == 2
            assert rig.companion.relay.features == 0
            reply = await rig.client.get("/api/v1/auth", headers=CLIENT)
            assert reply.status == 200
            assert rig.fake.requests[-1][4] is not None
            assert rig.fake.requests[-1][4]["version"] == 2
            status = await rig.client.get("/__companion/status")
            assert (await status.json())["relayFeatures"] == 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "info",
    [
        {"apiVersion": 1},  # Another sealed answer, swapped in.
        {
            "apiVersion": 1,
            "name": "x",
            "firmwareVersion": "1",
            "authRequired": False,
            "relayFeatures": 0,
        },
        ["not", "an", "object"],
    ],
)
def test_nothing_else_lowers_the_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, info: object
) -> None:
    """Only exactly info's shape can mean an older controller; anything else opens no session."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            sealed = rig.fake.answer

            def swapped(
                identity: fake_controller.Identity | None, payload: object, status: int = 200
            ) -> web.Response:
                told = info if isinstance(payload, dict) and "authRequired" in payload else payload
                return sealed(identity, told, status)

            monkeypatch.setattr(rig.fake, "answer", swapped)
            await rig.companion.relay.handshake()
            assert rig.companion.relay.key is None
            reply = await rig.client.get("/api/v1/auth", headers=CLIENT)
            assert reply.status == 502

    asyncio.run(scenario())


def test_an_unsealed_info_opens_no_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        async with Rig(tmp_path) as rig:

            def plain(
                _identity: fake_controller.Identity | None, payload: object, status: int = 200
            ) -> web.Response:
                return web.json_response(payload, status=status)

            monkeypatch.setattr(rig.fake, "answer", plain)
            await rig.companion.relay.handshake()
            assert rig.companion.relay.key is None

    asyncio.run(scenario())


def test_bound_answer_vectors() -> None:
    """The shared vectors: the v3 signature and an answer sealed by the firmware's rule."""
    relay = cast("dict[str, Any]", V["relay"])
    bound = cast("dict[str, Any]", relay["boundRequest"])
    key, body_key = bytes.fromhex(relay["key"]), bytes.fromhex(relay["bodyKey"])
    version, q, addr, screen, tag = bound["header"].split(" ")
    assert version == "3"
    assert (
        crypto.relay_tag(
            key, bound["method"], bound["uri"], int(q), addr, screen, bound["session"], 3
        )
        == tag
    )
    assert crypto.relay_answer_aad(int(q), 401).decode() == bound["answerAad"]
    sealed = base64.b64decode(bound["answerSealed"])
    additional = crypto.relay_answer_aad(int(q), 401)
    counter = bound["answerCounter"]
    assert crypto.relay_open(body_key, counter, sealed, additional).decode() == bound["answerPlain"]
    with pytest.raises(InvalidTag):
        crypto.relay_open(body_key, counter, sealed, crypto.relay_answer_aad(int(q) + 1, 401))
    with pytest.raises(InvalidTag):
        crypto.relay_open(body_key, counter, sealed, crypto.relay_answer_aad(int(q), 200))
    with pytest.raises(InvalidTag):
        crypto.relay_open(body_key, counter, sealed)


@pytest.mark.parametrize(
    "broken",
    [
        b"[]",
        b"{}",
        json.dumps(
            {
                "v": 2,
                "tag": "t",
                "etag": "e",
                "csp": "c",
                "shell": ["", 0],
                "shellPaths": [],
                "assets": [],
            }
        ).encode(),
        json.dumps(
            {
                "v": 1,
                "tag": "t",
                "etag": "e",
                "csp": "c",
                "shell": ["AAAA", 1],
                "shellPaths": ["/"],
                "assets": [],
            }
        ).encode(),
    ],
)
def test_a_list_of_the_wrong_shape_is_refused(broken: bytes) -> None:
    with pytest.raises((KeyError, TypeError, ValueError)):
        parse_listing(broken)


def test_files_are_verified_against_the_sealed_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-02: through the real relay, a file is served only as the list names it, with its headers
    from the list; an answer swapped in for the list is never believed."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            fake, assets = rig.fake, rig.companion.assets
            url = f"/app.js?v={fake.tag}"
            reply = await rig.client.get(url)
            assert (reply.status, await reply.read()) == (200, b"app")
            assert reply.headers["Cache-Control"] == "public, max-age=31536000, immutable"
            assert assets.facts() == {
                "verified": 1,
                "refused": 0,
                "lastPath": None,
                "legacy": False,
            }
            reply = await rig.client.get("/stats")
            assert (reply.status, await reply.read()) == (200, b"shell")
            assert reply.headers["Content-Security-Policy"] == "default-src 'self'"
            etag = reply.headers["ETag"]
            fetched = len(fake.requests)
            reply = await rig.client.get("/stats", headers={"If-None-Match": etag})
            assert reply.status == 304
            assert len(fake.requests) == fetched, "an unchanged shell costs the controller nothing"

            reply = await rig.client.get("/other", allow_redirects=False)
            assert (reply.status, reply.headers["Location"]) == (302, "/")
            assert (await rig.client.get("/__companion/none")).status == 404
            assert (await rig.client.post("/app.js")).status == 405

            fake.served["/app.js"] = b"steal"
            reply = await rig.client.get(url)
            assert reply.status == 502
            assert b"steal" not in await reply.read()
            assert assets.facts()["lastPath"] == "/app.js"
            assert assets.facts()["refused"] == 1
            fake.served["/app.js"] = b"app" + b"longer than the list says"
            assert (await rig.client.get(url)).status == 502
            del fake.served["/app.js"]

            # An update: the file that changed sends the companion for a new list, once.
            fake.files["/app.js"] = b"new app"
            assert await (await rig.client.get(url)).read() == b"new app"

            # Someone in the middle swaps another sealed answer in for the list.
            sealed = fake.answer

            def swapped(
                identity: fake_controller.Identity | None, payload: object, status: int = 200
            ) -> web.Response:
                told = (
                    {"ok": True} if isinstance(payload, dict) and "assets" in payload else payload
                )
                return sealed(identity, told, status)

            monkeypatch.setattr(fake, "answer", swapped)
            assets.listing, assets.listed_under = None, None
            assert (await rig.client.get(url)).status == 503

    asyncio.run(scenario())


def test_nothing_passes_before_pairing(tmp_path: Path) -> None:
    """Every page leads to the pairing page, nothing reaches the controller, a stored grant opens
    nothing, and a worker from an earlier pairing removes itself. The page still answers."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            worker = {"Service-Worker": "script"}
            reply = await rig.client.get("/evil.js", headers=worker)
            assert await reply.read() == UNREGISTER
            assert reply.headers["Service-Worker-Allowed"] == "/"
            assert await (await rig.client.get("/sw.js", headers=worker)).read() == b"worker"

            session = {"X-WebUI-Session": "kept"}
            digest = hashlib.sha256(session["X-WebUI-Session"].encode()).hexdigest()
            rig.companion.log_grants[digest] = time.time()
            rig.companion.device_id = "device"
            assert (await rig.client.get("/__companion/log/boots", headers=session)).status == 200

            await rig.companion.erase("a test", history=False)
            assert rig.companion.pairing_required()
            seen = len(rig.fake.requests)
            for path in ("/", "/stats", "/app.js", "/evil.js"):
                reply = await rig.client.get(path, allow_redirects=False)
                assert (reply.status, reply.headers["Location"]) == (302, "/__companion/?pair=1")
                assert reply.headers["Cache-Control"] == "no-store"
            for path in ("/sw.js", "/evil.js"):
                assert await (await rig.client.get(path, headers=worker)).read() == UNREGISTER
            reply = await rig.client.post("/api/v1/auth/login", json={}, headers=CLIENT)
            assert (reply.status, (await reply.json())["error"]) == (409, "COMPANION_NOT_PAIRED")
            assert len(rig.fake.requests) == seen
            with pytest.raises(aiohttp.WSServerHandshakeError):
                await rig.client.ws_connect("/api/v1/ui/ui-stream")
            assert (await rig.client.get("/__companion/log/boots", headers=session)).status == 401
            reply = await rig.client.get("/__companion/ui-gate", headers={"X-Original-URI": "/"})
            assert reply.status == 401
            reply = await rig.client.get(
                "/__companion/ui-gate", headers={"X-Original-URI": "/sw.js"}
            )
            assert reply.status == 204

            page = await (await rig.client.get("/__companion/?pair=1")).text()
            assert "Open the controller's Admin" in page
            facts = await (await rig.client.get("/__companion/status")).json()
            assert facts["pairingRequired"] is True, "an open tab reads this to come here"

            # A controller that forgot this companion is the same case.
            rig.companion.pairing.state = "not_recognized"
            assert rig.companion.pairing_required()

    asyncio.run(scenario())


def test_a_page_load_asks_a_controller_that_seemed_to_forget(tmp_path: Path) -> None:
    """An unsigned answer can only claim the controller forgot this companion, so opening the Web
    UI asks again: a controller that proves the secret brings it back."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            rig.companion.pairing.state = "not_recognized"
            reply = await rig.client.get("/__companion/ui-gate", headers={"X-Original-URI": "/"})
            assert reply.status == 204
            assert rig.companion.pairing.state == "paired"

    asyncio.run(scenario())


def test_firmware_without_pairing_says_to_update(tmp_path: Path) -> None:
    async def scenario() -> None:
        app = web.Application()
        server = TestServer(app, host="127.0.0.1")
        await server.start_server()
        Store(tmp_path).write("identity", {"id": ID, "key": "11" * 32})
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", tmp_path, http, Idle)
            companion.controller = target_of(server)
            assert companion.pairing.start(manual=True)
            task = companion.pairing.task
            assert task is not None
            await task
            assert companion.pairing.state == "unsupported"
            await companion.relay.close()
        await server.close()

    asyncio.run(scenario())


def test_diagnostic_says_an_older_controller_is_not_verified(tmp_path: Path) -> None:
    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            rig.fake.features = 0
            await rig.companion.relay.handshake()
            reply = await rig.client.get("/app.js")
            assert (reply.status, await reply.read()) == (200, b"app")
            facts = await (await rig.client.get("/__companion/status")).json()
            assert facts["assets"]["legacy"] is True

    asyncio.run(scenario())
