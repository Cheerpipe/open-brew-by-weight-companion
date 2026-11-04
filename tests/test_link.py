"""The companion against a fake controller: pairing, the link and the La Marzocco route.

The fake controller follows docs/COMPANION_LINK.md of the firmware with the
shared vector keys; La Marzocco is replaced by a scripted upstream. Offline,
inside the image (see the README).
"""

import asyncio
import json
import logging
import os
import socket
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import fake_controller
from companion import VERSION, crypto, dashboard, service
from companion.link import FrameCodec
from companion.service import Companion, web_app
from companion.store import Store

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    import pytest

    from companion.store import Account

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / "tests/fixtures/companion-link-v1.vectors.json").read_text())
D = json.loads((ROOT / "tests/fixtures/lamarzocco-dashboard.json").read_text())
ACCOUNT: Account = {
    "email": "barista@example.com",
    "password": "correct horse",
    "serial": "MR012345",
}
COMPANION_KEY, CONTROLLER_KEY = crypto.unb64(V["companionKey"]), crypto.unb64(V["controllerKey"])
SECRET = bytes.fromhex(V["pairingSecret"])
TO_CONTROLLER = {"ping", "lm", "creds", "st", "res", "logsub"}


class Lines(logging.Handler):
    """Everything the companion logs during the test, message by message."""

    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


class Upstream:
    """Scripted stand-in for the La Marzocco client, with the same interface."""

    def __init__(self, _store: Store, events: Companion) -> None:
        self.events = events
        self.sub, self.ep, self.up, self.tok = False, 0, False, 0
        self.refused = self.policy = False
        self.account: tuple[str, str, str] | None = None
        self.signed, self.rejected = False, False
        self.reads = 0
        self.commands: list[tuple[int, str, int | None]] = []
        self.configured: list[tuple[str | None, str, bool]] = []
        self.last_command, self.command_status = 0, 200
        self.confirm: dict[str, object] | None = None

    def configure(self, account: Account | None, conn: str, observe: bool) -> None:
        self.configured.append((account["email"] if account else None, conn, observe))
        identity = (account["email"], account["password"], account["serial"]) if account else None
        if identity == self.account:
            return
        self.account, self.signed, self.rejected = identity, False, False
        if account:
            asyncio.get_running_loop().call_later(
                0.05, self.sign_in, account["password"] == "correct horse"
            )

    def sign_in(self, ok: bool) -> None:
        self.signed, self.rejected = ok, not ok
        self.tok = 3000 if ok else 0
        self.events.account(ok)
        if ok:
            self.subscribe()

    def subscribe(self) -> None:
        self.sub, self.up = True, True
        self.ep += 1
        self.tok = 3000
        self.events.upstream()
        self.events.subscribed()

    def signed_in_for(self, account: Account) -> bool:
        return self.signed and self.account == (
            account["email"],
            account["password"],
            account["serial"],
        )

    def rejected_for(self, account: Account) -> bool:
        return self.rejected and self.account == (
            account["email"],
            account["password"],
            account["serial"],
        )

    def stop(self) -> None:
        pass

    def erase(self) -> None:
        self.account, self.signed, self.sub, self.up = None, False, False, False

    async def read(self) -> tuple[int, dict[str, object] | None, int]:
        self.reads += 1
        return 200, D["read"], self.last_command

    async def command(self, command_id: int, op: str, value: int | None = None) -> int:
        self.last_command = command_id
        self.commands.append((command_id, op, value))
        if self.confirm:
            self.events.pushed(self.confirm, command_id)
        return self.command_status


class Controller:
    """The controller's pairing routes and link endpoint, driven by the test."""

    def __init__(self) -> None:
        self.pair_requests: list[dict[str, object]] = []
        self.pair_state, self.mode, self.retries = "pending", "ok", 0
        self.commitment: str | None = None
        self.key_sent, self.revealed, self.reveal_status = False, False, 202
        self.sessions: asyncio.Queue[Session] = asyncio.Queue()
        self.transports: list[asyncio.Transport] = []
        self.relay = False  # The relay answers only once the link block asks for it.
        self.relay_body, self.relay_answers = bytes(32), 0
        # GET /api/v1/auth: password on; the controller answers.
        self.login, self.auth_up = True, True
        # The screen holding the Admin unlock, as the relay signs screens.
        self.admin_screen: str | None = None
        # True: the relay drops the connection unanswered, as when the controller is off.
        self.silent = False

    async def pair_post(self, request: web.Request) -> web.Response:
        assert request.content_type == "application/json"
        body = await request.json()
        self.pair_requests.append(body)
        if "commitment" in body:  # Commit: a new request, whose key is made afterwards.
            assert "publicKey" not in body
            self.commitment, self.key_sent, self.revealed = body["commitment"], False, False
            return web.json_response({"state": "pending", "expiresInS": 600}, status=202)
        assert self.key_sent, (
            "the companion reveals its key only after it received the controller's"
        )
        assert crypto.b64(crypto.commitment(crypto.unb64(body["publicKey"], 65))) == self.commitment
        if self.reveal_status != 202:
            return web.json_response({"error": "INVALID_REQUEST"}, status=self.reveal_status)
        self.revealed = True
        return web.json_response(
            {"state": "pending", "controllerKey": V["controllerKey"], "expiresInS": 590}, status=202
        )

    async def pair_get(self, request: web.Request) -> web.Response:
        assert request.query["id"] == self.pair_requests[-1]["id"]
        self.key_sent = True
        state = (
            "pending" if self.pair_state == "approved" and not self.revealed else self.pair_state
        )
        return web.json_response({"state": state, "controllerKey": V["controllerKey"]})

    RELAY_CHALLENGE = bytes(range(16))  # Fixed; the handshake's formulas are covered by test_relay.

    async def relay_get(self, request: web.Request) -> web.Response:
        if self.silent:
            assert request.transport is not None
            request.transport.abort()
            return web.Response()
        if not self.relay:  # Before that, the relay handshake fails: the link opens as ever.
            return web.json_response({"error": "UNAVAILABLE"}, status=503)
        return web.json_response({"challenge": crypto.b64(self.RELAY_CHALLENGE), "protocol": 1})

    async def relay_post(self, request: web.Request) -> web.Response:
        body = await request.json()
        nc = crypto.unb64(body["nonce"], 16)
        assert crypto.unb64(body["mac"]) == crypto.mac(SECRET, b"R", self.RELAY_CHALLENGE, nc), (
            "the companion proves the pairing secret"
        )
        self.relay_body = crypto.relay_body_key(crypto.relay_key(SECRET, self.RELAY_CHALLENGE, nc))
        self.relay_answers = 0
        return web.json_response(
            {
                "mac": crypto.b64(crypto.mac(SECRET, b"Q", self.RELAY_CHALLENGE, nc)),
                "ui": True,
                "link": True,
            }
        )

    async def auth(self, request: web.Request) -> web.Response:
        """Signed in whenever the browser sent a session (sealed through the relay, so any value);
        Admin unlocked only for the screen the relay signs, as the controller resolves it."""
        if not self.auth_up:
            return web.json_response({"error": "UNAVAILABLE"}, status=503)
        relay = request.headers.get("X-OBBW-Relay", "").split()
        answer: dict[str, object] = {
            "loginRequired": self.login,
            "signedIn": bool(request.headers.get("X-WebUI-Session")),
            "adminUnlocked": len(relay) == 5 and relay[3] == self.admin_screen,
        }
        return self.sealed(answer) if relay else web.json_response(answer)

    def sealed(self, answer: dict[str, object]) -> web.Response:
        """Every whole JSON answer to a relayed request is sealed."""
        self.relay_answers += 1
        return web.Response(
            content_type="application/json",
            headers={"X-OBBW-Enc": str(self.relay_answers)},
            body=AESGCM(self.relay_body).encrypt(
                fake_controller.nonce(b"f", 3, self.relay_answers),
                json.dumps(answer).encode(),
                None,
            ),
        )

    async def info(self, _request: web.Request) -> web.Response:
        """A controller from before `relayFeatures`: the link scenario runs on relay version 2."""
        return self.sealed(
            {"apiVersion": 1, "name": "Cafe Bar", "firmwareVersion": "1.0.0", "authRequired": False}
        )

    async def link(self, request: web.Request) -> web.StreamResponse:
        if self.mode == "not_paired":
            return web.json_response({"error": "COMPANION_NOT_PAIRED"}, status=404)
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        hello = json.loads(await ws.receive_str())
        assert hello["t"] == "hello"
        assert hello["protocol"] == 2
        assert hello["name"] == "Kitchen server"
        nc = crypto.unb64(hello["nonce"], 16)
        mode = self.mode
        if mode == "version":  # A controller of another release: its link refuses this one.
            self.mode = "ok"
            await ws.send_json({"t": "error", "code": "PROTOCOL"})
        elif mode == "retry":
            self.retries -= 1
            self.mode = "retry" if self.retries > 0 else "ok"
            await ws.send_json({"t": "error", "code": "RETRY_LATER"})
        elif mode in ("erase", "bad_erase"):
            await ws.send_json(
                {
                    "t": "erase",
                    "mac": crypto.b64(
                        crypto.mac(SECRET if mode == "erase" else bytes(32), b"E", nc)
                    ),
                }
            )
        else:
            ns = os.urandom(16)
            await ws.send_json({"t": "challenge", "nonce": crypto.b64(ns)})
            proof = json.loads(await ws.receive_str())
            assert crypto.unb64(proof["mac"]) == crypto.mac(SECRET, b"C", nc, ns), (
                "the companion proves the secret"
            )
            await ws.send_json({"t": "ready", "mac": crypto.b64(crypto.mac(SECRET, b"F", nc, ns))})
            session = Session(
                ws, FrameCodec(crypto.session_key(SECRET, nc, ns), send=b"f", receive=b"c")
            )
            await self.sessions.put(session)
            assert request.transport is not None
            self.transports.append(request.transport)
            if mode == "close":
                await ws.close(code=4000, message=b"busy")
                return ws
            if mode == "abort":
                request.transport.abort()
                return ws
            async for message in ws:
                frame = session.codec.decode(message.data)
                assert frame["t"] in TO_CONTROLLER, frame
                session.frames.put_nowait(frame)
            session.frames.put_nowait(None)
        await ws.close()
        return ws


class Session:
    def __init__(self, ws: web.WebSocketResponse, codec: FrameCodec) -> None:
        self.ws, self.codec = ws, codec
        self.frames: asyncio.Queue[dict[str, object] | None] = asyncio.Queue()

    async def send(self, frame: dict[str, object]) -> None:
        await self.ws.send_str(self.codec.encode(frame))

    async def next(self, kind: str, skip: tuple[str, ...] = ("ping",)) -> dict[str, object]:
        """The next frame of this type; frames listed in skip may come first.

        Each frame within 3 s (a caller may bound the whole wait tighter).
        """
        while True:
            frame = await asyncio.wait_for(self.frames.get(), 3)
            assert frame is not None, f"the link closed while waiting for {kind}"
            if frame["t"] == kind:
                return frame
            assert frame["t"] in skip, f"expected {kind}, got {frame}"

    async def quiet(self, seconds: float, skip: tuple[str, ...] = ("ping",)) -> None:
        """Nothing but pings for a while."""
        deadline = asyncio.get_running_loop().time() + seconds
        try:
            while True:
                frame = await asyncio.wait_for(
                    self.frames.get(), deadline - asyncio.get_running_loop().time()
                )
                assert frame is not None, f"unexpected {frame}"
                assert frame["t"] in skip, f"unexpected {frame}"
        except TimeoutError:
            pass


async def eventually(predicate: Callable[[], object]) -> None:
    """Until predicate holds, for at most 3 s."""
    for _ in range(int(3 / 0.02)):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not reached")


async def settles(read: Callable[[], Awaitable[object]], want: object) -> None:
    """Poll an async read (the store's cursor) until it equals `want`, for at most 3 s."""
    for _ in range(int(3 / 0.02)):
        if await read() == want:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"{want!r} not reached")


def encrypt(generation: int, account: Account) -> dict[str, object]:
    iv = os.urandom(12)
    ct = AESGCM(crypto.credentials_key(SECRET)).encrypt(
        iv, json.dumps(account).encode(), f"obbw-creds|{generation}".encode()
    )
    return {"t": "creds", "gen": generation, "iv": crypto.b64(iv), "ct": crypto.b64(ct)}


async def scenario(monkeypatch: pytest.MonkeyPatch, lines: Lines) -> None:
    fake = Controller()
    app = web.Application()
    app.router.add_post("/api/v1/companion/pair", fake.pair_post)
    app.router.add_get("/api/v1/companion/pair", fake.pair_get)
    app.router.add_get("/api/v1/companion/link", fake.link)
    app.router.add_get("/api/v1/companion/relay", fake.relay_get)
    app.router.add_post("/api/v1/companion/relay", fake.relay_post)
    app.router.add_get("/api/v1/auth", fake.auth)
    app.router.add_get("/api/v1/integration/info", fake.info)
    server = TestServer(app, host="127.0.0.1")
    await server.start_server()
    assert server.port is not None
    target = ("Cafe Bar", ("127.0.0.1", server.port))
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-link-") as temporary:
        data = Path(temporary)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as http:
            # The identity holds the vector's companion key, so the code and secret match the
            # firmware's.
            seed = Store(data)
            seed.write(
                "identity",
                {"id": "0b9f6a3c-2f4e-4d7a-9c1b-5e8f0a1d2c3b", "key": V["companionPrivate"]},
            )
            companion = Companion("Kitchen server", data, http, Upstream)
            await companion.open_log()  # _serve opens it; the test builds the service by hand.
            upstream = companion.lm
            assert isinstance(upstream, Upstream)
            pages = TestServer(web_app(companion), host="127.0.0.1")
            await pages.start_server()
            page_url = f"http://127.0.0.1:{pages.port}/__companion"
            async with http.get(page_url + "/") as reply:
                page = await reply.text()
                assert reply.status == 200
                assert "@STYLE@" not in page
                assert "--ac:" in page
                assert reply.headers["Cache-Control"] == "no-store"
            async with http.post(page_url + "/pair", data="{}") as reply:
                assert reply.status == 415, (
                    "pairing needs a JSON request a foreign page cannot send unasked"
                )
            async with http.post(page_url + "/pair", json={}) as reply:
                assert reply.status == 409
                assert (await reply.json())["error"] == "NO_CONTROLLER"

            # --- Pairing (entry point a): commit, then reveal, polled while pending --
            # The shared vectors' key, as this attempt's own (each makes one: test_hardening).
            monkeypatch.setattr(
                crypto, "new_key", lambda: crypto.load_key(bytes.fromhex(V["companionPrivate"]))
            )
            _ = companion.spawn(companion.run_link())
            companion.set_controller(target)
            await eventually(
                lambda: companion.pairing.state == "pending" and companion.pairing.code
            )
            identity = {
                "id": "0b9f6a3c-2f4e-4d7a-9c1b-5e8f0a1d2c3b",
                "name": "Kitchen server",
                "version": VERSION,
                "protocol": 1,
            }
            assert fake.pair_requests == [
                {**identity, "commitment": V["commitment"]},
                {**identity, "publicKey": V["companionKey"]},
            ]
            async with http.get(page_url + "/status") as reply:
                status = await reply.json()
            assert status["pairing"]["code"] == V["sas"]
            assert status["pairing"]["expiresInS"] > 590
            assert status["paired"] is False
            assert status["link"] == "down"
            assert status["name"] == "Kitchen server"
            companion.set_controller(
                target
            )  # Another announcement while pending sends nothing new.
            await asyncio.sleep(0.3)
            assert len(fake.pair_requests) == 2
            fake.pair_state = "approved"
            session = await asyncio.wait_for(fake.sessions.get(), 5)
            pairing = companion.store.pairing()
            assert pairing is not None
            assert pairing["secret"] == SECRET
            secrets = data / "secrets"
            assert secrets.stat().st_mode & 0o777 == 0o700
            assert all(path.stat().st_mode & 0o777 == 0o600 for path in secrets.iterdir())
            await eventually(lambda: companion.link == "open")
            assert (await companion.status())["paired"]
            assert (await companion.status())["pairedWith"] == "Cafe Bar"
            assert companion.ws is not None
            assert (
                companion.ws.get_extra_info("socket").getsockopt(
                    socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT
                )
                == 30000
            ), "an unacknowledged ping closes the link"
            async with http.post(page_url + "/erase", json={}) as reply:
                assert reply.status == 409, "a working pairing is forgotten in Admin, not here"

            # --- A ping as the link opens, cfg, then the account ------------------
            assert await session.next("ping", skip=()) == {"q": 1, "t": "ping", "up": False}
            controller = (await companion.status())["controller"]
            assert isinstance(controller, dict)
            assert controller["name"] == "Cafe Bar", "falls back to discovery"
            await session.send({"t": "dev", "name": "Cafe Bar 2"})
            await eventually(lambda: companion.device_name == "Cafe Bar 2")
            status = await companion.status()
            controller = status["controller"]
            assert isinstance(controller, dict)
            assert controller["name"] == "Cafe Bar 2" == status["pairedWith"]
            assert status["unknownFrames"] == 0
            await session.send({"t": "dev", "name": 7})  # Not a name: ignored, not unknown.
            await session.send({"t": "dev", "name": "bad \ud800 name"})  # Nor is a lone surrogate.
            await asyncio.sleep(0.2)
            assert companion.device_name == "Cafe Bar 2"
            await session.send({"t": "dev", "name": "Bar"})  # A rename reaches the page.
            await eventually(lambda: companion.device_name == "Bar")
            assert (await companion.status())["pairedWith"] == "Bar"
            await session.send({"t": "cfg", "lm": True, "conn": "ws", "observe": True})
            assert await session.next("lm") == {"q": 2, "t": "lm", "sub": False, "ep": 0, "tok": 0}
            assert upstream.configured == [(None, "ws", True)], "no account yet"
            await session.send(encrypt(3, ACCOUNT))
            assert await session.next("creds") == {"q": 3, "t": "creds", "gen": 3, "ok": True}
            assert await session.next("lm") == {
                "q": 4,
                "t": "lm",
                "sub": False,
                "ep": 0,
                "tok": 3000,
            }, "a sign-in reports the new token's life at once"
            assert await session.next("lm") == {
                "q": 5,
                "t": "lm",
                "sub": True,
                "ep": 1,
                "tok": 3000,
            }
            assert await session.next("ping", skip=()) == {"q": 6, "t": "ping", "up": True}, (
                "a ping when up changes"
            )
            assert json.loads((secrets / "credentials.json").read_text()) == {"gen": 3, **ACCOUNT}
            await session.send(encrypt(3, ACCOUNT))  # The controller resends it each new session.
            assert (await session.next("creds"))["ok"] is True
            assert upstream.configured[-1][0] == ACCOUNT["email"]
            await session.next("lm")

            # --- Fresh evidence of the controller pokes an open link ----------------
            # An announcement and a relay handshake each ping at once, so a socket that
            # died with the controller's restart — a reboot sends no FIN or RST — is
            # found now, not at the next ping cadence.
            fake.relay = True
            companion.set_controller(target)  # The same controller announced itself again.
            assert (await session.next("ping", skip=()))["up"] is True, "the announcement's poke"
            await eventually(lambda: companion.relay.mode == "ready")
            assert (await session.next("ping", skip=()))["up"] is True, "the handshake it spawned"
            assert await companion.relay.handshake() == "ready"
            assert (await session.next("ping", skip=()))["up"] is True, "one asked for directly"

            # --- Nothing is forwarded while the route is direct --------------------
            upstream.events.pushed(D["pushes"]["standby"], 0)
            await session.quiet(0.3)

            # --- Route to the companion: an immediate ping, then `full` -----------
            await session.send({"t": "route", "to": "companion"})
            assert (await session.next("ping", skip=()))["up"] is True
            full = await session.next("st")
            assert full["k"] == "full"
            assert full["ep"] == 1
            assert full["ac"] == 0
            assert full["d"] == dashboard.reduce(D["read"], push=False)
            await session.next("ping", skip=())  # Every PING_S["companion"] from now on.

            # --- A sync hold (a shot): no ping at all until it ends, then one at once ---
            await session.send({"t": "hold", "on": False, "sync": True})
            await session.quiet(1.0, skip=())  # Two and a half ping intervals without a frame.
            # A controller that restarted mid-shot never ends the hold: its announcement (or relay
            # handshake) still pings, the one frame that finds the dead socket.
            companion.poke()
            async with asyncio.timeout(0.3):
                await session.next("ping", skip=())
            await session.quiet(0.5, skip=())
            await session.send({"t": "hold", "on": False, "sync": False})
            began = asyncio.get_running_loop().time()
            async with asyncio.timeout(0.3):
                await session.next("ping", skip=())
            assert asyncio.get_running_loop().time() - began < 0.2, (
                "the first ping checks the link at once"
            )

            # --- Pushes: filtered per event, dropped when they carry nothing -------
            upstream.events.pushed(D["pushes"]["commandsOnly"], 0)
            upstream.events.pushed(D["pushes"]["backflush"], 0)
            push = await session.next("st")
            assert push["k"] == "push"
            assert isinstance(push["d"], dict)
            assert push["d"]["widgets"][0]["code"] == "CMBackFlush"
            assert "ac" not in push, (
                "pushes take their order from when the controller receives them"
            )

            # --- Hold: the latest push and read wait, and go once in order --------
            await session.send({"t": "hold", "on": True})
            await eventually(lambda: companion.hold)
            upstream.events.renewed()
            assert (await session.next("lm"))["tok"] == 3000
            upstream.events.pushed(D["pushes"]["standby"], 0)
            await session.quiet(0.3)
            upstream.events.polled(D["read"], 0, False)
            upstream.events.pushed(D["pushes"]["backflush"], 0)  # Supersedes the held one.
            await session.quiet(0.3)
            await session.send({"t": "hold", "on": False})
            held = await session.next("st")
            assert held["k"] == "read"
            assert isinstance(held["d"], dict)
            assert held["d"]["widgets"][0]["code"] == "CMMachineStatus"
            held = await session.next("st")
            assert held["k"] == "push"
            assert isinstance(held["d"], dict)
            assert held["d"]["widgets"][0]["code"] == "CMBackFlush"
            await session.quiet(0.3)

            # A new subscription mid-hold: its full frame goes at once, the held push never does.
            await session.send({"t": "hold", "on": True})
            await eventually(lambda: companion.hold)
            upstream.events.pushed(D["pushes"]["standby"], 0)
            await session.quiet(0.2)
            upstream.subscribe()
            await session.next("lm")
            full = await session.next("st")
            assert full["k"] == "full"
            assert full["ep"] == 2
            await session.send({"t": "hold", "on": False})
            await session.quiet(0.3)

            # A route back to direct while a hold stands: what it held is discarded.
            await session.send({"t": "hold", "on": True})
            await eventually(lambda: companion.hold)
            upstream.events.pushed(D["pushes"]["standby"], 0)
            await session.quiet(0.2)
            await session.send({"t": "route", "to": "direct"})
            await session.send({"t": "hold", "on": False})
            await session.quiet(0.3)
            await session.send({"t": "route", "to": "companion"})
            assert (await session.next("st"))["k"] == "full"

            # --- Commands --------------------------------------------------------
            reads = upstream.reads
            await session.send({"t": "cmd", "id": 7, "op": "temp", "v": 935})
            assert (await session.next("res"))["id"] == 7
            assert session.codec.received > 7
            async with asyncio.timeout(2):  # No confirming push: one read after CONFIRM_S.
                read = await session.next("st")
            assert (read["k"], read["ac"], upstream.reads) == ("read", 7, reads + 1)
            upstream.confirm = D["pushes"]["standby"]
            await session.send({"t": "cmd", "id": 8, "op": "standby"})
            assert (await session.next("st"))["k"] == "push"
            assert (await session.next("res"))["r"] == "accepted"
            await session.quiet(0.6)
            assert upstream.reads == reads + 1, "a confirming push needs no read"
            upstream.confirm, upstream.command_status = None, 503
            await session.send({"t": "cmd", "id": 9, "op": "on"})
            res = await session.next("res")
            assert (res["id"], res["r"], res["http"]) == (9, "failed", 503)
            await session.send({"t": "cmd", "id": 10, "op": "refresh"})
            assert (await session.next("st"))["k"] == "read"
            assert (await session.next("res"))["r"] == "accepted"
            await session.send({"t": "cmd", "id": 11, "op": "temp", "v": "93.5"})
            assert (await session.next("res"))["http"] == 0
            assert [c[:2] for c in upstream.commands] == [(7, "temp"), (8, "standby"), (9, "on")]
            await session.quiet(0.6)

            # --- A new La Marzocco subscription epoch sends `full` again ---------
            upstream.subscribe()
            assert (await session.next("lm"))["ep"] == 3
            assert (await session.next("st"))["k"] == "full"

            # --- A loop stall is named before the ping it delayed ----------------
            lines.lines.clear()
            # A callback that blocks: the whole loop, this test task included, stands still.
            asyncio.get_running_loop().call_soon(time.sleep, 1.2)
            await asyncio.sleep(0)  # It runs now, before this task goes on.
            await asyncio.sleep(0.05)
            assert any("stood still" in line for line in lines.lines), (
                "a stall before a ping is named"
            )

            # --- Why the link ended is named: close code, socket death -----------
            fake.mode = "close"
            await session.ws.close()
            await eventually(lambda: companion.link_reason == "CLOSED_4000")
            fake.mode = "abort"
            await asyncio.wait_for(fake.sessions.get(), 3)  # The close session, already dead.
            session = await asyncio.wait_for(fake.sessions.get(), 3)  # Killed by the transport.
            await eventually(lambda: companion.link_reason.startswith("SOCKET_"))
            fake.mode = "ok"
            session = await asyncio.wait_for(fake.sessions.get(), 3)
            await eventually(lambda: companion.link == "open")
            await session.next("ping", skip=())  # The new session's opening ping.
            upstream.events.upstream()  # One re-report on the fresh session; nothing pending.
            await session.next("lm")

            # --- Route back to direct: forwarding stops ----------------------------
            await session.send({"t": "route", "to": "direct"})
            await eventually(lambda: companion.route == "direct")
            upstream.events.pushed(D["pushes"]["standby"], 0)
            await session.quiet(0.5)

            # --- `up` changing sends a ping at once, also on the slow interval -----
            upstream.up = False
            upstream.events.upstream()
            assert (await session.next("ping", skip=()))["up"] is False
            upstream.up = True
            upstream.events.upstream()
            assert (await session.next("ping", skip=()))["up"] is True

            # --- A refused data plane reports `err` on `lm` while `up` stays true --
            upstream.refused = True
            upstream.events.upstream()
            refusal = await session.next("lm")
            assert refusal["err"] == "auth"
            assert refusal["sub"]
            assert refusal["tok"] == 3000
            assert "policy" not in refusal, "`policy` is present only for a pending policy"
            upstream.policy = True  # auth -> policy is a change of state, reported at once.
            upstream.events.upstream()
            refusal = await session.next("lm")
            assert refusal["err"] == "auth"
            assert refusal["policy"] is True
            upstream.refused = upstream.policy = False
            upstream.events.upstream()
            cleared = await session.next("lm")
            assert "err" not in cleared
            assert "policy" not in cleared

            # --- A newer controller's frame type is ignored and counted ------------
            await session.send({"t": "webhook", "id": 1})
            await session.send({"t": "hold", "on": True})
            await eventually(lambda: companion.hold)
            assert companion.link == "open"
            assert (await companion.status())["unknownFrames"] == 1
            await session.send({"t": "hold", "on": False})

            # --- A frame out of sequence closes the link; it reopens after backoff -
            body = json.dumps(
                {"q": session.codec.sent + 2, "t": "hold", "on": True}, separators=(",", ":")
            )
            await session.ws.send_str(f"{session.codec._tag(b'f', body)}.{body}")
            await eventually(lambda: companion.link == "retry")
            assert companion.link_reason == "PROTOCOL"
            session = await asyncio.wait_for(fake.sessions.get(), 3)
            await eventually(lambda: companion.link == "open")
            assert companion.route == "direct", "every session starts direct"
            assert not companion.hold, "every session starts direct"
            assert companion.link == "open"
            assert (await companion.status())["unknownFrames"] == 0

            # --- Any unexpected error ends only that session -----------------------
            def broken(*_: object) -> NoReturn:
                raise OSError("disk full")

            with monkeypatch.context() as patch:
                patch.setattr(companion.store, "save_credentials", broken)
                await session.send(encrypt(5, ACCOUNT))
                await eventually(lambda: companion.link_reason == "ERROR")
            session = await asyncio.wait_for(fake.sessions.get(), 3)
            await eventually(lambda: companion.link == "open")

            # --- RETRY_LATER retries at its short interval, without escalating -----
            monkeypatch.setattr(service, "BACKOFF_S", (0.2, 30, 30, 30, 30))
            fake.mode, fake.retries = "retry", 3
            await session.ws.close()
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            await eventually(lambda: companion.link == "open")

            # --- ...and an announcement reconnects at once -------------------------
            monkeypatch.setattr(service, "RETRY_LATER_S", 30)
            fake.mode, fake.retries = "retry", 1
            await session.ws.close()
            await eventually(lambda: companion.link_reason == "RETRY_LATER")
            await asyncio.sleep(0.3)
            assert fake.sessions.empty()
            companion.set_controller(target)
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            await eventually(lambda: companion.link == "open")
            monkeypatch.setattr(service, "RETRY_LATER_S", 0.2)

            # --- Another link version: the link waits for an update, the relay keeps the Web UI ---
            fake.mode = "version"
            await session.ws.close()
            await eventually(lambda: companion.link_reason == "VERSION")
            assert companion.relay.mode == "ready", (
                "a mismatched pair still serves the Web UI (and OTA)"
            )
            companion.set_controller(target)  # The updated controller announces itself.
            session = await asyncio.wait_for(fake.sessions.get(), 3)
            await eventually(lambda: companion.link == "open")

            # --- Started with the controller off: the relay handshake is asked again --
            # A manual address hears no announcement, so an unanswered handshake must
            # not leave the link waiting for one; no new announcement is made here.
            monkeypatch.setattr(service, "BACKOFF_S", (0.2,) * 5)
            fake.silent = True
            companion.relay.reset(None)  # As at start: the controller has not answered yet.
            await session.ws.close()
            await eventually(lambda: companion.link_reason == "UNREACHABLE")
            assert companion.relay.link is None
            assert fake.sessions.empty()
            fake.silent = False
            session = await asyncio.wait_for(fake.sessions.get(), 3)
            await eventually(lambda: companion.link == "open")
            assert companion.relay.mode == "ready"
            monkeypatch.setattr(service, "BACKOFF_S", (0.2, 30, 30, 30, 30))

            # --- Erasing the account keeps the installation -------------------------
            (secrets / "lamarzocco.json").write_text("{}")
            await session.send({"t": "creds", "gen": 4, "erase": True})
            await eventually(lambda: not (secrets / "credentials.json").exists())
            assert (secrets / "lamarzocco.json").exists()
            assert upstream.account is None
            await session.send(encrypt(6, ACCOUNT))
            assert (await session.next("creds", skip=("ping", "lm")))["ok"] is True

            # --- Diagnostic log: subscribe, pages, gaps, resume, reset ------------
            # cfg turns the stream on, but the subscription waits for `dev` to
            # name the controller, so its cursor is that controller's.
            await session.send({"t": "cfg", "lm": True, "conn": "ws", "observe": True, "log": True})
            await session.quiet(0.2, skip=("ping", "lm"))
            await session.send({"t": "dev", "name": "Bar", "id": "AA:BB:CC:DD:EE:FF"})
            await session.send({"t": "hold", "on": False, "sync": False})  # Sync may flow.
            sub = await session.next("logsub", skip=("ping", "lm"))
            assert sub["on"] is True
            assert sub["boot"] == 0
            assert sub["after"] == 0
            assert await companion.logs.meta("device") == "AA:BB:CC:DD:EE:FF", (
                "the id is kept for a restart"
            )
            await session.send(
                {
                    "t": "log",
                    "b": 7,
                    "e": [
                        [1, 100, 1789000000, "i", "state", "Open Brew by Weight 1.1.0 (bootId=7)"],
                        [2, 200, 1789000000, "w", "scale", "the scale link was lost"],
                    ],
                }
            )
            await settles(lambda: companion.logs.cursor("AA:BB:CC:DD:EE:FF"), (7, 2))
            await session.send(
                {"t": "log", "b": 7, "e": [[3, 300, 1789000001, "i", "state", "shot done"]]}
            )
            await settles(lambda: companion.logs.cursor("AA:BB:CC:DD:EE:FF"), (7, 3))
            # Only a browser the controller would let open the Web UI reads it.
            signed = {"X-WebUI-Session": "letmein"}
            async with http.get(page_url + "/log?limit=2") as reply:
                assert reply.status == 401
                assert (await reply.json())["error"] == "AUTH_REQUIRED"
            async with http.get(page_url + "/log?limit=2", headers=signed) as reply:
                assert reply.status == 200
                page = await reply.json()
            assert page["device"] == "AA:BB:CC:DD:EE:FF"
            assert [entry.get("s") for entry in page["entries"]] == [3, 2]
            assert page["next"] == {"boot": 1, "before": 2}  # Opaque: the first boot.
            assert page["hasMore"] is True
            async with http.get(
                page_url + "/log?boot=1&before=2&limit=10", headers=signed
            ) as reply:
                page = await reply.json()
            assert [entry.get("s") for entry in page["entries"]] == [1]
            assert page["next"] is None
            # A gap names itself between the events it separates.
            await session.send(
                {
                    "t": "log",
                    "b": 7,
                    "miss": 4,
                    "e": [[8, 900, 1789000010, "e", "network", "the Web UI socket was lost"]],
                }
            )
            await settles(lambda: companion.logs.cursor("AA:BB:CC:DD:EE:FF"), (7, 8))
            async with http.get(page_url + "/log?limit=3", headers=signed) as reply:
                page = await reply.json()
            assert [entry.get("s", entry.get("g")) for entry in page["entries"]] == [8, "gap", 3, 2]
            assert page["entries"][1]["count"] == 4
            log_status = (await companion.status())["log"]
            assert isinstance(log_status, dict)
            assert log_status["enabled"]
            assert log_status["rows"] == 4
            assert log_status["missed"] == 4
            assert log_status["mb"] == 50
            assert log_status["dropped"] == 0
            # A log frame never closes the link: out-of-bounds text is cut, an
            # unknown level reads as info, an unkeyed frame is counted.
            await session.send(
                {"t": "log", "b": 7, "e": [[9, 1000, 1789000011, "?", "x" * 40, "m" * 2000]]}
            )
            await settles(lambda: companion.logs.cursor("AA:BB:CC:DD:EE:FF"), (7, 9))
            await session.send(
                {"t": "log", "b": 7, "e": [["nine", 0, 0, "i", "state", "no sequence"]]}
            )
            await eventually(lambda: companion.log_dropped == 1)
            assert companion.link == "open"
            async with http.get(page_url + "/log?limit=1", headers=signed) as reply:
                newest = (await reply.json())["entries"][0]
            assert newest["l"] == "i"
            assert len(newest["c"]) == 24
            assert len(newest["m"]) == 1024
            # A frame the store could not write is asked for again from the cursor.

            async def unwritable(*_: object) -> NoReturn:
                raise sqlite3.OperationalError("disk I/O error")

            with monkeypatch.context() as patch:
                patch.setattr(companion.logs, "apply", unwritable)
                await session.send(
                    {"t": "log", "b": 7, "e": [[10, 1100, 1789000012, "i", "state", "lost?"]]}
                )
                resync = await session.next("logsub", skip=("ping", "lm"))
                assert resync["boot"] == 7
                assert resync["after"] == 9
            # A reconnect resumes from the stored cursor once `dev` named the controller again.
            await session.ws.close()
            session = await asyncio.wait_for(fake.sessions.get(), 3)
            await eventually(lambda: companion.link == "open")
            await session.send({"t": "cfg", "lm": True, "conn": "ws", "observe": True, "log": True})
            await session.quiet(0.2, skip=("ping", "lm"))
            await session.send({"t": "dev", "name": "Bar", "id": "AA:BB:CC:DD:EE:FF"})
            await session.send({"t": "hold", "on": False, "sync": False})  # Sync may flow.
            sub = await session.next("logsub", skip=("ping", "lm"))
            assert sub["boot"] == 7
            assert sub["after"] == 9
            # A cursor the controller could not resume (a boot id it reused) is
            # a new boot: the rows stay and the spot is marked.
            await session.send(
                {
                    "t": "log",
                    "b": 7,
                    "reset": True,
                    "e": [[10, 5000, 1789000020, "i", "state", "the log started over"]],
                }
            )
            await settles(lambda: companion.logs.cursor("AA:BB:CC:DD:EE:FF"), (7, 10))
            async with http.get(page_url + "/log?limit=3", headers=signed) as reply:
                page = await reply.json()
            assert [entry.get("s", entry.get("g")) for entry in page["entries"]] == [
                10,
                "reset",
                "boot",
                9,
                8,
                "gap",
            ]
            async with http.get(page_url + "/log/export", headers=signed) as reply:
                assert (
                    reply.headers["Content-Disposition"]
                    == 'attachment; filename="obbw-log-AA-BB-CC-DD-EE-FF.json"'
                )
                exported = await reply.json()
            assert exported["format"] == "openbrewbyweight-companion-log"
            assert exported["version"] == 2
            assert exported["device"] == "AA:BB:CC:DD:EE:FF"
            assert [entry.get("s", entry.get("g")) for entry in exported["entries"]] == [
                1,
                2,
                3,
                "gap",
                8,
                9,
                "boot",
                "reset",
                10,
            ]
            # A companion restarted with the controller off still shows the
            # history, to the browser the controller accepted before.
            monkeypatch.setattr(service, "LOG_ACCESS_RECHECK_S", 0)
            fake.auth_up = False
            restarted = Companion("Kitchen server", data, http, Upstream)
            await restarted.open_log()
            assert restarted.device_id == "AA:BB:CC:DD:EE:FF"
            pages_again = TestServer(web_app(restarted), host="127.0.0.1")
            await pages_again.start_server()
            again_url = f"http://127.0.0.1:{pages_again.port}/__companion"
            restarted.set_controller(target)
            async with http.get(again_url + "/log?limit=1", headers=signed) as reply:
                assert reply.status == 200
                assert (await reply.json())["entries"][0]["s"] == 10
            async with http.get(
                again_url + "/log?limit=1", headers={"X-WebUI-Session": "stranger"}
            ) as reply:
                assert reply.status == 401, "a session the controller never accepted waits for it"
            log_status = (await restarted.status())["log"]
            assert isinstance(log_status, dict)
            assert log_status["rows"] == 6
            assert log_status["enabled"] is False
            await pages_again.close()
            await restarted.logs.close()
            await restarted.relay.close()
            # With the password off, any browser reads it; the answer is asked again.
            fake.auth_up, fake.login = True, False
            await companion.relay.handshake()  # The fake keeps one session: the restart took it.
            async with http.get(page_url + "/log?limit=1") as reply:
                assert reply.status == 200
            fake.login = True
            monkeypatch.setattr(service, "LOG_ACCESS_RECHECK_S", 300)
            # Delete history empties the store and keeps reading rights and the id.
            async with http.post(page_url + "/log/delete", data="{}", headers=signed) as reply:
                assert reply.status == 415
            # Off: a remembered sign-in still reads, but deletes nothing (review C7).
            fake.auth_up = False
            async with http.post(page_url + "/log/delete", json={}, headers=signed) as reply:
                assert reply.status == 503
                assert (await reply.json())["error"] == "CONTROLLER_UNREACHABLE"
            fake.auth_up = True
            # Deleting needs Admin unlocked on the screen asking (D14, AC16): the relay signs
            # that screen's own id, never the companion's shared client.
            screen = "0123456789abcdef01234567"
            fake.admin_screen = screen
            for headers in (signed, {**signed, "X-WebUI-Client": "fedcba9876543210fedcba98"}):
                async with http.post(page_url + "/log/delete", json={}, headers=headers) as reply:
                    assert reply.status == 401
                    assert (await reply.json())["error"] == "ADMIN_LOCKED"
            fake.admin_screen = companion.relay.client_id
            async with http.post(page_url + "/log/delete", json={}, headers=signed) as reply:
                assert reply.status == 401, (
                    "the companion's shared client never holds the unlock for a screen"
                )
            fake.admin_screen = screen
            async with http.post(
                page_url + "/log/delete", json={}, headers={**signed, "X-WebUI-Client": screen}
            ) as reply:
                assert reply.status == 200
            log_status = (await companion.status())["log"]
            assert isinstance(log_status, dict)
            assert log_status["rows"] == 0
            assert await companion.logs.meta("device") == "AA:BB:CC:DD:EE:FF"
            await session.send(
                {"t": "log", "b": 7, "e": [[11, 6000, 1789000030, "i", "state", "after delete"]]}
            )
            await settles(lambda: companion.logs.cursor("AA:BB:CC:DD:EE:FF"), (7, 11))
            # The switch off stops the subscription; the store keeps what it has.
            await session.send(
                {"t": "cfg", "lm": True, "conn": "ws", "observe": True, "log": False}
            )
            await eventually(lambda: companion.log_on is False)
            log_status = (await companion.status())["log"]
            assert isinstance(log_status, dict)
            assert log_status["rows"] == 1

            # --- Not recognized: La Marzocco stops, every secret stays ----------------
            monkeypatch.setattr(service, "BACKOFF_S", (0.2,) * 5)
            fake.mode = "not_paired"
            await session.ws.close()
            await eventually(lambda: companion.pairing.state == "not_recognized")
            assert upstream.account is None
            await eventually(lambda: upstream.configured[-1][0] is None)
            assert companion.store.pairing()
            assert companion.store.credentials()
            assert sorted(path.name for path in secrets.iterdir()) == [
                "credentials.json",
                "identity.json",
                "lamarzocco.json",
                "pairing.json",
            ]
            async with http.post(page_url + "/erase", data="{}") as reply:
                assert reply.status == 415

            # --- A forged erase, then a real one ---------------------------------------
            fake.mode = "bad_erase"
            await eventually(lambda: companion.link_reason == "AUTH")
            assert companion.store.pairing()
            fake.mode = "erase"
            await eventually(lambda: companion.store.pairing() is None)
            assert (await companion.status())["paired"] is False
            assert companion.pairing.state == "unpaired"
            assert companion.device_id is None, "Forget erases the log"
            assert await companion.logs.meta("device") is None, "Forget erases the log"
            assert (await companion.logs.stats("AA:BB:CC:DD:EE:FF"))["rows"] == 0
            assert sorted(path.name for path in secrets.iterdir()) == ["identity.json"]
            await asyncio.sleep(0.3)
            assert len(fake.pair_requests) == 2, (
                "no new request on its own after the controller forgot it"
            )

            # --- Pair button (entry point b): a refused reveal shows no code -------------
            fake.pair_state, fake.reveal_status = "pending", 400
            async with http.post(page_url + "/pair", json={}) as reply:
                assert reply.status == 202
            await eventually(lambda: companion.pairing.state == "error")
            assert companion.pairing.code is None
            assert companion.store.pairing() is None
            assert "commitment" in fake.pair_requests[2]
            assert "publicKey" in fake.pair_requests[3]

            # --- An approved pairing whose save fails is an error, never stuck -----
            fake.pair_state, fake.reveal_status = "approved", 202

            def refused(*_: object) -> NoReturn:
                raise OSError("disk full")

            with monkeypatch.context() as patch:
                patch.setattr(companion.store, "save_pairing", refused)
                async with http.post(page_url + "/pair", json={}) as reply:
                    assert reply.status == 202
                await eventually(lambda: companion.pairing.state == "error")

            # --- Paired again, then not recognized: "Erase this pairing" on the page ----
            fake.mode, fake.pair_state, fake.reveal_status = "ok", "approved", 202
            async with http.post(page_url + "/pair", json={}) as reply:
                assert reply.status == 202
            session = await asyncio.wait_for(fake.sessions.get(), 5)
            await eventually(lambda: companion.link == "open")
            fake.mode = "not_paired"
            await session.ws.close()
            await eventually(lambda: companion.pairing.state == "not_recognized")
            async with http.post(page_url + "/erase", json={}) as reply:
                assert reply.status == 200
                assert (await reply.json())["paired"] is False
            assert sorted(path.name for path in secrets.iterdir()) == ["identity.json"]
            await eventually(
                lambda: companion.pairing.state == "unpaired" and companion.device_name is None
            )
            await pages.close()
            await companion.logs.close()
            await companion.relay.close()
    await server.close()


def test_link(monkeypatch: pytest.MonkeyPatch) -> None:
    """Companion link: pairing, handshake, pings, sync hold silence, cfg, creds, route, hold,
    commands, errors, link version and erase."""
    monkeypatch.setattr(service, "BACKOFF_S", (0.2,) * 5)
    monkeypatch.setattr(service, "RETRY_LATER_S", 0.2)
    monkeypatch.setattr(service, "PING_S", {"companion": 0.4, "direct": 60})
    monkeypatch.setattr(service, "CONFIRM_S", 0.4)
    monkeypatch.setattr(service, "FULL_RETRY_S", (0.1,))
    monkeypatch.setattr(service, "STALL_WARN_S", 0.2)
    lines = Lines()
    logger = logging.getLogger("obbw")
    logger.addHandler(lines)
    try:
        asyncio.run(scenario(monkeypatch, lines))
    finally:
        logger.removeHandler(lines)
