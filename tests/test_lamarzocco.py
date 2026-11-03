"""The companion's La Marzocco client against a fake La Marzocco cloud.

Offline, inside the image.
"""

import asyncio
import json
import logging
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from companion import crypto, lamarzocco
from companion.lamarzocco import LaMarzocco, request_proof, stomp_frame, stomp_parse
from companion.store import Account, Store

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).resolve().parents[1]
D = json.loads((ROOT / "tests/fixtures/lamarzocco-dashboard.json").read_text())
ACCOUNT: Account = {
    "email": "barista@example.com",
    "password": "correct horse",
    "serial": "MR012345",
}
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def test_stomp_codec() -> None:
    """The STOMP codec on the controller's own frames."""
    assert stomp_parse("\n\nCONNECTED\r\nversion:1.2\r\nheart-beat:0,0\r\n\r\n") == (
        "CONNECTED",
        {"version": "1.2", "heart-beat": "0,0"},
        "",
    )
    assert stomp_parse("MESSAGE\ndestination:/a\\cb\ndestination:/x\n\n{}") == (
        "MESSAGE",
        {"destination": "/a:b"},
        "{}",
    )
    assert stomp_parse("\n") is None
    for bad, why in (
        ("MESSAGE", "STOMP frame without a header end"),
        ("MESSAGE\nbroken\n\n", "malformed STOMP header"),
    ):
        with pytest.raises(ValueError, match=why):
            stomp_parse(bad)


def test_request_proof() -> None:
    """The request proof's rotation, checked by hand for one byte.

    'A' (65) → index 1, shift from work[2].
    """
    work = bytearray(range(32))
    work[1] = ((65 ^ 1) << 2 | (65 ^ 1) >> 6) & 0xFF
    assert request_proof("A", bytes(range(32))) == crypto.b64(crypto.sha256(bytes(work)))


class Cloud:
    """La Marzocco's customer-app API as the controller's client uses it."""

    def __init__(self) -> None:
        self.installations: dict[str, ec.EllipticCurvePublicKey] = {}  # id → public key
        self.calls: list[str] = []
        self.commands: list[tuple[str, str, str]] = []
        self.access: str | None = None
        self.refresh: str | None = None
        self.tokens = 0
        self.pong = True
        self.socket: web.WebSocketResponse | None = None
        self.subscription = ""
        self.subscribed = asyncio.Event()
        self.command_status = 200
        self.refuse_dashboard = 0

    def verify(self, request: web.Request) -> None:
        headers = request.headers
        installation = headers["X-App-Installation-Id"]
        public = self.installations[installation]
        der = public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        secret = crypto.sha256(
            f"{installation}.{crypto.b64(der)}.{crypto.b64(crypto.sha256(installation.encode()))}".encode()
        )
        base = f"{installation}.{headers['X-Nonce']}.{headers['X-Timestamp']}"
        assert UUID4.match(headers["X-Nonce"])
        assert headers["X-Timestamp"].isdigit()
        public.verify(
            crypto.unb64(headers["X-Request-Signature"]),
            f"{base}.{request_proof(base, secret)}".encode(),
            ec.ECDSA(hashes.SHA256()),
        )
        assert headers["User-Agent"] == "OpenBrewByWeight/1"

    def issue(self) -> web.Response:
        self.tokens += 1
        self.access, self.refresh = f"access-{self.tokens}", f"refresh-{self.tokens}"
        return web.json_response({"accessToken": self.access, "refreshToken": self.refresh})

    def authorized(self, request: web.Request) -> bool:
        self.verify(request)
        return request.headers.get("Authorization") == f"Bearer {self.access}"

    async def init(self, request: web.Request) -> web.Response:
        installation = request.headers["X-App-Installation-Id"]
        body = await request.json()
        der = crypto.unb64(body["pk"])
        assert len(der) == 91
        assert UUID4.match(installation)
        public = serialization.load_der_public_key(der)
        assert isinstance(public, ec.EllipticCurvePublicKey)
        secret = crypto.sha256(
            f"{installation}.{body['pk']}.{crypto.b64(crypto.sha256(installation.encode()))}".encode()
        )
        assert request.headers["X-Request-Proof"] == request_proof(
            f"{installation}.{crypto.b64(crypto.sha256(der))}", secret
        )
        self.installations[installation] = public
        self.calls.append("init")
        return web.json_response({})

    async def signin(self, request: web.Request) -> web.Response:
        self.verify(request)
        body = await request.json()
        self.calls.append("signin")
        if (body["username"], body["password"]) != (ACCOUNT["email"], ACCOUNT["password"]):
            return web.json_response({"message": "wrong"}, status=401)
        return self.issue()

    async def refreshtoken(self, request: web.Request) -> web.Response:
        self.verify(request)
        body = await request.json()
        self.calls.append("refresh")
        assert body == {"username": ACCOUNT["email"], "refreshToken": self.refresh}
        return self.issue()

    async def dashboard(self, request: web.Request) -> web.Response:
        assert request.match_info["serial"] == ACCOUNT["serial"]
        self.calls.append("dashboard")
        if self.refuse_dashboard:
            return web.Response(status=self.refuse_dashboard)
        return (
            web.json_response(D["read"]) if self.authorized(request) else web.Response(status=401)
        )

    async def command(self, request: web.Request) -> web.Response:
        assert self.authorized(request)
        self.commands.append(
            (request.match_info["name"], await request.text(), request.content_type)
        )
        return web.json_response({}, status=self.command_status)

    async def ws(self, request: web.Request) -> web.WebSocketResponse:
        self.verify(request)
        socket = web.WebSocketResponse(autoping=False)
        await socket.prepare(request)
        self.socket = socket

        async def text() -> str:
            while (message := await socket.receive()).type is aiohttp.WSMsgType.PING:
                await socket.pong(message.data)
            data = message.data
            assert isinstance(data, str)
            return data

        connect = stomp_parse((await text()).removesuffix("\0"))
        assert connect == (
            "CONNECT",
            {
                "host": "lion.lamarzocco.io",
                "accept-version": "1.2,1.1",
                "heart-beat": "0,0",
                "Authorization": f"Bearer {self.access}",
            },
            "",
        )
        await socket.send_str(stomp_frame("CONNECTED", {"version": "1.2", "heart-beat": "0,0"}))
        subscribe = await text()
        assert subscribe.endswith("\0")
        parsed = stomp_parse(subscribe.removesuffix("\0"))
        assert parsed is not None
        command, headers, _ = parsed
        assert command == "SUBSCRIBE"
        assert headers["destination"] == "/ws/sn/MR012345/dashboard"
        assert headers["ack"] == "auto"
        self.subscription = headers["id"]
        self.subscribed.set()
        async for message in socket:
            if message.type is aiohttp.WSMsgType.PING and self.pong:
                await socket.pong(message.data)
        return socket

    async def push(self, body: object) -> None:
        assert self.socket is not None
        await self.socket.send_str(
            stomp_frame(
                "MESSAGE",
                {
                    "destination": "/ws/sn/MR012345/dashboard",
                    "subscription": self.subscription,
                    "content-type": "application/json",
                },
                json.dumps(body),
            )
        )


class Lines(logging.Handler):
    """Everything the companion logs during the test, message by message."""

    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


class Events:
    """The companion's side of lamarzocco.Events, recorded in order."""

    def __init__(self) -> None:
        self.log: list[tuple[object, ...]] = []
        self.changed = asyncio.Event()

    def _record(self, *event: object) -> None:
        self.log.append(event)
        self.changed.set()

    def account(self, ok: bool) -> None:
        self._record("account", ok)

    def upstream(self) -> None:
        self._record("upstream")

    def subscribed(self) -> None:
        self._record("subscribed")

    def pushed(self, data: dict[str, object], ac: int) -> None:
        self._record("pushed", data, ac)

    def polled(self, _data: dict[str, object], ac: int, first: bool) -> None:
        self._record("polled", ac, first)

    def renewed(self) -> None:
        self._record("renewed")

    async def wait(self, predicate: Callable[[], object]) -> None:
        """Until predicate holds, for at most 5 s (a caller may bound it tighter)."""

        async def check() -> None:
            while not predicate():
                self.changed.clear()
                await self.changed.wait()

        await asyncio.wait_for(check(), 5)


async def scenario(monkeypatch: pytest.MonkeyPatch, lines: Lines) -> None:
    cloud = Cloud()
    app = web.Application()
    root = "/api/customer-app"
    app.router.add_post(root + "/auth/init", cloud.init)
    app.router.add_post(root + "/auth/signin", cloud.signin)
    app.router.add_post(root + "/auth/refreshtoken", cloud.refreshtoken)
    app.router.add_get(root + "/things/{serial}/dashboard", cloud.dashboard)
    app.router.add_post(root + "/things/{serial}/command/{name}", cloud.command)
    app.router.add_get("/ws/connect", cloud.ws)
    server = TestServer(app, host="127.0.0.1")
    await server.start_server()
    base = f"http://127.0.0.1:{server.port}"
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-lm-") as temporary:
        store = Store(Path(temporary))
        store.save_credentials(1, ACCOUNT)
        async with aiohttp.ClientSession() as http:

            def client(events: Events) -> LaMarzocco:
                return LaMarzocco(
                    store,
                    http,
                    events,
                    api_root=base + root,
                    ws_url=base.replace("http", "ws") + "/ws/connect",
                )

            # Registration, sign-in, WebSocket subscription and pushes.
            events = Events()
            lm = client(events)
            lm.configure(ACCOUNT, "ws", True)
            await events.wait(lambda: ("subscribed",) in events.log)
            await asyncio.wait_for(cloud.subscribed.wait(), 3)
            assert cloud.calls[:2] == ["init", "signin"]
            assert ("account", True) in events.log
            assert lm.sub
            assert lm.ep == 1
            assert lm.up
            assert 2990 < lm.tok <= 3000
            assert lm.signed_in_for(ACCOUNT)
            assert not lm.signed_in_for({**ACCOUNT, "serial": "MR000000"})
            installation = next(iter(cloud.installations))
            assert (store.dir / "lamarzocco.json").stat().st_mode & 0o777 == 0o600
            await cloud.push(D["pushes"]["standby"])
            await events.wait(lambda: events.log[-1][0] == "pushed")
            assert events.log[-1] == ("pushed", D["pushes"]["standby"], 0)

            # Reads and commands, with the id of the last command in each observation.
            status, data, ac = await lm.read()
            assert (status, data, ac) == (200, D["read"], 0)
            assert await lm.command(7, "temp", 935) == 200
            assert await lm.command(8, "standby") == 200
            assert await lm.command(9, "on") == 200
            assert cloud.commands == [
                (
                    "CoffeeMachineSettingCoffeeBoilerTargetTemperature",
                    '{"boilerIndex":1,"targetTemperature":93.5}',
                    "application/json",
                ),
                ("CoffeeMachineChangeMode", '{"mode":"StandBy"}', "application/json"),
                ("CoffeeMachineChangeMode", '{"mode":"BrewingMode"}', "application/json"),
            ]
            await cloud.push(D["pushes"]["temperature"])
            await events.wait(
                lambda: (
                    events.log[-1][0] == "pushed"
                    and events.log[-1][1] == D["pushes"]["temperature"]
                )
            )
            assert events.log[-1][2] == 9
            assert (await lm.read())[2] == 9
            cloud.command_status = 409
            assert await lm.command(10, "temp", 1001) == 409
            assert lm.last_command == 10

            # WebSocket pings keep it alive; a missing pong ends the subscription, then it
            # resubscribes.
            await asyncio.sleep(1.5)
            assert lm.up, "pongs keep the subscription alive"
            assert lm.ep == 1, "pongs keep the subscription alive"
            cloud.pong = False
            cloud.subscribed.clear()
            async with asyncio.timeout(3):
                await events.wait(lambda: not lm.sub)
            assert any("no pong within" in line for line in lines.lines), (
                "a silent WebSocket is named"
            )
            cloud.pong = True
            await asyncio.wait_for(cloud.subscribed.wait(), 3)
            await events.wait(lambda: lm.sub)
            assert lm.ep == 2, "a reconnection reuses the token"
            assert cloud.calls.count("signin") == 1, "a reconnection reuses the token"

            # Token renewal before it runs out: only the renew loop refreshes, then the
            # companion's read.
            monkeypatch.setattr(lamarzocco, "RENEW_AFTER_S", 0.5)
            lm.configure(ACCOUNT, "api", True)  # Restarts its tasks with the short token life.
            await events.wait(lambda: ("renewed",) in events.log)
            assert cloud.calls.count("refresh") >= 1
            assert lm.access == cloud.access
            monkeypatch.setattr(lamarzocco, "RENEW_AFTER_S", 50 * 60)
            lm.stop()
            await asyncio.sleep(0.1)
            assert not lm.sub
            refreshes, renewals = cloud.calls.count("refresh"), events.log.count(("renewed",))
            # Long past due: a read uses the token it has and refreshes nothing.
            lm.issued_at -= 3 * 3600
            assert (await lm.read())[1] is not None
            assert cloud.calls.count("refresh") == refreshes
            lm.access = None  # As after a 401: the read gets a new token and reports it.
            refreshes, accounts = cloud.calls.count("refresh"), events.log.count(("account", True))
            assert (await lm.read())[1] is not None
            assert cloud.calls.count("refresh") == refreshes + 1
            assert events.log.count(("account", True)) == accounts + 1
            assert events.log.count(("renewed",)) == renewals

            # A refused dashboard or command (401/403) marks the data plane; a 200 clears it.
            cloud.refuse_dashboard = 403
            upstreams = events.log.count(("upstream",))
            assert (await lm.read())[:2] == (403, None)
            assert lm.refused
            assert events.log.count(("upstream",)) == upstreams + 1, (
                "the refusal is reported at once"
            )
            assert any("answers 401/403" in line for line in lines.lines), (
                "a refused data plane is logged"
            )
            cloud.refuse_dashboard = 0
            assert (await lm.read())[1] is not None
            assert not lm.refused
            assert any("accepts reads and commands again" in line for line in lines.lines)
            cloud.refuse_dashboard = 500
            assert (await lm.read())[:2] == (500, None)
            assert any("dashboard read answered 500" in line for line in lines.lines)
            cloud.refuse_dashboard = 0
            cloud.command_status = 403
            assert await lm.command(13, "on") == 403
            assert lm.refused
            cloud.command_status = 200

            # The installation survives a restart: no second registration, same id.
            events = Events()
            lm = client(events)
            lm.configure(ACCOUNT, "api", True)
            await events.wait(lambda: [e for e in events.log if e[0] == "polled"][1:])
            polls = [e for e in events.log if e[0] == "polled"]
            assert polls[0][2] is True
            assert polls[1][2] is False
            assert lm.sub
            assert lm.up
            assert lm.ep == 1
            assert cloud.calls.count("init") == 1
            assert list(cloud.installations) == [installation]
            # Show power state off: La Marzocco stays on the controller.
            lm.configure(ACCOUNT, "api", False)
            await asyncio.sleep(0.1)
            calls = len(cloud.calls)
            lm.access = None
            lm.configure(None, "api", False)
            lm.configure(ACCOUNT, "api", False)
            await asyncio.sleep(0.7)
            assert len(cloud.calls) == calls, "no sign-in, renewal or polling"
            assert not lm.sub, "no sign-in, renewal or polling"
            assert not lm.tasks, "no sign-in, renewal or polling"
            assert (await lm.read())[1] is None
            assert await lm.command(12, "on") == 0
            assert len(cloud.calls) == calls
            lm.configure(None, "api", True)

            # Erasing the account keeps the installation; erasing the pairing removes it.
            store.erase_account()
            assert (store.dir / "lamarzocco.json").exists()
            assert store.credentials() is None

            # A refused account: one sign-in, reported once, never retried with the same account.
            lm.erase()
            store.erase_pairing()
            assert not (store.dir / "lamarzocco.json").exists()
            wrong: Account = {**ACCOUNT, "password": "wrong"}
            store.save_credentials(2, wrong)
            signins = cloud.calls.count("signin")
            lm.configure(wrong, "ws", True)
            await events.wait(lambda: ("account", False) in events.log)
            await asyncio.sleep(0.5)
            assert cloud.calls.count("signin") == signins + 1
            assert lm.rejected_for(wrong)
            assert cloud.calls.count("init") == 2, "erase means a new installation"
            assert len(cloud.installations) == 2, "erase means a new installation"
            assert (await lm.read())[1] is None
            assert await lm.command(11, "on") == 0
            lm.stop()
    await server.close()


def test_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Companion La Marzocco client: registration, signing, STOMP, commands, renewal."""
    monkeypatch.setattr(lamarzocco, "PING_S", 0.2)
    monkeypatch.setattr(lamarzocco, "PONG_TIMEOUT_S", 1.0)
    monkeypatch.setattr(lamarzocco, "POLL_S", 0.3)
    monkeypatch.setattr(lamarzocco, "RETRY_S", (0.1,) * 6)
    lines = Lines()
    logger = logging.getLogger("obbw")
    logger.addHandler(lines)
    try:
        asyncio.run(scenario(monkeypatch, lines))
    finally:
        logger.removeHandler(lines)
