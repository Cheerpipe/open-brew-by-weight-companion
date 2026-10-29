#!/usr/bin/env python3
"""The companion's La Marzocco client against a fake La Marzocco cloud (offline, inside the image)."""

import asyncio
import json
import logging
import re
import sys
import tempfile
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from companion import crypto, lamarzocco  # noqa: E402
from companion.lamarzocco import LaMarzocco, request_proof, stomp_frame, stomp_parse  # noqa: E402
from companion.store import Store  # noqa: E402

D = json.loads((ROOT / "tests/fixtures/lamarzocco-dashboard.json").read_text())
ACCOUNT = {"email": "barista@example.com", "password": "correct horse", "serial": "MR012345"}
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

lamarzocco.PING_S, lamarzocco.PONG_TIMEOUT_S, lamarzocco.POLL_S = 0.2, 1.0, 0.3
lamarzocco.RETRY_S = (0.1,) * 6

# The STOMP codec on the controller's own frames.
assert stomp_parse("\n\nCONNECTED\r\nversion:1.2\r\nheart-beat:0,0\r\n\r\n") == (
    "CONNECTED", {"version": "1.2", "heart-beat": "0,0"}, "")
assert stomp_parse("MESSAGE\ndestination:/a\\cb\ndestination:/x\n\n{}") == ("MESSAGE", {"destination": "/a:b"}, "{}")
assert stomp_parse("\n") is None
for bad in ("MESSAGE", "MESSAGE\nbroken\n\n"):
    try:
        stomp_parse(bad)
        raise AssertionError(bad)
    except ValueError:
        pass
# The request proof's rotation, checked by hand for one byte: 'A' (65) → index 1, shift from work[2].
work = bytearray(range(32))
work[1] = ((65 ^ 1) << 2 | (65 ^ 1) >> 6) & 0xFF
assert request_proof("A", bytes(range(32))) == crypto.b64(crypto.sha256(bytes(work)))


class Cloud:
    """La Marzocco's customer-app API as the controller's client uses it."""

    def __init__(self):
        self.installations = {}  # id → public key
        self.calls, self.commands = [], []
        self.access, self.refresh = None, None
        self.tokens = 0
        self.pong = True
        self.socket = None
        self.subscribed = asyncio.Event()
        self.command_status = 200
        self.refuse_dashboard = 0

    def verify(self, request):
        headers = request.headers
        installation = headers["X-App-Installation-Id"]
        public = self.installations[installation]
        der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        secret = crypto.sha256(f"{installation}.{crypto.b64(der)}.{crypto.b64(crypto.sha256(installation.encode()))}"
                               .encode())
        base = f"{installation}.{headers['X-Nonce']}.{headers['X-Timestamp']}"
        assert UUID4.match(headers["X-Nonce"]) and headers["X-Timestamp"].isdigit()
        public.verify(crypto.unb64(headers["X-Request-Signature"]), f"{base}.{request_proof(base, secret)}".encode(),
                      ec.ECDSA(hashes.SHA256()))
        assert headers["User-Agent"] == "OpenBrewByWeight/1"

    def issue(self):
        self.tokens += 1
        self.access, self.refresh = f"access-{self.tokens}", f"refresh-{self.tokens}"
        return web.json_response({"accessToken": self.access, "refreshToken": self.refresh})

    def authorized(self, request):
        self.verify(request)
        return request.headers.get("Authorization") == f"Bearer {self.access}"

    async def init(self, request):
        installation = request.headers["X-App-Installation-Id"]
        body = await request.json()
        der = crypto.unb64(body["pk"])
        assert len(der) == 91 and UUID4.match(installation)
        public = serialization.load_der_public_key(der)
        secret = crypto.sha256(f"{installation}.{body['pk']}.{crypto.b64(crypto.sha256(installation.encode()))}"
                               .encode())
        assert request.headers["X-Request-Proof"] == request_proof(
            f"{installation}.{crypto.b64(crypto.sha256(der))}", secret)
        self.installations[installation] = public
        self.calls.append("init")
        return web.json_response({})

    async def signin(self, request):
        self.verify(request)
        body = await request.json()
        self.calls.append("signin")
        if (body["username"], body["password"]) != (ACCOUNT["email"], ACCOUNT["password"]):
            return web.json_response({"message": "wrong"}, status=401)
        return self.issue()

    async def refreshtoken(self, request):
        self.verify(request)
        body = await request.json()
        self.calls.append("refresh")
        assert body == {"username": ACCOUNT["email"], "refreshToken": self.refresh}
        return self.issue()

    async def dashboard(self, request):
        assert request.match_info["serial"] == ACCOUNT["serial"]
        self.calls.append("dashboard")
        if self.refuse_dashboard:
            return web.Response(status=self.refuse_dashboard)
        return web.json_response(D["read"]) if self.authorized(request) else web.Response(status=401)

    async def command(self, request):
        assert self.authorized(request)
        self.commands.append((request.match_info["name"], await request.text(), request.content_type))
        return web.json_response({}, status=self.command_status)

    async def ws(self, request):
        self.verify(request)
        socket = web.WebSocketResponse(autoping=False)
        await socket.prepare(request)
        self.socket = socket

        async def text():
            while (message := await socket.receive()).type is aiohttp.WSMsgType.PING:
                await socket.pong(message.data)
            return message.data

        connect = stomp_parse((await text()).removesuffix("\0"))
        assert connect == ("CONNECT", {"host": "lion.lamarzocco.io", "accept-version": "1.2,1.1",
                                       "heart-beat": "0,0", "Authorization": f"Bearer {self.access}"}, "")
        await socket.send_str(stomp_frame("CONNECTED", {"version": "1.2", "heart-beat": "0,0"}))
        subscribe = await text()
        assert subscribe.endswith("\0")
        command, headers, _ = stomp_parse(subscribe.removesuffix("\0"))
        assert command == "SUBSCRIBE" and headers["destination"] == "/ws/sn/MR012345/dashboard"
        assert headers["ack"] == "auto"
        self.subscription = headers["id"]
        self.subscribed.set()
        async for message in socket:
            if message.type is aiohttp.WSMsgType.PING and self.pong:
                await socket.pong(message.data)
        return socket

    async def push(self, body):
        await self.socket.send_str(stomp_frame("MESSAGE", {
            "destination": "/ws/sn/MR012345/dashboard", "subscription": self.subscription,
            "content-type": "application/json"}, json.dumps(body)))


class Lines(logging.Handler):
    """Everything the companion logs during the test, message by message."""

    def __init__(self):
        super().__init__(level=logging.INFO)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class Events:
    def __init__(self):
        self.log = []
        self.changed = asyncio.Event()

    def _record(self, *event):
        self.log.append(event)
        self.changed.set()

    def account(self, ok): self._record("account", ok)
    def upstream(self): self._record("upstream")
    def subscribed(self): self._record("subscribed")
    def pushed(self, data, ac): self._record("pushed", data, ac)
    def polled(self, data, ac, first): self._record("polled", ac, first)
    def renewed(self): self._record("renewed")

    async def wait(self, predicate, timeout=5):
        async def check():
            while not predicate():
                self.changed.clear()
                await self.changed.wait()
        await asyncio.wait_for(check(), timeout)


async def main():
    lines = Lines()
    logging.getLogger("obbw").addHandler(lines)
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
            def client(events):
                return LaMarzocco(store, http, events, api_root=base + root, ws_url=base.replace("http", "ws") + "/ws/connect")

            # Registration, sign-in, WebSocket subscription and pushes.
            events = Events()
            lm = client(events)
            lm.configure(ACCOUNT, "ws", True)
            await events.wait(lambda: ("subscribed",) in events.log)
            await asyncio.wait_for(cloud.subscribed.wait(), 3)
            assert cloud.calls[:2] == ["init", "signin"] and ("account", True) in events.log
            assert lm.sub and lm.ep == 1 and lm.up and 2990 < lm.tok <= 3000
            assert lm.signed_in_for(ACCOUNT) and not lm.signed_in_for({**ACCOUNT, "serial": "MR000000"})
            installation = next(iter(cloud.installations))
            assert (store.dir / "lamarzocco.json").stat().st_mode & 0o777 == 0o600
            await cloud.push(D["pushes"]["standby"])
            await events.wait(lambda: events.log[-1][0] == "pushed")
            assert events.log[-1] == ("pushed", D["pushes"]["standby"], 0)

            # Reads and commands, with the id of the last command in each observation.
            status, data, ac = await lm.read()
            assert (status, data, ac) == (200, D["read"], 0)
            assert await lm.command(7, "temp", 935) == 200
            assert await lm.command(8, "standby") == 200 and await lm.command(9, "on") == 200
            assert cloud.commands == [
                ("CoffeeMachineSettingCoffeeBoilerTargetTemperature", '{"boilerIndex":1,"targetTemperature":93.5}',
                 "application/json"),
                ("CoffeeMachineChangeMode", '{"mode":"StandBy"}', "application/json"),
                ("CoffeeMachineChangeMode", '{"mode":"BrewingMode"}', "application/json")]
            await cloud.push(D["pushes"]["temperature"])
            await events.wait(lambda: events.log[-1][0] == "pushed" and events.log[-1][1] == D["pushes"]["temperature"])
            assert events.log[-1][2] == 9 and (await lm.read())[2] == 9
            cloud.command_status = 409
            assert await lm.command(10, "temp", 1001) == 409 and lm.last_command == 10

            # WebSocket pings keep it alive; a missing pong ends the subscription, then it resubscribes.
            await asyncio.sleep(1.5)
            assert lm.up and lm.ep == 1, "pongs keep the subscription alive"
            cloud.pong = False
            cloud.subscribed.clear()
            await events.wait(lambda: not lm.sub, timeout=3)
            assert any("no pong within" in line for line in lines.lines), "a silent WebSocket is named"
            cloud.pong = True
            await asyncio.wait_for(cloud.subscribed.wait(), 3)
            await events.wait(lambda: lm.sub)
            assert lm.ep == 2 and cloud.calls.count("signin") == 1, "a reconnection reuses the token"

            # Token renewal before it runs out: only the renew loop refreshes, then the companion's read.
            lamarzocco.RENEW_AFTER_S = 0.5
            lm.configure(ACCOUNT, "api", True)  # Restarts its tasks with the short token life.
            await events.wait(lambda: ("renewed",) in events.log)
            assert cloud.calls.count("refresh") >= 1 and lm.access == cloud.access
            lamarzocco.RENEW_AFTER_S = 50 * 60
            lm.stop()
            await asyncio.sleep(0.1)
            assert not lm.sub
            refreshes, renewals = cloud.calls.count("refresh"), events.log.count(("renewed",))
            lm.issued_at -= 3 * 3600  # Long past due: a read uses the token it has and refreshes nothing.
            assert (await lm.read())[1] is not None and cloud.calls.count("refresh") == refreshes
            lm.access = None  # As after a 401: the read gets a new token and reports it.
            refreshes, accounts = cloud.calls.count("refresh"), events.log.count(("account", True))
            assert (await lm.read())[1] is not None and cloud.calls.count("refresh") == refreshes + 1
            assert events.log.count(("account", True)) == accounts + 1 and events.log.count(("renewed",)) == renewals

            # A refused dashboard or command (401/403) marks the data plane; a 200 clears it.
            cloud.refuse_dashboard = 403
            upstreams = events.log.count(("upstream",))
            assert (await lm.read())[:2] == (403, None) and lm.refused
            assert events.log.count(("upstream",)) == upstreams + 1, "the refusal is reported at once"
            assert any("answers 401/403" in line for line in lines.lines), "a refused data plane is logged"
            cloud.refuse_dashboard = 0
            assert (await lm.read())[1] is not None and not lm.refused
            assert any("accepts reads and commands again" in line for line in lines.lines)
            cloud.refuse_dashboard = 500
            assert (await lm.read())[:2] == (500, None)
            assert any("dashboard read answered 500" in line for line in lines.lines)
            cloud.refuse_dashboard = 0
            cloud.command_status = 403
            assert await lm.command(13, "on") == 403 and lm.refused
            cloud.command_status = 200

            # The installation survives a restart: no second registration, same id.
            events = Events()
            lm = client(events)
            lm.configure(ACCOUNT, "api", True)
            await events.wait(lambda: [e for e in events.log if e[0] == "polled"][1:])
            polls = [e for e in events.log if e[0] == "polled"]
            assert polls[0][2] is True and polls[1][2] is False and lm.sub and lm.up and lm.ep == 1
            assert cloud.calls.count("init") == 1 and list(cloud.installations) == [installation]
            lm.configure(ACCOUNT, "api", False)  # Show power state off: La Marzocco stays on the controller.
            await asyncio.sleep(0.1)
            calls = len(cloud.calls)
            lm.access = None
            lm.configure(None, "api", False)
            lm.configure(ACCOUNT, "api", False)
            await asyncio.sleep(0.7)
            assert len(cloud.calls) == calls and not lm.sub and not lm.tasks, "no sign-in, renewal or polling"
            assert (await lm.read())[1] is None and await lm.command(12, "on") == 0 and len(cloud.calls) == calls
            lm.configure(None, "api", True)

            # Erasing the account keeps the installation; erasing the pairing removes it.
            store.erase_account()
            assert (store.dir / "lamarzocco.json").exists() and store.credentials() is None

            # A refused account: one sign-in, reported once, never retried with the same account.
            lm.erase()
            store.erase_pairing()
            assert not (store.dir / "lamarzocco.json").exists()
            wrong = {**ACCOUNT, "password": "wrong"}
            store.save_credentials(2, wrong)
            signins = cloud.calls.count("signin")
            lm.configure(wrong, "ws", True)
            await events.wait(lambda: ("account", False) in events.log)
            await asyncio.sleep(0.5)
            assert cloud.calls.count("signin") == signins + 1 and lm.rejected_for(wrong)
            assert cloud.calls.count("init") == 2 and len(cloud.installations) == 2, "erase means a new installation"
            assert (await lm.read())[1] is None and await lm.command(11, "on") == 0
            lm.stop()
    await server.close()
    print("Companion La Marzocco client: registration, signing, STOMP, commands, renewal OK")


asyncio.run(main())
