#!/usr/bin/env python3
"""The companion against a fake controller: pairing, the link and the La Marzocco route.

The fake controller follows docs/COMPANION_LINK.md of the firmware with the
shared vector keys; La Marzocco is replaced by a scripted upstream. Offline,
inside the image (see the README).
"""

import asyncio
import json
import os
import socket
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from companion import crypto, service  # noqa: E402
from companion.link import FrameCodec  # noqa: E402
from companion.service import Companion, web_app  # noqa: E402

V = json.loads((ROOT / "tests/fixtures/companion-link-v1.vectors.json").read_text())
D = json.loads((ROOT / "tests/fixtures/lamarzocco-dashboard.json").read_text())
ACCOUNT = {"email": "barista@example.com", "password": "correct horse", "serial": "MR012345"}
COMPANION_KEY, CONTROLLER_KEY = crypto.unb64(V["companionKey"]), crypto.unb64(V["controllerKey"])
SECRET = bytes.fromhex(V["pairingSecret"])
TO_CONTROLLER = {"ping", "lm", "creds", "st", "res"}

service.BACKOFF_S = (0.2, 0.2, 0.2, 0.2)
service.RETRY_LATER_S = 0.2
service.PING_S = {"companion": 0.4, "direct": 60}
service.CONFIRM_S = 0.4
service.FULL_RETRY_S = (0.1,)


class Upstream:
    """Scripted stand-in for the La Marzocco client, with the same interface."""

    def __init__(self, store, events):
        self.events = events
        self.sub, self.ep, self.up, self.tok = False, 0, False, 0
        self.account, self.signed, self.rejected = None, False, False
        self.reads, self.commands, self.configured = 0, [], []
        self.last_command, self.command_status, self.confirm = 0, 200, None

    def configure(self, account, conn, observe):
        self.configured.append((account and account["email"], conn, observe))
        identity = account and (account["email"], account["password"], account["serial"])
        if identity == self.account:
            return
        self.account, self.signed, self.rejected = identity, False, False
        if account:
            asyncio.get_running_loop().call_later(0.05, self.sign_in, account["password"] == "correct horse")

    def sign_in(self, ok):
        self.signed, self.rejected = ok, not ok
        self.tok = 3000 if ok else 0
        self.events.account(ok)
        if ok:
            self.subscribe()

    def subscribe(self):
        self.sub, self.up = True, True
        self.ep += 1
        self.tok = 3000
        self.events.upstream()
        self.events.subscribed()

    def signed_in_for(self, account):
        return self.signed and self.account == (account["email"], account["password"], account["serial"])

    def rejected_for(self, account):
        return self.rejected and self.account == (account["email"], account["password"], account["serial"])

    def stop(self):
        pass

    def erase(self):
        self.account, self.signed, self.sub, self.up = None, False, False, False

    async def read(self):
        self.reads += 1
        return 200, D["read"], self.last_command

    async def command(self, command_id, op, value=None):
        self.last_command = command_id
        self.commands.append((command_id, op, value))
        if self.confirm:
            self.events.pushed(self.confirm, command_id)
        return self.command_status


class Controller:
    """The controller's pairing routes and link endpoint, driven by the test."""

    def __init__(self):
        self.pair_requests, self.pair_state, self.mode, self.retries = [], "pending", "ok", 0
        self.commitment, self.key_sent, self.revealed, self.reveal_status = None, False, False, 202
        self.sessions = asyncio.Queue()

    async def pair_post(self, request):
        assert request.content_type == "application/json"
        body = await request.json()
        self.pair_requests.append(body)
        if "commitment" in body:  # Commit: a new request, whose key is made afterwards.
            assert "publicKey" not in body
            self.commitment, self.key_sent, self.revealed = body["commitment"], False, False
            return web.json_response({"state": "pending", "expiresInS": 600}, status=202)
        assert self.key_sent, "the companion reveals its key only after it received the controller's"
        assert crypto.b64(crypto.commitment(crypto.unb64(body["publicKey"], 65))) == self.commitment
        if self.reveal_status != 202:
            return web.json_response({"error": "INVALID_REQUEST"}, status=self.reveal_status)
        self.revealed = True
        return web.json_response({"state": "pending", "controllerKey": V["controllerKey"], "expiresInS": 590},
                                 status=202)

    async def pair_get(self, request):
        assert request.query["id"] == self.pair_requests[-1]["id"]
        self.key_sent = True
        state = "pending" if self.pair_state == "approved" and not self.revealed else self.pair_state
        return web.json_response({"state": state, "controllerKey": V["controllerKey"]})

    async def link(self, request):
        if self.mode == "not_paired":
            return web.json_response({"error": "COMPANION_NOT_PAIRED"}, status=404)
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        hello = json.loads(await ws.receive_str())
        assert hello["t"] == "hello" and hello["protocol"] == 1 and hello["name"] == "Kitchen server"
        nc = crypto.unb64(hello["nonce"], 16)
        mode = self.mode
        if mode == "retry":
            self.retries -= 1
            self.mode = "retry" if self.retries > 0 else "ok"
            await ws.send_json({"t": "error", "code": "RETRY_LATER"})
        elif mode in ("erase", "bad_erase"):
            await ws.send_json({"t": "erase", "mac": crypto.b64(crypto.mac(SECRET if mode == "erase" else bytes(32),
                                                                           b"E", nc))})
        else:
            ns = os.urandom(16)
            await ws.send_json({"t": "challenge", "nonce": crypto.b64(ns)})
            proof = json.loads(await ws.receive_str())
            assert crypto.unb64(proof["mac"]) == crypto.mac(SECRET, b"C", nc, ns), "the companion proves the secret"
            await ws.send_json({"t": "ready", "mac": crypto.b64(crypto.mac(SECRET, b"F", nc, ns))})
            session = Session(ws, FrameCodec(crypto.session_key(SECRET, nc, ns), send=b"f", receive=b"c"))
            await self.sessions.put(session)
            async for message in ws:
                frame = session.codec.decode(message.data)
                assert frame["t"] in TO_CONTROLLER, frame
                session.frames.put_nowait(frame)
            session.frames.put_nowait(None)
        await ws.close()
        return ws


class Session:
    def __init__(self, ws, codec):
        self.ws, self.codec, self.frames = ws, codec, asyncio.Queue()

    async def send(self, frame):
        await self.ws.send_str(self.codec.encode(frame))

    async def next(self, kind, timeout=3, skip=("ping",)):
        """The next frame of this type; frames listed in skip may come first."""
        while True:
            frame = await asyncio.wait_for(self.frames.get(), timeout)
            assert frame is not None, f"the link closed while waiting for {kind}"
            if frame["t"] == kind:
                return frame
            assert frame["t"] in skip, f"expected {kind}, got {frame}"

    async def quiet(self, seconds, skip=("ping",)):
        """Nothing but pings for a while."""
        deadline = asyncio.get_running_loop().time() + seconds
        try:
            while True:
                frame = await asyncio.wait_for(self.frames.get(), deadline - asyncio.get_running_loop().time())
                assert frame is not None and frame["t"] in skip, f"unexpected {frame}"
        except asyncio.TimeoutError:
            pass


async def eventually(predicate, timeout=3):
    for _ in range(int(timeout / 0.02)):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not reached")


def encrypt(generation, account):
    iv = os.urandom(12)
    ct = AESGCM(crypto.credentials_key(SECRET)).encrypt(iv, json.dumps(account).encode(),
                                                         f"obbw-creds|{generation}".encode())
    return {"t": "creds", "gen": generation, "iv": crypto.b64(iv), "ct": crypto.b64(ct)}


async def main():
    fake = Controller()
    app = web.Application()
    app.router.add_post("/api/v1/companion/pair", fake.pair_post)
    app.router.add_get("/api/v1/companion/pair", fake.pair_get)
    app.router.add_get("/api/v1/companion/link", fake.link)
    server = TestServer(app, host="127.0.0.1")
    await server.start_server()
    target = ("Cafe Bar", ("127.0.0.1", server.port))
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-link-") as temporary:
        data = Path(temporary)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as http:
            # The identity holds the vector's companion key, so the code and secret match the firmware's.
            seed = service.Store(data)
            seed.write("identity", {"id": "0b9f6a3c-2f4e-4d7a-9c1b-5e8f0a1d2c3b", "key": V["companionPrivate"]})
            companion = Companion("Kitchen server", data, http, Upstream)
            upstream = companion.lm
            pages = TestServer(web_app(companion), host="127.0.0.1")
            await pages.start_server()
            page_url = f"http://127.0.0.1:{pages.port}/__companion"
            async with http.get(page_url + "/") as reply:
                page = await reply.text()
                assert reply.status == 200 and "@STYLE@" not in page and "--accent" in page
                assert reply.headers["Cache-Control"] == "no-store"
            async with http.post(page_url + "/pair", data="{}") as reply:
                assert reply.status == 415, "pairing needs a JSON request a foreign page cannot send unasked"
            async with http.post(page_url + "/pair", json={}) as reply:
                assert reply.status == 409 and (await reply.json())["error"] == "NO_CONTROLLER"

            # --- Pairing (entry point a): commit, then reveal, polled while pending --
            companion.spawn(companion.run_link())
            companion.set_controller(target)
            await eventually(lambda: companion.pairing.state == "pending" and companion.pairing.code)
            identity = {"id": "0b9f6a3c-2f4e-4d7a-9c1b-5e8f0a1d2c3b", "name": "Kitchen server", "version": "1.0.0",
                        "protocol": 1}
            assert fake.pair_requests == [{**identity, "commitment": V["commitment"]},
                                          {**identity, "publicKey": V["companionKey"]}]
            async with http.get(page_url + "/status") as reply:
                status = await reply.json()
            assert status["pairing"]["code"] == V["sas"] and status["pairing"]["expiresInS"] > 590
            assert status["paired"] is False and status["link"] == "down" and status["name"] == "Kitchen server"
            companion.set_controller(target)  # Another announcement while pending sends nothing new.
            await asyncio.sleep(0.3)
            assert len(fake.pair_requests) == 2
            fake.pair_state = "approved"
            session = await asyncio.wait_for(fake.sessions.get(), 5)
            assert companion.store.pairing()["secret"] == SECRET
            secrets = data / "secrets"
            assert secrets.stat().st_mode & 0o777 == 0o700
            assert all(path.stat().st_mode & 0o777 == 0o600 for path in secrets.iterdir())
            await eventually(lambda: companion.link == "open")
            assert companion.status()["paired"] and companion.status()["pairedWith"] == "Cafe Bar"
            assert companion.ws.get_extra_info("socket").getsockopt(
                socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT) == 30000, "an unacknowledged ping closes the link"
            async with http.post(page_url + "/erase", json={}) as reply:
                assert reply.status == 409, "a working pairing is forgotten in Admin, not here"

            # --- A ping as the link opens, cfg, then the account ------------------
            assert await session.next("ping", skip=()) == {"q": 1, "t": "ping", "up": False}
            await session.send({"t": "cfg", "lm": True, "conn": "ws", "observe": True})
            assert await session.next("lm") == {"q": 2, "t": "lm", "sub": False, "ep": 0, "tok": 0}
            assert upstream.configured[-1] == (None, "ws", True), "no account yet"
            await session.send(encrypt(3, ACCOUNT))
            assert await session.next("creds") == {"q": 3, "t": "creds", "gen": 3, "ok": True}
            assert await session.next("lm") == {"q": 4, "t": "lm", "sub": False, "ep": 0, "tok": 3000}, \
                "a sign-in reports the new token's life at once"
            assert await session.next("lm") == {"q": 5, "t": "lm", "sub": True, "ep": 1, "tok": 3000}
            assert await session.next("ping", skip=()) == {"q": 6, "t": "ping", "up": True}, "a ping when up changes"
            assert json.loads((secrets / "credentials.json").read_text()) == {"gen": 3, **ACCOUNT}
            await session.send(encrypt(3, ACCOUNT))  # The controller resends it after each new session.
            assert (await session.next("creds"))["ok"] is True and upstream.configured[-1][0] == ACCOUNT["email"]
            await session.next("lm")

            # --- Nothing is forwarded while the route is direct --------------------
            upstream.events.pushed(D["pushes"]["standby"], 0)
            await session.quiet(0.3)

            # --- Route to the companion: an immediate ping, then `full` -----------
            await session.send({"t": "route", "to": "companion"})
            assert (await session.next("ping", skip=()))["up"] is True
            full = await session.next("st")
            assert full["k"] == "full" and full["ep"] == 1 and full["ac"] == 0
            assert full["d"] == service.dashboard.reduce(D["read"], push=False)
            await session.next("ping", skip=())  # Every PING_S["companion"] from now on.

            # --- Pushes: filtered per event, dropped when they carry nothing -------
            upstream.events.pushed(D["pushes"]["commandsOnly"], 0)
            upstream.events.pushed(D["pushes"]["backflush"], 0)
            push = await session.next("st")
            assert push["k"] == "push" and push["d"]["widgets"][0]["code"] == "CMBackFlush"
            assert "ac" not in push, "pushes take their order from when the controller receives them"

            # --- Hold: pushes go at once, reads wait and go once -------------------
            await session.send({"t": "hold", "on": True})
            await eventually(lambda: companion.hold)
            upstream.events.renewed()
            assert (await session.next("lm"))["tok"] == 3000
            upstream.events.pushed(D["pushes"]["standby"], 0)
            assert (await session.next("st"))["k"] == "push"
            upstream.events.polled(D["read"], 0, False)
            await session.quiet(0.3)
            await session.send({"t": "hold", "on": False})
            held = await session.next("st")
            assert held["k"] == "read" and held["d"]["widgets"][0]["code"] == "CMMachineStatus"
            await session.quiet(0.3)

            # --- Commands --------------------------------------------------------
            reads = upstream.reads
            await session.send({"t": "cmd", "id": 7, "op": "temp", "v": 935})
            assert (await session.next("res"))["id"] == 7 and session.codec.received > 7
            read = await session.next("st", timeout=2)  # No confirming push: one read after CONFIRM_S.
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
            assert (await session.next("lm"))["ep"] == 2
            assert (await session.next("st"))["k"] == "full"

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

            # --- A newer controller's frame type is ignored and counted ------------
            await session.send({"t": "webhook", "id": 1})
            await session.send({"t": "hold", "on": True})
            await eventually(lambda: companion.hold)
            assert companion.link == "open" and companion.status()["unknownFrames"] == 1
            await session.send({"t": "hold", "on": False})

            # --- A frame out of sequence closes the link; it reopens after backoff -
            body = json.dumps({"q": session.codec.sent + 2, "t": "hold", "on": True}, separators=(",", ":"))
            await session.ws.send_str(f"{session.codec._tag(b'f', body)}.{body}")
            await eventually(lambda: companion.link == "retry")
            assert companion.link_reason == "PROTOCOL"
            session = await asyncio.wait_for(fake.sessions.get(), 3)
            await eventually(lambda: companion.link == "open")
            assert companion.route == "direct" and not companion.hold, "every session starts direct"
            assert companion.status()["unknownFrames"] == 0

            # --- Any unexpected error ends only that session -----------------------
            save = companion.store.save_credentials

            def broken(*_):
                raise OSError("disk full")
            companion.store.save_credentials = broken
            await session.send(encrypt(5, ACCOUNT))
            await eventually(lambda: companion.link_reason == "ERROR")
            companion.store.save_credentials = save
            session = await asyncio.wait_for(fake.sessions.get(), 3)
            await eventually(lambda: companion.link == "open")

            # --- RETRY_LATER retries at its short interval, without escalating -----
            service.BACKOFF_S = (0.2, 30, 30, 30)
            fake.mode, fake.retries = "retry", 3
            await session.ws.close()
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            await eventually(lambda: companion.link == "open")

            # --- ...and an announcement reconnects at once -------------------------
            service.RETRY_LATER_S = 30
            fake.mode, fake.retries = "retry", 1
            await session.ws.close()
            await eventually(lambda: companion.link_reason == "RETRY_LATER")
            await asyncio.sleep(0.3)
            assert fake.sessions.empty()
            companion.set_controller(target)
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            await eventually(lambda: companion.link == "open")
            service.RETRY_LATER_S = 0.2

            # --- Erasing the account keeps the installation -------------------------
            (secrets / "lamarzocco.json").write_text("{}")
            await session.send({"t": "creds", "gen": 4, "erase": True})
            await eventually(lambda: not (secrets / "credentials.json").exists())
            assert (secrets / "lamarzocco.json").exists() and upstream.account is None
            await session.send(encrypt(6, ACCOUNT))
            assert (await session.next("creds", skip=("ping", "lm")))["ok"] is True

            # --- Not recognized: La Marzocco stops, every secret stays ----------------
            service.BACKOFF_S = (0.2, 0.2, 0.2, 0.2)
            fake.mode = "not_paired"
            await session.ws.close()
            await eventually(lambda: companion.pairing.state == "not_recognized")
            assert upstream.account is None and upstream.configured[-1][0] is None
            assert companion.store.pairing() and companion.store.credentials()
            assert sorted(path.name for path in secrets.iterdir()) == [
                "credentials.json", "identity.json", "lamarzocco.json", "pairing.json"]
            async with http.post(page_url + "/erase", data="{}") as reply:
                assert reply.status == 415

            # --- A forged erase, then a real one ---------------------------------------
            fake.mode = "bad_erase"
            await eventually(lambda: companion.link_reason == "AUTH")
            assert companion.store.pairing()
            fake.mode = "erase"
            await eventually(lambda: companion.store.pairing() is None)
            assert companion.status()["paired"] is False and companion.pairing.state == "unpaired"
            assert sorted(path.name for path in secrets.iterdir()) == ["identity.json"]
            await asyncio.sleep(0.3)
            assert len(fake.pair_requests) == 2, "no new request on its own after the controller forgot it"

            # --- Pair button (entry point b): a refused reveal shows no code -------------
            fake.pair_state, fake.reveal_status = "pending", 400
            async with http.post(page_url + "/pair", json={}) as reply:
                assert reply.status == 202
            await eventually(lambda: companion.pairing.state == "error")
            assert companion.pairing.code is None and companion.store.pairing() is None
            assert "commitment" in fake.pair_requests[2] and "publicKey" in fake.pair_requests[3]

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
                assert reply.status == 200 and (await reply.json())["paired"] is False
            assert sorted(path.name for path in secrets.iterdir()) == ["identity.json"]
            assert companion.pairing.state == "unpaired"
            await pages.close()
    await server.close()
    print("Companion link: pairing, handshake, pings, cfg, creds, route, hold, commands, errors and erase OK")


asyncio.run(main())
