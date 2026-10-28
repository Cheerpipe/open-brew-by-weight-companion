#!/usr/bin/env python3
"""Several screens on the companion's one controller session, against a fake controller.

Home and the shot card, Settings, History and Stats groups (owner, fetches, promotion), Diagnostic
and the log, records, liveness, the command queue, takeover, 4003, the 1 MiB bound, and the upstream
op count for one screen against three. Offline, inside the image (see the README).
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import aiohttp  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import fake_controller  # noqa: E402
from companion import mux, service, upstream  # noqa: E402
from companion.service import Companion, web_app  # noqa: E402
from fake_controller import event, history_frame, log_frame  # noqa: E402

V = json.loads((ROOT / "tests/fixtures/companion-link-v1.vectors.json").read_text())
SECRET = bytes.fromhex(V["pairingSecret"])
ID = "0b9f6a3c-2f4e-4d7a-9c1b-5e8f0a1d2c3b"
CLIENTS = ["0123456789abcdef", "1123456789abcdef", "2123456789abcdef", "3123456789abcdef"]
DIRECT = "aaaaaaaaaaaaaaaaaaaaaaaa"

mux.IDLE_S = mux.DIAGNOSTIC_LINGER_S = 0.3
mux.ATTRIBUTION_S = 0.3
upstream.TICK_S = 0.05

HISTORY = {"op": "history", "on": True, "offset": 0, "limit": 20, "dir": "desc"}
STATS = {"op": "stats", "on": True, "offset": 0, "limit": 10, "sort": "date", "dir": "desc"}


class Idle:
    sub = up = False
    ep = tok = 0

    def __init__(self, store, events):
        pass

    def configure(self, *args):
        pass

    def erase(self):
        pass

    def stop(self):
        pass


async def eventually(predicate, timeout=3):
    for _ in range(int(timeout / 0.02)):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not reached")


class Browser:
    """One screen: a claimed page with its ui-stream."""

    def __init__(self, http, base, client):
        self.http, self.base, self.client = http, base, client
        self.frames, self.ws, self.code, self.reason = asyncio.Queue(), None, None, None

    async def claim(self):
        async with self.http.post(self.base + "/api/v1/ui/claim", json={},
                                  headers={"X-WebUI-Client": self.client, "X-Real-IP": "192.168.1.9"}) as reply:
            assert reply.status == 200

    async def open(self, ops=(), claim=True, **bind):
        if claim:
            await self.claim()
        self.ws = await self.http.ws_connect(self.base + "/api/v1/ui/ui-stream", headers={"X-Real-IP": "192.168.1.9"})
        asyncio.create_task(self._reader())
        await self.send({"op": "bind", "client": self.client, **({"ops": list(ops)} if ops else {}), **bind})
        return self

    async def _reader(self):
        while True:
            message = await self.ws.receive()
            if message.type is not aiohttp.WSMsgType.TEXT:
                break
            self.frames.put_nowait(json.loads(message.data))
        if message.type is aiohttp.WSMsgType.CLOSE:
            self.code, self.reason = message.data, message.extra
        else:
            self.code = self.ws.close_code
        self.frames.put_nowait(None)

    async def send(self, op):
        await self.ws.send_str(json.dumps(op))

    async def next(self, kind="any", timeout=2):
        """The next frame, skipping `alive`; kind "card" means a shot-card frame."""
        while True:
            frame = await asyncio.wait_for(self.frames.get(), timeout)
            assert frame is not None, f"the stream closed ({self.code}) while waiting for {kind}"
            if frame.get("type") == "alive" and kind != "alive":
                continue
            found = "card" if "type" not in frame else frame["type"]
            assert kind in ("any", found), f"expected {kind}, got {frame}"
            return frame

    async def quiet(self, seconds=0.3):
        try:
            frame = await asyncio.wait_for(self.frames.get(), seconds)
        except asyncio.TimeoutError:
            return
        assert frame is None or frame.get("type") == "alive", f"unexpected {frame}"

    async def closed(self, timeout=2):
        while True:
            frame = await asyncio.wait_for(self.frames.get(), timeout)
            if frame is None:
                return self.code

    async def close(self):
        await self.ws.close()


async def ops_after(session, count, timeout=2):
    """The controller session's ops once it has at least `count`."""
    await eventually(lambda: len(session.ops) >= count, timeout)
    return session.ops


async def main():
    fake = fake_controller.Controller(SECRET, ID)
    server = TestServer(fake.app(), host="127.0.0.1")
    await server.start_server()
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-screens-") as temporary:
        data = Path(temporary)
        store = service.Store(data)
        store.write("identity", {"id": ID, "key": V["companionPrivate"]})
        store.save_pairing(SECRET, "Cafe Bar")
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as http, \
                aiohttp.ClientSession() as web:
            companion = Companion("Kitchen server", data, http, Idle)
            companion.pairing.auto = False
            companion.set_controller(("Cafe Bar", ("127.0.0.1", server.port)))
            await eventually(lambda: companion.relay.mode == "ready")
            relay_id, the_mux = companion.relay.client_id, companion.screens.mux
            pages = TestServer(web_app(companion), host="127.0.0.1")
            await pages.start_server()
            base = f"http://127.0.0.1:{pages.port}"

            def screen(index):
                return Browser(web, base, CLIENTS[index])

            async def all_closed(*screens):
                for item in screens:
                    await item.close()
                session = fake.streams[-1] if fake.streams else None
                if session:
                    await asyncio.wait_for(asyncio.shield(session.closed), 3)
                await eventually(lambda: the_mux.upstream.state == "closed")

            # --- A bind needs a claim through the companion ----------------------------------
            stranger = await screen(3).open(claim=False)
            assert await stranger.closed() == 4001 and fake.streams == []

            # --- Home, card, Settings and History: the second screen costs the controller nothing ---
            a = await screen(0).open([{"op": "settings", "on": True}, {**HISTORY, "request": 1}])
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            bind = (await ops_after(session, 1))[0]
            assert session.identity["screen"] == relay_id and bind["client"] == relay_id
            assert bind["ops"][0] == {"op": "settings", "on": True}
            up_history = bind["ops"][1]
            assert {**up_history, "request": 0} == {**HISTORY, "request": 0} and "presetsTag" not in bind
            assert (await a.next("home"))["snapshot"] and (await a.next("card"))["snapshot"]
            assert (await a.next("settings"))["tag"] == 55
            history = await a.next("history")
            assert history["request"] == 1 and history["snapshot"] is True
            await a.send({"op": "activity", "seconds": 0, "hidden": False})
            assert (await a.next("alive"))["type"] == "alive"
            count = len(session.ops)

            b = await screen(1).open([{"op": "settings", "on": True, "tag": 55}, {**HISTORY, "request": 7}],
                                     presetsTag=9)
            home = await b.next("home")
            assert home["snapshot"] and "presets" not in home["changes"] and home["changes"]["presetsTag"] == 9, \
                "the screen's presets are current: Home omits them"
            assert (await b.next("card"))["cycle"] == 3
            history = await b.next("history")
            assert history["request"] == 7 and history["snapshot"] is True and len(history["records"]) == 3
            await b.quiet()  # Settings: the tag matches, nothing to send.
            assert len(session.ops) == count, "a second screen on the same views sends the controller nothing"

            await session.send({"type": "home", "changes": {"machineState": "brewing"}})
            assert (await a.next("home"))["changes"] == {"machineState": "brewing"}
            assert (await b.next("home"))["changes"] == {"machineState": "brewing"}
            refresh = history_frame({**HISTORY}, snapshot=False, request=up_history["request"])
            await session.send(refresh)
            assert (await a.next("history"))["request"] == 1 and (await b.next("history"))["request"] == 7

            # A third screen with another dir and type: one fetch, with every parameter explicit.
            c = await screen(2).open([{**HISTORY, "request": 3, "dir": "asc", "types": ["rinse"]}])
            await c.next("home")
            await c.next("card")
            ops = await ops_after(session, count + 1)
            fetch = ops[-1]
            assert fetch == {"op": "history", "on": True, "fetch": True, "request": fetch["request"], "offset": 0,
                             "limit": 20, "dir": "asc", "types": ["rinse"]}
            page = await c.next("history")
            assert page["request"] == 3 and page["snapshot"] is True and page["records"][0]["type"] == "rinse"
            # A fourth screen in that group: from the companion's copy.
            d = await screen(3).open([{**HISTORY, "request": 4, "dir": "asc", "types": ["rinse"]}])
            await d.next("home")
            await d.next("card")
            assert (await d.next("history"))["request"] == 4 and len(session.ops) == count + 1
            # The store changed: the owner group's refresh, then one fetch for the other group.
            fake.epoch = 6
            await session.send(history_frame({**HISTORY}, snapshot=False, epoch=6, request=up_history["request"]))
            assert (await a.next("history"))["epoch"] == 6 and (await b.next("history"))["epoch"] == 6
            assert (await c.next("history"))["epoch"] == 6 and (await d.next("history"))["epoch"] == 6
            assert len(await ops_after(session, count + 2)) == count + 2 and session.ops[-1]["fetch"] is True

            # A scroll fetch takes the screen's own window for what it leaves out.
            await c.send({"op": "history", "on": True, "fetch": True, "request": 30, "offset": 20})
            ops = await ops_after(session, count + 3)
            assert {**ops[-1], "request": 0} == {"op": "history", "on": True, "fetch": True, "request": 0,
                                                 "offset": 20, "limit": 20, "dir": "asc", "types": ["rinse"]}
            page = await c.next("history")
            assert page["request"] == 30 and page["snapshot"] is False
            await d.quiet()

            # --- Owner promotion: the owner group empties, the other group takes the window ----------
            await a.close()
            await b.close()
            ops = await ops_after(session, count + 4)
            promoted = ops[-1]
            assert {**promoted, "request": 0} == {**HISTORY, "request": 0, "dir": "asc", "types": ["rinse"]}
            assert (await c.next("history"))["request"] == 3 and (await d.next("history"))["request"] == 4
            assert the_mux.status()["views"]["history"] == 2

            # --- An invalid op closes only that screen, with 4003 -------------------------------------
            await d.send({"op": "history", "on": True, "limit": 500})
            assert await d.closed() == 4003
            assert len(session.ops) == count + 4
            await all_closed(c)

            # --- Two Stats windows: a fetch names the window; each screen has its own seq -------------
            a = await screen(0).open([{**STATS, "request": 2}])
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            await a.next("home")
            await a.next("card")
            first = await a.next("stats")
            assert first["request"] == 2 and first["seq"] == 1 and first["snapshot"] and first["stats"]["window"] == 10
            second = await a.next("stats")
            assert second["seq"] == 1 and second["rowBase"] == 1 and second["snapshot"] is False
            b = await screen(1).open([{**STATS, "request": 5, "window": 50}])
            await b.next("home")
            await b.next("card")
            ops = await ops_after(session, 2)
            assert ops[-1] == {"op": "stats", "on": True, "fetch": True, "request": ops[-1]["request"], "offset": 0,
                               "limit": 10, "sort": "date", "dir": "desc", "filter": {}, "window": 50}
            first, second = await b.next("stats"), await b.next("stats")
            assert (first["request"], first["seq"], first["snapshot"], first["stats"]["window"]) == (5, 1, True, 50)
            assert (second["request"], second["seq"], second["snapshot"]) == (5, 1, False)
            await b.send({"op": "stats", "on": True, "fetch": True, "request": 9, "offset": 10, "limit": 10,
                          "sort": "date", "dir": "desc"})
            ops = await ops_after(session, 3)
            assert ops[-1]["window"] == 50 and ops[-1]["filter"] == {} and ops[-1]["offset"] == 10
            first = await b.next("stats")
            assert (first["request"], first["seq"]) == (9, 2) and (await b.next("stats"))["seq"] == 2
            # The owner alone changes its window: the header refresh, not a new subscription.
            await a.send({"op": "stats", "on": True, "window": 100})
            assert (await ops_after(session, 4))[-1] == {"op": "stats", "on": True, "window": 100}
            await all_closed(a, b)

            # --- Diagnostic: a late screen gets the merged model, split; the last one leaves ----------
            a = await screen(0).open([{"op": "diagnostic", "on": True}])
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            await a.next("home")
            await a.next("card")
            assert (await a.next("diagnostic"))["snapshot"] and "tasks" in (await a.next("diagnostic"))["changes"]
            await session.send({"type": "diagnostic", "changes": {"safety.fault": "relay"}})
            await a.next("diagnostic")
            b = await screen(1).open()
            await b.next("home")
            await b.next("card")
            await b.send({"op": "diagnostic", "on": True})
            first = await b.next("diagnostic")
            assert first["snapshot"] is True and first["changes"]["safety.fault"] == "relay"
            assert {"relayClosed", "controlSource", "scale.controlState"} <= set(first["changes"])
            rest = await b.next("diagnostic")
            assert "snapshot" not in rest and "tasks" in rest["changes"] and len(json.dumps(first)) <= 20 * 1024
            assert len(session.ops) == 1
            await a.send({"op": "diagnostic", "on": False})
            await b.send({"op": "diagnostic", "on": False})
            assert (await ops_after(session, 2))[-1] == {"op": "diagnostic", "on": False}
            await asyncio.sleep(0.5)
            assert len(session.ops) == 2, "one off after the linger"

            # --- Log: one upstream subscription, a cursor per screen ------------------------------------
            await a.send({"op": "log", "on": True, "after": 0})
            assert (await ops_after(session, 3))[-1] == {"op": "log", "on": True, "after": 0}
            assert [e["sequence"] for e in (await a.next("log"))["events"]] == [1, 2, 3, 4, 5]
            await b.send({"op": "log", "on": True, "after": 3})
            frame = await b.next("log")
            assert [e["sequence"] for e in frame["events"]] == [4, 5] and frame["cursorInvalid"] is False
            c = await screen(2).open([{"op": "log", "on": True, "after": 99}])
            await c.next("home")
            await c.next("card")
            frame = await c.next("log")
            assert frame["cursorInvalid"] is True and len(frame["events"]) == 5, "a cursor from elsewhere refills"
            assert len(session.ops) == 3
            await session.send(log_frame([event(6)]))
            for item in (a, b, c):
                assert [e["sequence"] for e in (await item.next("log"))["events"]] == [6]
            for item in (a, b, c):
                await item.send({"op": "log", "on": False})
            assert (await ops_after(session, 4))[-1] == {"op": "log", "on": False}

            # --- Hidden and activity: the most of the visible screens, hidden only when all are -------
            await a.send({"op": "activity", "seconds": 20, "hidden": False})
            assert (await ops_after(session, 5))[-1] == {"op": "activity", "seconds": 20, "hidden": False}
            await b.send({"op": "activity", "seconds": 0, "hidden": True})
            await c.send({"op": "activity", "seconds": 0, "hidden": True})
            await asyncio.sleep(0.2)
            assert len(session.ops) == 5
            await a.send({"op": "activity", "seconds": 0, "hidden": True})
            assert (await ops_after(session, 6))[-1] == {"op": "activity", "seconds": 0, "hidden": True}

            # --- Records: one ask for screens asking together, then the companion's copy ---------------
            await a.send({"op": "records", "shots": 0})
            await b.send({"op": "records", "shots": 0})
            ops = await ops_after(session, 7)
            assert ops[-1] == {"op": "records", "shots": 0}
            assert (await a.next("records"))["rows"] == [3, 111, 2, 222]
            assert (await b.next("records"))["rows"] == [3, 111, 2, 222]
            await c.send({"op": "records", "shots": 40})
            assert (await ops_after(session, 8))[-1] == {"op": "records", "shots": 40}, "asks with its cached epoch"
            assert "rows" not in await c.next("records")
            await b.send({"op": "records", "shots": 0, "history": 0})
            ops = await ops_after(session, 9)
            assert ops[-1] == {"op": "records", "shots": 40, "history": 0}
            answers = {frame["store"]: frame for frame in (await b.next("records"), await b.next("records"))}
            assert answers["shots"]["rows"] == [3, 111, 2, 222], "rows from the companion's copy"

            # --- Commands: the next mutation waits for the controller's lastCommand ------------------------
            async def command(index):
                async with web.post(base + "/api/v1/config", json={"patch": {}},
                                    headers={"X-WebUI-Client": CLIENTS[index]}) as reply:
                    return reply.status, await reply.json()

            assert await command(0) == (202, {"accepted": True, "requestId": 101})
            second = asyncio.create_task(command(1))
            await asyncio.sleep(0.4)
            assert not second.done() and fake.requests[-1][1] == "/api/v1/config"
            seen = len(fake.requests)
            await session.send({"type": "home", "changes": {"lastCommand.requestId": 101,
                                                            "lastCommand.state": "QUEUED"}})
            await asyncio.sleep(0.2)
            assert not second.done(), "QUEUED is not settled"
            await session.send({"type": "home", "changes": {"lastCommand.state": "PERSISTED"}})
            assert (await asyncio.wait_for(second, 2))[1]["requestId"] == 102 and len(fake.requests) == seen + 1
            async with web.get(base + "/api/v1/status/admin", headers={"X-WebUI-Client": CLIENTS[2]}) as reply:
                assert reply.status == 200, "reads do not wait behind a command"
            for item in (a, b, c):
                for _ in range(2):
                    await item.next("home")

            # --- A screen 1 MiB behind is closed quietly -------------------------------------------------
            slow = next(item for item in the_mux.screens if item.id == CLIENTS[2])
            slow.send("x" * 600000)
            slow.send("x" * 600000)
            assert await c.closed() == 4002

            # --- 4003 from the controller: the screen that just sent an op, 4002 for the others ----------
            async def reject(controller_session, op):
                if op["op"] == "records":
                    await controller_session.ws.close(code=4003)
                    return True
                return False
            fake.handler = reject
            await asyncio.sleep(0.4)
            await a.send({"op": "records", "history": 5})
            assert await a.closed() == 4003 and await b.closed() == 4002
            fake.handler = None
            await eventually(lambda: the_mux.upstream.state == "closed")

            # --- Takeover: a direct browser opens the Web UI ----------------------------------------------
            a = await screen(0).open([{"op": "settings", "on": True}])
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            b = await screen(1).open()
            await a.next("home")
            await b.next("home")
            async with web.post(f"http://127.0.0.1:{server.port}/api/v1/ui/claim", json={},
                                headers={"X-WebUI-Client": DIRECT}) as reply:
                assert reply.status == 200
            assert await a.closed() == 4001 and await b.closed() == 4001
            assert b.reason == "direct" and the_mux.claimed == set()
            async with web.get(base + "/api/v1/status/admin", headers={"X-WebUI-Client": CLIENTS[0]}) as reply:
                assert reply.status == 409 and fake.requests[-1][2]["X-WebUI-Client"] == CLIENTS[0]
            await eventually(lambda: the_mux.upstream.state == "closed")

            # --- A screen arriving as the last one left: the window moves, the orphaned log goes ------------
            a = await screen(0).open([{**HISTORY, "request": 1}, {"op": "log", "on": True, "after": 0}])
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            await a.next("home")
            await a.next("card")
            assert {(await a.next())["type"], (await a.next())["type"]} == {"history", "log"}
            await a.close()
            await asyncio.sleep(0.05)
            b = await screen(1).open([{**HISTORY, "request": 2, "dir": "asc"}])
            await b.next("home")
            await b.next("card")
            ops = await ops_after(session, 3)
            assert {**ops[1], "request": 0} == {**HISTORY, "request": 0, "dir": "asc"} and ops[2] == {
                "op": "log", "on": False}
            assert (await b.next("history"))["request"] == 2

            # Resync: answered by the companion; the same screen again within 30 s asks the controller.
            await b.send({"op": "resync"})
            assert (await b.next("home"))["snapshot"] and (await b.next("card"))["snapshot"]
            assert (await b.next("history"))["snapshot"] is True and len(session.ops) == 3
            await b.send({"op": "resync"})
            assert (await ops_after(session, 4))[-1] == {"op": "resync"}
            assert (await b.next("home"))["snapshot"] and (await b.next("card"))["snapshot"]
            # A newer controller's frame type reaches the screens as it is.
            await session.send({"v": 1, "type": "future", "x": 1})
            assert (await b.next("future"))["x"] == 1
            await all_closed(b)

            # --- Upstream op count: three screens on the same views cost what one does --------------------
            views = [{"op": "settings", "on": True}, {"op": "diagnostic", "on": True},
                     {"op": "log", "on": True, "after": 0}, {**HISTORY, "request": 1}, {**STATS, "request": 2}]

            async def run(count):
                screens = []
                for index in range(count):
                    screens.append(await screen(index).open(views))
                    await asyncio.sleep(0.2)
                controller_session = await asyncio.wait_for(fake.sessions.get(), 2)
                for item in screens:
                    await item.send({"op": "activity", "seconds": 0, "hidden": False})
                    await item.send({"op": "diagnostic", "on": False})
                    await item.send({"op": "diagnostic", "on": True})
                    await asyncio.sleep(0.1)
                await session_settled(controller_session)
                sent = list(controller_session.ops)
                await all_closed(*screens)
                return sent

            async def session_settled(controller_session):
                previous = -1
                while previous != len(controller_session.ops):
                    previous = len(controller_session.ops)
                    await asyncio.sleep(0.4)

            one, three = await run(1), await run(3)
            assert [op["op"] for op in one] == [op["op"] for op in three], (one, three)
            assert len(one) == len(three) == 1, "the bind carries every view; nothing else reaches the controller"

            # --- No screens left: the session closes, the claim stays ------------------------------------
            assert fake.streams == [] and the_mux.claimed and fake.active == relay_id
            status = companion.status()
            assert status["screens"] == 0 and status["relay"] == "ready" and status["owner"] is True
            await pages.close()
            await companion.relay.close()
    await server.close()
    print("Companion screens: Home, card, Settings, History, Stats, Diagnostic, log, records, liveness, "
          "commands, takeover, 4003, bounds and op count OK")


asyncio.run(main())
