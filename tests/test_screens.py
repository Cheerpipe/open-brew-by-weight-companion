"""Several screens on the companion's one controller session, against a fake controller.

Home and the shot card, Settings, History and Stats groups (owner, fetches, promotion, parked
pages), Diagnostic and the log, an older page's ignored records op, liveness, the command queue,
takeover, 4003, the 1 MiB bound, the upstream op count for one screen against three, and the
replayed clock against the firmware's per-session fields. Offline, inside the image (see the
README).
"""

import asyncio
import hashlib
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict, cast

import aiohttp
import pytest
from aiohttp.test_utils import TestServer

import fake_controller
from companion import mux, upstream
from companion.service import Companion, web_app
from companion.store import Store
from fake_controller import event, history_frame, log_frame

if TYPE_CHECKING:
    from collections.abc import Callable

    from companion.store import Account


class Vectors(TypedDict):
    """What these checks read of the link's vectors."""

    pairingSecret: str
    companionPrivate: str


class Frame(TypedDict, total=False):
    """A frame a screen received, with the fields these checks read."""

    type: str
    snapshot: bool
    changes: dict[str, object]
    boot: int
    epoch: int
    tag: int
    request: int
    seq: int
    rowBase: int
    more: bool
    stats: dict[str, object]
    records: list[dict[str, object]]
    rows: list[object]
    cycle: int
    events: list[dict[str, object]]
    cursorInvalid: bool
    x: int  # A newer controller's frame type.


ROOT = Path(__file__).resolve().parents[1]
V = cast(
    "Vectors", json.loads((ROOT / "tests/fixtures/companion-link-v1.vectors.json").read_text())
)
SECRET = bytes.fromhex(V["pairingSecret"])
ID = "0b9f6a3c-2f4e-4d7a-9c1b-5e8f0a1d2c3b"
CLIENTS = ["0123456789abcdef", "1123456789abcdef", "2123456789abcdef", "3123456789abcdef"]
DIRECT = "aaaaaaaaaaaaaaaaaaaaaaaa"
# The firmware's per-session fields (src/tests/fixtures/ there); its checksum pins the copy.
REPLAY = ROOT / "tests/fixtures/companion_replay_v1.json"
REPLAY_SHA256 = "10c1609c9b253db1750db426e76d923a42acb5d65aa0ba865ff5d1061b26d076"
EVENTUALLY_S, FRAME_S, OPS_S = 3, 2, 2

HISTORY = {"op": "history", "on": True, "offset": 0, "limit": 20, "dir": "desc"}
STATS = {"op": "stats", "on": True, "offset": 0, "limit": 10, "sort": "date", "dir": "desc"}


class Idle:
    """La Marzocco stays off in these checks."""

    sub = up = False
    ep = tok = 0
    refused = policy = False

    def __init__(self, store: Store, events: Companion) -> None:
        pass

    def configure(self, *args: object) -> None:
        pass

    def erase(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def signed_in_for(self, _account: Account) -> bool:
        return False

    def rejected_for(self, _account: Account) -> bool:
        return False

    async def read(self) -> tuple[int, dict[str, object] | None, int]:
        return 0, None, 0

    async def command(self, _command_id: int, _op: str, _value: int | None) -> int:
        return 0


async def eventually(predicate: Callable[[], object]) -> None:
    """Wait until `predicate` holds, at most EVENTUALLY_S (or what the caller's own timeout
    allows)."""
    for _ in range(int(EVENTUALLY_S / 0.02)):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not reached")


class Browser:
    """One screen: a claimed page with its ui-stream."""

    ws: aiohttp.ClientWebSocketResponse  # Once it opened.
    reader: asyncio.Task[None]

    def __init__(self, http: aiohttp.ClientSession, base: str, client: str) -> None:
        self.http, self.base, self.client = http, base, client
        self.frames: asyncio.Queue[Frame | None] = asyncio.Queue()
        self.code: int | None = None
        self.reason: str | None = None

    async def claim(self) -> None:
        async with self.http.post(
            self.base + "/api/v1/ui/claim",
            json={},
            headers={"X-WebUI-Client": self.client, "X-Real-IP": "192.168.1.9"},
        ) as reply:
            assert reply.status == 200

    async def open(
        self, ops: list[dict[str, object]] | tuple[()] = (), claim: bool = True, **bind: object
    ) -> Browser:
        if claim:
            await self.claim()
        self.ws = await self.http.ws_connect(
            self.base + "/api/v1/ui/ui-stream", headers={"X-Real-IP": "192.168.1.9"}
        )
        self.reader = asyncio.create_task(self._reader())
        await self.send(
            {"op": "bind", "client": self.client, **({"ops": list(ops)} if ops else {}), **bind}
        )
        return self

    async def _reader(self) -> None:
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

    async def send(self, op: dict[str, object]) -> None:
        await self.ws.send_str(json.dumps(op))

    async def next(self, kind: str = "any") -> Frame:
        """The next frame, skipping `alive`; kind "card" means a shot-card frame."""
        while True:
            frame = await asyncio.wait_for(self.frames.get(), FRAME_S)
            assert frame is not None, f"the stream closed ({self.code}) while waiting for {kind}"
            if frame.get("type") == "alive" and kind != "alive":
                continue
            found = frame.get("type", "card")
            assert kind in ("any", found), f"expected {kind}, got {frame}"
            return frame

    async def quiet(self, seconds: float = 0.3) -> None:
        try:
            frame = await asyncio.wait_for(self.frames.get(), seconds)
        except TimeoutError:
            return
        assert frame is None or frame.get("type") == "alive", f"unexpected {frame}"

    async def closed(self) -> int | None:
        while True:
            frame = await asyncio.wait_for(self.frames.get(), FRAME_S)
            if frame is None:
                return self.code

    async def close(self) -> None:
        await self.ws.close()


async def ops_after(session: fake_controller.Session, count: int) -> list[fake_controller.Op]:
    """The controller session's ops once it has at least `count`, within OPS_S."""
    async with asyncio.timeout(OPS_S):
        await eventually(lambda: len(session.ops) >= count)
    return session.ops


def test_an_op_number_must_be_finite() -> None:
    """`1e400` parses as infinity, which int() cannot take."""
    for value in (json.loads("1e400"), float("nan"), 10**400):
        with pytest.raises(mux.InvalidOpError):
            mux._integer(value, 0, 10)


def test_replay_fixture_is_the_firmwares() -> None:
    assert hashlib.sha256(REPLAY.read_bytes()).hexdigest() == REPLAY_SHA256, (
        "the replay fixture differs from the firmware's: copy its file again"
    )


def test_replay_fields_are_handled() -> None:
    assert json.loads(REPLAY.read_text())["sessionFields"] == {
        "home": dict.fromkeys(mux.CLOCKS, "clock")
    }, "a per-session field of the controller is not handled on a replay (mux.CLOCKS)"


def test_screens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Companion screens: Home, card, Settings, History, Stats, parked pages, Diagnostic, log, an
    ignored records op, liveness, commands, takeover, 4003, bounds and op count."""
    monkeypatch.setattr(mux, "IDLE_S", 0.3)
    monkeypatch.setattr(mux, "DIAGNOSTIC_LINGER_S", 0.3)
    monkeypatch.setattr(mux, "ATTRIBUTION_S", 0.3)
    monkeypatch.setattr(upstream, "TICK_S", 0.05)
    asyncio.run(scenario())


async def scenario() -> None:
    fake = fake_controller.Controller(SECRET, ID)
    server = TestServer(fake.app(), host="127.0.0.1")
    await server.start_server()
    assert server.port is not None
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-screens-") as temporary:
        data = Path(temporary)
        store = Store(data)
        store.write("identity", {"id": ID, "key": V["companionPrivate"]})
        store.save_pairing(SECRET, "Cafe Bar")
        async with (
            aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as http,
            aiohttp.ClientSession() as web,
        ):
            companion = Companion("Kitchen server", data, http, Idle)
            companion.pairing.auto = False
            companion.set_controller(("Cafe Bar", ("127.0.0.1", server.port)))
            await eventually(lambda: companion.relay.mode == "ready")
            relay_id, the_mux = companion.relay.client_id, companion.screens.mux
            pages = TestServer(web_app(companion), host="127.0.0.1")
            await pages.start_server()
            base = f"http://127.0.0.1:{pages.port}"

            def screen(index: int) -> Browser:
                return Browser(web, base, CLIENTS[index])

            async def all_closed(*screens: Browser) -> None:
                for item in screens:
                    await item.close()
                session = fake.streams[-1] if fake.streams else None
                if session:
                    await asyncio.wait_for(asyncio.shield(session.closed), 3)
                await eventually(lambda: the_mux.upstream.state == "closed")

            # --- A bind needs a claim through the companion ----------------------------------
            stranger = await screen(3).open(claim=False)
            assert await stranger.closed() == 4001
            assert fake.streams == []

            # --- Home, card, Settings and History: the second screen costs the controller nothing
            a = await screen(0).open([{"op": "settings", "on": True}, {**HISTORY, "request": 1}])
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            bind = (await ops_after(session, 1))[0]
            assert session.identity is not None
            assert session.identity["screen"] == relay_id
            assert bind["client"] == relay_id
            assert bind["ops"][0] == {"op": "settings", "on": True}
            up_history = bind["ops"][1]
            assert {**up_history, "request": 0} == {**HISTORY, "request": 0}
            assert "presetsTag" not in bind
            assert (await a.next("home"))["snapshot"]
            assert (await a.next("card"))["snapshot"]
            assert (await a.next("settings"))["tag"] == 55
            history = await a.next("history")
            assert history["request"] == 1
            assert history["snapshot"] is True
            await a.send({"op": "activity", "seconds": 0, "hidden": False})
            assert (await a.next("alive"))["type"] == "alive"
            count = len(session.ops)
            # Five seconds after the controller's clock arrived.
            the_mux.home.clock_at["timeUtcSec"] -= 5

            b = await screen(1).open(
                [{"op": "settings", "on": True, "tag": 55}, {**HISTORY, "request": 7}], presetsTag=9
            )
            home = await b.next("home")
            assert home["snapshot"], "the screen's presets are current: Home omits them"
            assert "presets" not in home["changes"], (
                "the screen's presets are current: Home omits them"
            )
            assert home["changes"]["presetsTag"] == 9, (
                "the screen's presets are current: Home omits them"
            )
            assert home["changes"]["timeUtcSec"] == 1800000005, (
                "a late screen's clock is as old as it is"
            )
            assert (await b.next("card"))["cycle"] == 3
            history = await b.next("history")
            assert history["request"] == 7
            assert history["snapshot"] is True
            assert len(history["records"]) == 3
            await b.quiet()  # Settings: the tag matches, nothing to send.
            assert len(session.ops) == count, (
                "a second screen on the same views sends the controller nothing"
            )

            await session.send({"type": "home", "changes": {"machineState": "brewing"}})
            assert (await a.next("home"))["changes"] == {"machineState": "brewing"}
            assert (await b.next("home"))["changes"] == {"machineState": "brewing"}
            refresh = history_frame({**HISTORY}, snapshot=False, request=up_history["request"])
            await session.send(refresh)
            assert (await a.next("history"))["request"] == 1
            assert (await b.next("history"))["request"] == 7

            # A third screen with another dir and type: one fetch, with every parameter explicit.
            c = await screen(2).open([{**HISTORY, "request": 3, "dir": "asc", "types": ["rinse"]}])
            await c.next("home")
            await c.next("card")
            ops = await ops_after(session, count + 1)
            fetch = ops[-1]
            assert fetch == {
                "op": "history",
                "on": True,
                "fetch": True,
                "request": fetch["request"],
                "offset": 0,
                "limit": 20,
                "dir": "asc",
                "types": ["rinse"],
            }
            page = await c.next("history")
            assert page["request"] == 3
            assert page["snapshot"] is True
            assert page["records"][0]["type"] == "rinse"
            # A fourth screen in that group: from the companion's copy.
            d = await screen(3).open([{**HISTORY, "request": 4, "dir": "asc", "types": ["rinse"]}])
            await d.next("home")
            await d.next("card")
            assert (await d.next("history"))["request"] == 4
            assert len(session.ops) == count + 1
            # The store changed: the owner group's refresh, then one fetch for the other group.
            fake.epoch = 6
            await session.send(
                history_frame({**HISTORY}, snapshot=False, epoch=6, request=up_history["request"])
            )
            assert (await a.next("history"))["epoch"] == 6
            assert (await b.next("history"))["epoch"] == 6
            assert (await c.next("history"))["epoch"] == 6
            assert (await d.next("history"))["epoch"] == 6
            assert len(await ops_after(session, count + 2)) == count + 2
            assert session.ops[-1]["fetch"] is True

            # A scroll fetch takes the screen's own window for what it leaves out.
            await c.send({"op": "history", "on": True, "fetch": True, "request": 30, "offset": 20})
            ops = await ops_after(session, count + 3)
            assert {**ops[-1], "request": 0} == {
                "op": "history",
                "on": True,
                "fetch": True,
                "request": 0,
                "offset": 20,
                "limit": 20,
                "dir": "asc",
                "types": ["rinse"],
            }
            page = await c.next("history")
            assert page["request"] == 30
            assert page["snapshot"] is False
            await d.quiet()

            # --- Owner promotion: the owner group empties, the other group takes the window -------
            await a.close()
            await b.close()
            ops = await ops_after(session, count + 4)
            promoted = ops[-1]
            assert {**promoted, "request": 0} == {
                **HISTORY,
                "request": 0,
                "dir": "asc",
                "types": ["rinse"],
            }
            assert (await c.next("history"))["request"] == 3
            assert (await d.next("history"))["request"] == 4
            assert the_mux.status()["views"]["history"] == 2

            # --- An invalid op closes only that screen, with 4003 ---------------------------------
            await d.send({"op": "history", "on": True, "limit": 500})
            assert await d.closed() == 4003
            assert len(session.ops) == count + 4
            await all_closed(c)

            # --- Two Stats windows: a fetch names the window; each screen has its own seq ---------
            a = await screen(0).open([{**STATS, "request": 2}])
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            await a.next("home")
            await a.next("card")
            first = await a.next("stats")
            assert first["request"] == 2
            assert first["seq"] == 1
            assert first["snapshot"]
            assert first["stats"]["window"] == 10
            second = await a.next("stats")
            assert second["seq"] == 1
            assert second["rowBase"] == 1
            assert second["snapshot"] is False
            b = await screen(1).open([{**STATS, "request": 5, "window": 50}])
            await b.next("home")
            await b.next("card")
            ops = await ops_after(session, 2)
            assert ops[-1] == {
                "op": "stats",
                "on": True,
                "fetch": True,
                "request": ops[-1]["request"],
                "offset": 0,
                "limit": 10,
                "sort": "date",
                "dir": "desc",
                "filter": {},
                "window": 50,
            }
            first, second = await b.next("stats"), await b.next("stats")
            assert (
                first["request"],
                first["seq"],
                first["snapshot"],
                first["stats"]["window"],
            ) == (5, 1, True, 50)
            assert (second["request"], second["seq"], second["snapshot"]) == (5, 1, False)
            await b.send(
                {
                    "op": "stats",
                    "on": True,
                    "fetch": True,
                    "request": 9,
                    "offset": 10,
                    "limit": 10,
                    "sort": "date",
                    "dir": "desc",
                }
            )
            ops = await ops_after(session, 3)
            assert ops[-1]["window"] == 50
            assert ops[-1]["filter"] == {}
            assert ops[-1]["offset"] == 10
            first = await b.next("stats")
            assert (first["request"], first["seq"]) == (9, 2)
            assert (await b.next("stats"))["seq"] == 2
            # The owner alone changes its window: the header refresh, not a new subscription.
            await a.send({"op": "stats", "on": True, "window": 100})
            assert (await ops_after(session, 4))[-1] == {"op": "stats", "on": True, "window": 100}
            # Home's rows-only fetch, from a screen with no Stats view: its rows, not a 4003.
            c = await screen(2).open()
            await c.next("home")
            await c.next("card")
            await c.send(
                {
                    "op": "stats",
                    "on": True,
                    "fetch": True,
                    "request": 11,
                    "offset": 1,
                    "limit": 2,
                    "sort": "date",
                    "dir": "desc",
                    "filter": {},
                }
            )
            ops = await ops_after(session, 5)
            assert ops[-1] == {
                "op": "stats",
                "on": True,
                "fetch": True,
                "request": ops[-1]["request"],
                "offset": 1,
                "limit": 2,
                "sort": "date",
                "dir": "desc",
                "filter": {},
                "window": 10,
            }
            assert (await c.next("stats"))["request"] == 11
            assert (await c.next("stats"))["rowBase"] == 1
            await all_closed(a, b, c)

            # --- Diagnostic: a late screen gets the merged model, split; the last one leaves ------
            a = await screen(0).open([{"op": "diagnostic", "on": True}])
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            await a.next("home")
            await a.next("card")
            assert (await a.next("diagnostic"))["snapshot"]
            assert "tasks" in (await a.next("diagnostic"))["changes"]
            await session.send({"type": "diagnostic", "changes": {"safety.fault": "relay"}})
            await a.next("diagnostic")
            b = await screen(1).open()
            await b.next("home")
            await b.next("card")
            await b.send({"op": "diagnostic", "on": True})
            first = await b.next("diagnostic")
            assert first["snapshot"] is True
            assert first["changes"]["safety.fault"] == "relay"
            assert {"relayClosed", "controlSource", "scale.controlState"} <= set(first["changes"])
            rest = await b.next("diagnostic")
            assert "snapshot" not in rest
            assert "tasks" in rest["changes"]
            assert len(json.dumps(first)) <= 20 * 1024
            assert len(session.ops) == 1
            await a.send({"op": "diagnostic", "on": False})
            await b.send({"op": "diagnostic", "on": False})
            assert (await ops_after(session, 2))[-1] == {"op": "diagnostic", "on": False}
            await asyncio.sleep(0.5)
            assert len(session.ops) == 2, "one off after the linger"

            # --- Log: one upstream subscription, a cursor per screen ------------------------------
            await a.send({"op": "log", "on": True, "after": 0})
            assert (await ops_after(session, 3))[-1] == {"op": "log", "on": True, "after": 0}
            assert [e["sequence"] for e in (await a.next("log"))["events"]] == [1, 2, 3, 4, 5]
            await b.send({"op": "log", "on": True, "after": 3})
            frame = await b.next("log")
            assert [e["sequence"] for e in frame["events"]] == [4, 5]
            assert frame["cursorInvalid"] is False
            c = await screen(2).open([{"op": "log", "on": True, "after": 99}])
            await c.next("home")
            await c.next("card")
            frame = await c.next("log")
            assert frame["cursorInvalid"] is True, "a cursor from elsewhere refills"
            assert len(frame["events"]) == 5, "a cursor from elsewhere refills"
            assert len(session.ops) == 3
            await session.send(log_frame([event(6)]))
            for item in (a, b, c):
                assert [e["sequence"] for e in (await item.next("log"))["events"]] == [6]
            for item in (a, b, c):
                await item.send({"op": "log", "on": False})
            assert (await ops_after(session, 4))[-1] == {"op": "log", "on": False}

            # --- Hidden and activity: the most of the visible screens, hidden only when all are ---
            await a.send({"op": "activity", "seconds": 20, "hidden": False})
            assert (await ops_after(session, 5))[-1] == {
                "op": "activity",
                "seconds": 20,
                "hidden": False,
            }
            await b.send({"op": "activity", "seconds": 0, "hidden": True})
            await c.send({"op": "activity", "seconds": 0, "hidden": True})
            await asyncio.sleep(0.2)
            assert len(session.ops) == 5
            await a.send({"op": "activity", "seconds": 0, "hidden": True})
            assert (await ops_after(session, 6))[-1] == {
                "op": "activity",
                "seconds": 0,
                "hidden": True,
            }

            # --- An older page's `records` op (a record index): ignored, never sent up nor
            # closed (4003) ------------------------------------------------------------------------
            await a.send({"op": "records", "shots": 0})
            await a.quiet()
            assert len(session.ops) == 6
            assert a.code is None

            # --- Commands: the next mutation waits for the controller's lastCommand ---------------
            async def command(index: int) -> tuple[int, dict[str, object]]:
                async with web.post(
                    base + "/api/v1/config",
                    json={"patch": {}},
                    headers={"X-WebUI-Client": CLIENTS[index]},
                ) as reply:
                    return reply.status, await reply.json()

            assert await command(0) == (202, {"accepted": True, "requestId": 101})
            second_command = asyncio.create_task(command(1))
            await asyncio.sleep(0.4)
            assert not second_command.done()
            assert fake.requests[-1][1] == "/api/v1/config"
            seen = len(fake.requests)
            await session.send(
                {
                    "type": "home",
                    "changes": {"lastCommand.requestId": 101, "lastCommand.state": "QUEUED"},
                }
            )
            await asyncio.sleep(0.2)
            assert not second_command.done(), "QUEUED is not settled"
            await session.send({"type": "home", "changes": {"lastCommand.state": "PERSISTED"}})
            assert (await asyncio.wait_for(second_command, 2))[1]["requestId"] == 102
            assert len(fake.requests) == seen + 1

            # A held save does not hold back a control action.
            async def post(path: str) -> int:
                async with web.post(
                    base + path, json={}, headers={"X-WebUI-Client": CLIENTS[0]}
                ) as reply:
                    return reply.status

            for path in ("/api/v1/control/stop", "/api/v1/control/paddle"):
                assert await asyncio.wait_for(post(path), 1) == 202, "control never queues"
                assert fake.requests[-1][1] == path
            third_command = asyncio.create_task(command(1))
            await asyncio.sleep(0.2)
            assert not third_command.done(), "another save still waits"

            async def settle() -> None:
                await session.send(
                    {
                        "type": "home",
                        "changes": {
                            "lastCommand.requestId": fake.request_id,
                            "lastCommand.state": "PERSISTED",
                        },
                    }
                )

            await settle()
            await asyncio.wait_for(third_command, 2)
            await settle()
            await eventually(lambda: not companion.screens.commands.locked())
            assert await post("/api/v1/time/sync") == 202
            assert (await asyncio.wait_for(command(1), 1))[0] == 202, "a time sync holds nothing"
            await settle()
            await eventually(lambda: not companion.screens.commands.locked())
            async with web.get(
                base + "/api/v1/status/admin", headers={"X-WebUI-Client": CLIENTS[2]}
            ) as reply:
                assert reply.status == 200, "reads do not wait behind a command"
            for item in (a, b, c):
                for _ in range(2):
                    await item.next("home")

            # --- A screen 1 MiB behind is closed quietly ------------------------------------------
            slow = next(item for item in the_mux.screens if item.id == CLIENTS[2])
            slow.send("x" * 600000)
            slow.send("x" * 600000)
            assert await c.closed() == 4002

            # --- The relay session ends: no screen stays ------------------------------------------
            e = await screen(3).open()
            await e.next("home")
            fake.ui = False
            assert await companion.relay.handshake() == "disabled"
            assert await e.closed() == 4001
            assert await a.closed() == 4001
            assert await b.closed() == 4001
            assert not the_mux.claimed
            await eventually(lambda: the_mux.upstream.state == "closed")
            fake.ui = True
            assert await companion.relay.handshake() == "ready"
            a = await screen(0).open()
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            b = await screen(1).open()
            await a.next("home")
            await b.next("home")

            # --- A relayed UI_TAKEN_OVER does not claim a direct page took it ---------------------
            taken = await screen(3).open()
            await taken.next("home")
            fake.active = DIRECT
            async with web.get(
                base + "/api/v1/status/admin", headers={"X-WebUI-Client": CLIENTS[3]}
            ) as reply:
                assert reply.status == 409
            assert await taken.closed() == 4001
            assert not taken.reason
            assert await a.closed() == 4001
            assert await b.closed() == 4001
            await eventually(lambda: the_mux.upstream.state == "closed")
            a = await screen(0).open()
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            b = await screen(1).open()
            await a.next("home")
            await b.next("home")

            # --- A signed-out screen loses its claim and live updates; the others keep theirs -----
            for path, code in (("/api/v1/auth/logout", 200), ("/api/v1/status/admin", 401)):
                d = await screen(3).open()
                await d.next("home")
                fake.auth_required = code == 401
                call = web.post if code == 200 else web.get
                async with call(base + path, headers={"X-WebUI-Client": CLIENTS[3]}) as reply:
                    assert reply.status == code
                fake.auth_required = False
                assert await d.closed() == 4001
                assert CLIENTS[3] not in the_mux.claimed
                assert CLIENTS[0] in the_mux.claimed
                assert await (await screen(3).open(claim=False)).closed() == 4001
                assert a.code is None

            # --- 4003 from the controller: the screen that just sent an op, 4002 for the others ---
            async def reject(
                controller_session: fake_controller.Session, op: fake_controller.Op
            ) -> bool:
                if op["op"] == "log":
                    await controller_session.ws.close(code=4003)
                    return True
                return False

            fake.handler = reject
            await asyncio.sleep(0.4)
            await a.send({"op": "log", "on": True})
            assert await a.closed() == 4003
            assert await b.closed() == 4002
            fake.handler = None
            await eventually(lambda: the_mux.upstream.state == "closed")

            # --- Takeover: a direct browser opens the Web UI --------------------------------------
            a = await screen(0).open([{"op": "settings", "on": True}])
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            b = await screen(1).open()
            await a.next("home")
            await b.next("home")
            async with web.post(
                f"http://127.0.0.1:{server.port}/api/v1/ui/claim",
                json={},
                headers={"X-WebUI-Client": DIRECT},
            ) as reply:
                assert reply.status == 200
            assert await a.closed() == 4001
            assert await b.closed() == 4001
            assert b.reason == "direct"
            assert the_mux.claimed == set()
            async with web.get(
                base + "/api/v1/status/admin", headers={"X-WebUI-Client": CLIENTS[0]}
            ) as reply:
                assert reply.status == 409
                assert fake.requests[-1][2]["X-WebUI-Client"] == CLIENTS[0]
            await eventually(lambda: the_mux.upstream.state == "closed")

            # --- A screen arriving as the last one left: the window moves, the orphaned log goes --
            a = await screen(0).open(
                [{**HISTORY, "request": 1}, {"op": "log", "on": True, "after": 0}]
            )
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
            assert {**ops[1], "request": 0} == {**HISTORY, "request": 0, "dir": "asc"}
            assert ops[2] == {"op": "log", "on": False}
            assert (await b.next("history"))["request"] == 2

            # Resync: answered by the companion; the same screen again within 30 s asks the
            # controller.
            await b.send({"op": "resync"})
            assert (await b.next("home"))["snapshot"]
            assert (await b.next("card"))["snapshot"]
            assert (await b.next("history"))["snapshot"] is True
            assert len(session.ops) == 3
            await b.send({"op": "resync"})
            assert (await ops_after(session, 4))[-1] == {"op": "resync"}
            assert (await b.next("home"))["snapshot"]
            assert (await b.next("card"))["snapshot"]
            # A newer controller's frame type reaches the screens as it is.
            await session.send({"v": 1, "type": "future", "x": 1})
            assert (await b.next("future"))["x"] == 1
            await all_closed(b)

            # --- Upstream op count: three screens on the same views cost what one does ------------
            views: list[dict[str, object]] = [
                {"op": "settings", "on": True},
                {"op": "diagnostic", "on": True},
                {"op": "log", "on": True, "after": 0},
                {**HISTORY, "request": 1},
                {**STATS, "request": 2},
            ]

            async def run(count: int) -> list[fake_controller.Op]:
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

            async def session_settled(controller_session: fake_controller.Session) -> None:
                previous = -1
                while previous != len(controller_session.ops):
                    previous = len(controller_session.ops)
                    await asyncio.sleep(0.4)

            one, three = await run(1), await run(3)
            assert [op["op"] for op in one] == [op["op"] for op in three], (one, three)
            assert len(one) == len(three) == 1, (
                "the bind carries every view; nothing else reaches the controller"
            )

            # --- Parked pages: the last screen's page waits for the next one's revalidation by
            # its tag ------------------------------------------------------------------------------
            async def page_of(item: Browser, kind: str) -> tuple[Frame, list[object]]:
                """A screen's next whole History or Stats page: its first frame and every row."""
                first = frame = await item.next(kind)
                rows: list[object] = list(frame[mux.ROWS[kind]])
                while kind == "stats" and frame["more"]:
                    frame = await item.next(kind)
                    rows += frame["rows"]
                return first, rows

            async def parked(item: Browser, view: mux.View) -> None:
                await item.send({"op": view.kind, "on": False})
                await eventually(lambda: view.parked is not None)

            held: list[fake_controller.Op] = []  # The parked tag's subscribe, held back.
            for kind, view_op in (("history", HISTORY), ("stats", STATS)):
                view, key = the_mux.views[kind], "sh" if kind == "stats" else "hi"
                the_mux.unpark()
                fake.epoch = 5
                h = await screen(0).open()  # Keeps the session while the view has no screen.
                session = await asyncio.wait_for(fake.sessions.get(), 2)
                await h.next("home")
                await h.next("card")
                a = await screen(1).open([{**view_op, "request": 1}])
                await a.next("home")
                await a.next("card")
                first, rows = await page_of(a, kind)
                assert "tag" not in session.ops[-1]
                assert all(type(row) is not int for row in rows)
                await parked(a, view)
                assert session.ops[-1] == {"op": kind, "on": False}, (
                    "the last screen still ends the upstream window"
                )
                # Another task moves the parked page between two checks: each reads it anew.
                parked_page = view.parked
                assert parked_page is not None
                assert parked_page["tag"] == first["tag"]
                assert parked_page["epoch"] == 5

                # The next screen: the parked tag goes up, and nothing reaches the screen before the
                # answer.
                held.clear()

                async def hold(
                    _session: fake_controller.Session, op: fake_controller.Op, kind: str = kind
                ) -> bool:
                    if op["op"] == kind and "tag" in op:
                        held.append(op)
                        return True
                    return False

                fake.handler = hold
                await a.send({**view_op, "request": 2})
                await eventually(lambda: held)
                assert held[0]["tag"] == first["tag"]
                # Joins while the answer is pending.
                d = await screen(3).open([{**view_op, "request": 9}])
                await d.next("home")
                await d.next("card")
                await a.quiet()
                await d.quiet()
                fake.handler = None
                sent = len(session.sent)
                await session.answer(held[0])
                kept = [json.loads(text) for text in session.sent[sent:]]
                assert len(kept) == 1, "the controller answers the tag with bare ids, in one frame"
                assert all(type(row) is int for row in kept[0][mux.ROWS[kind]]), (
                    "the controller answers the tag with bare ids, in one frame"
                )
                again, whole = await page_of(a, kind)
                assert again["request"] == 2, "made whole"
                assert again["snapshot"] is True, "made whole"
                assert whole == rows, "made whole"
                assert (await page_of(d, kind))[1] == rows
                parked_page = view.parked
                assert parked_page is None
                await d.close()
                await eventually(lambda: len(the_mux.bound()) == 2)
                # A late screen joins from the buffer: whole rows, nothing upstream.
                count = len(session.ops)
                c = await screen(2).open([{**view_op, "request": 3}])
                await c.next("home")
                await c.next("card")
                assert (await page_of(c, kind))[1] == rows
                assert len(session.ops) == count

                # A changed store (Clear, a new shot): the controller's page replaces the parked
                # one.
                await a.send({"op": kind, "on": False})
                await parked(c, view)
                fake.epoch = 6
                await a.send({**view_op, "request": 4})
                changed, fresh = await page_of(a, kind)
                assert "tag" in session.ops[-1]
                assert changed["epoch"] == 6
                assert changed["tag"] != first["tag"]
                assert all(type(row) is not int for row in fresh)
                parked_page = view.parked
                assert parked_page is None

                # An `rs` notice of the same epoch keeps the parked page; a moved one drops it.
                await parked(a, view)
                await companion._on_frame({"t": "rs", key: 6})
                parked_page = view.parked
                assert parked_page is not None
                await companion._on_frame({"t": "rs", key: 7})
                assert view.parked is None
                await a.send({**view_op, "request": 5})
                await page_of(a, kind)
                assert "tag" not in session.ops[-1]

                # Another boot: a kept answer is not trusted; the page comes again without the tag.
                await parked(a, view)
                fake.boot = 8
                count = len(session.ops)
                await a.send({**view_op, "request": 6})
                rebooted, fresh = await page_of(a, kind)
                ops = session.ops[count:]
                assert len(ops) == 2
                assert "tag" in ops[0]
                assert "tag" not in ops[1]
                assert rebooted["boot"] == 8
                assert fresh == rows

                # The idle close keeps the parked page for the next session; a lost session drops
                # it.
                fake.boot, fake.epoch = 7, 5
                await parked(a, view)
                await a.send({**view_op, "request": 7})
                await page_of(a, kind)
                await parked(a, view)
                await all_closed(a, c, h)
                a = await screen(1).open([{**view_op, "request": 8}])
                session = await asyncio.wait_for(fake.sessions.get(), 2)
                await a.next("home")
                await a.next("card")
                assert (await page_of(a, kind))[1] == rows
                assert "tag" in session.ops[0]["ops"][0]
                assert type(json.loads(session.sent[-1])[mux.ROWS[kind]][0]) is int
                await parked(a, view)
                await session.ws.close(code=1011)
                assert await a.closed() == 1001
                assert view.parked is None
                await eventually(lambda: the_mux.upstream.state == "closed")

            # --- No screens left: the session closes, the claim stays -----------------------------
            assert fake.streams == []
            assert the_mux.claimed
            assert fake.active == relay_id
            status = await companion.status()
            assert status["screens"] == 0
            assert status["relay"] == "ready"
            assert status["owner"] is True
            # --- A group nobody holds keeps no page copy ------------------------------------------
            view = the_mux.views["history"]
            a = await screen(0).open([{**HISTORY, "request": 2}])
            session = await asyncio.wait_for(fake.sessions.get(), 2)
            await a.next("home")
            await a.next("card")
            await a.next("history")
            c = await screen(2).open([{**HISTORY, "request": 3, "dir": "asc", "types": ["rinse"]}])
            await c.next("home")
            await c.next("card")
            await c.next("history")
            assert view.pages
            await c.send({"op": "history", "on": False})
            await eventually(lambda: not view.pages)
            await all_closed(a, c)
            # A fetch still filling it keeps it: a screen that joins now needs the whole page.
            gone: mux.Group = (0, 0, "gone", ())
            view.pages[gone], view.inflight = ([], False), mux.Fetch(gone, gone, None)
            view._forget(gone)
            assert gone in view.pages
            view.inflight = None
            view._forget(gone)
            assert gone not in view.pages

            await pages.close()
            await companion.relay.close()
    await server.close()
