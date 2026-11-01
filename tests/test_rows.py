#!/usr/bin/env python3
"""The offline copy's Stats windows answered from the archive, against the fake controller.

A screen fills its offline copy with Stats fetches (date/desc, no filter, at most 50 rows) at positions of
the record index the companion just gave it. The companion answers such a window itself when its archive
holds every row of it under the revision that index lists; on any doubt the window goes to the controller
as before, and each guard below shows one. Every other Stats op reaches the controller as before, and a
screen gets the same rows either way. Offline, inside the image (see the README).
"""

import asyncio
import json
import logging
import sqlite3
import sys
import tempfile
import time
import zlib
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

V = json.loads((ROOT / "tests/fixtures/companion-link-v1.vectors.json").read_text())
CASES = {case["name"]: case for case in json.loads(
    (ROOT / "tests/fixtures/companion-records-v1.vectors.json").read_text())["cases"]}
ID, DEVICE = "0b9f6a3c-2f4e-4d7a-9c1b-5e8f0a1d2c3b", "AA:BB:CC:DD:EE:FF"
CLIENTS = ["0123456789abcdef", "1123456789abcdef", "2123456789abcdef", "3123456789abcdef"]
N, EPOCH = 1000, 7001
upstream.TICK_S = 0.05

# The controller's N good shots, newest first: the firmware's own browser rows (contract vectors) as
# templates, each under its own id and end time.
PAGE = [json.loads(text) for text in CASES["browser_fetch_shots"]["frames"]]
COLS = PAGE[0]["cols"]
NAMES = COLS.split(",")
TEMPLATES = [row for frame in PAGE for row in frame["rows"]]
ROWS = []
for rid in range(N, 0, -1):
    row = json.loads(json.dumps(TEMPLATES[rid % len(TEMPLATES)]))
    row[0], row[NAMES.index("endedAtMs")] = rid, 600000 + rid * 1000
    ROWS.append(row)
PAIRS = [(row[0], row[0] * 40503 & 0xFFFFFF) for row in ROWS]
FLAT = [value for pair in PAIRS for value in pair]
sent = []  # The frames the fake controller sent for its last Stats page.


def stats_page(session, op, snapshot, epoch=5, request=None):
    """The fake controller's Stats page over ROWS (date/desc only here), 20 rows a frame, its header first."""
    session.seq += 1
    offset, limit = op.get("offset", 0), op.get("limit", 10)
    rows = ROWS[offset:offset + limit]
    common = {"v": 1, "type": "stats", "boot": 7, "snapshot": snapshot, "epoch": epoch, "seq": session.seq,
              "request": op.get("request", 0)}
    tail = {"total": N, "offset": offset, "limit": limit, "hasMore": offset + limit < N}
    sent[:] = [{**common, "snapshot": snapshot and not base,
                **({} if base else {"stats": {"window": 10}, "cols": COLS, "tag": 88, "good": N}), **tail,
                "rows": rows[base:base + 20], "rowBase": base, "more": base + 20 < len(rows)}
               for base in range(0, max(len(rows), 1), 20)]
    return sent


fake_controller.stats_page = stats_page


class Idle:
    sub = up = refused = False
    ep = tok = 0

    def __init__(self, store, events):
        pass

    def configure(self, *args):
        pass

    def erase(self):
        pass

    def stop(self):
        pass


class Lines(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.INFO)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


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
        self.frames, self.ws, self.request = asyncio.Queue(), None, 100

    async def open(self):
        async with self.http.post(self.base + "/api/v1/ui/claim", json={},
                                  headers={"X-WebUI-Client": self.client, "X-Real-IP": "192.168.1.9"}) as reply:
            assert reply.status == 200
        self.ws = await self.http.ws_connect(self.base + "/api/v1/ui/ui-stream", headers={"X-Real-IP": "192.168.1.9"})
        asyncio.create_task(self._reader())
        await self.send({"op": "bind", "client": self.client})
        return self

    async def _reader(self):
        async for message in self.ws:
            if message.type is aiohttp.WSMsgType.TEXT:
                self.frames.put_nowait(json.loads(message.data))
        self.frames.put_nowait(None)

    async def send(self, op):
        await self.ws.send_str(json.dumps(op))

    async def next(self, kind, request=None, timeout=3):
        while True:
            frame = await asyncio.wait_for(self.frames.get(), timeout)
            assert frame is not None, f"the stream closed while waiting for {kind}"
            if frame.get("type") == kind and request in (None, frame.get("request")):
                return frame

    async def page(self, op):
        """Send a Stats fetch; its frames once the last arrived."""
        frames = [await self.next("stats", op.get("request", 0))]
        while frames[-1]["more"]:
            frames.append(await self.next("stats", op.get("request", 0)))
        return frames

    async def records(self, held=0):
        await self.send({"op": "records", "shots": held})
        return await self.next("records")


def fetches(session):
    return sum(op.get("fetch") is True for op in session.ops)


async def main():
    fake = fake_controller.Controller(bytes.fromhex(V["pairingSecret"]), ID)
    fake.epoch, fake.indexes = EPOCH, {"shots": (EPOCH, FLAT)}
    server = TestServer(fake.app(), host="127.0.0.1")
    await server.start_server()
    lines = Lines()
    logging.getLogger("obbw.companion").addHandler(lines)
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-rows-") as temporary:
        data = Path(temporary)
        store = service.Store(data)
        store.write("identity", {"id": ID, "key": V["companionPrivate"]})
        store.save_pairing(bytes.fromhex(V["pairingSecret"]), "Cafe Bar")
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as http, \
                aiohttp.ClientSession() as web:
            companion = Companion("Kitchen server", data, http, Idle)
            companion.pairing.auto = False
            companion.set_controller(("Cafe Bar", ("127.0.0.1", server.port)))
            await eventually(lambda: companion.relay.mode == "ready")
            pages = TestServer(web_app(companion), host="127.0.0.1")
            await pages.start_server()
            base = f"http://127.0.0.1:{pages.port}"
            await companion.open_log()
            companion.device_id, companion.archive.on = DEVICE, True
            archive = companion.archive.store

            async def copy(generation, epoch):
                """Every shot under its listed revision, as a sync at `epoch` leaves them (0: one not finished)."""
                await archive.sync_state(DEVICE, "shots")
                await archive.put(DEVICE, "shots", generation, [
                    (row[0], f"43:{row[NAMES.index('endedAtMs')]}", rev, dict(zip(NAMES, row[:-1])), row[-1])
                    for row, (_, rev) in zip(ROWS, PAIRS)])
                await archive.adopt(DEVICE, "shots", generation, epoch, 1, [rid for rid, _ in PAIRS], [2400, N + 1])

            async def sql(statement, *args):
                await service.offload(lambda: companion.logs.connection.execute(statement, args))

            await copy(1, EPOCH)
            a = await Browser(web, base, CLIENTS[0]).open()
            session = await asyncio.wait_for(fake.sessions.get(), 3)
            await eventually(lambda: companion.screens.mux.upstream.state == "open")
            await a.send({"op": "stats", "on": True, "request": 1, "offset": 0, "limit": 10, "sort": "date",
                          "dir": "desc"})
            standing = await a.next("stats", 1)
            assert standing["snapshot"] and standing["cols"] == COLS
            assert (await a.records())["rows"] == FLAT

            async def window(screen, offset, limit=50, **op):
                """One offline-copy window: (its frames, whether it went to the controller)."""
                screen.request += 1
                op = {"op": "stats", "on": True, "fetch": True, "request": screen.request, "offset": offset,
                      "limit": limit, "sort": "date", "dir": "desc", "filter": {}, **op}
                before = fetches(session)
                await screen.send(op)
                frames = await screen.page(op)
                rows = [row for frame in frames for row in frame["rows"]]
                assert json.dumps(rows) == json.dumps(ROWS[offset:offset + limit]), "the same rows either way"
                return frames, fetches(session) > before

            # --- Served: the controller sends nothing; a cold copy of every shot ---------------------
            frames, forwarded = await window(a, 0)
            assert not forwarded and len(frames) > 1 and all("stats" not in frame for frame in frames)
            assert [frame["rowBase"] for frame in frames] == sorted({frame["rowBase"] for frame in frames})
            assert all(len(json.dumps(frame, separators=(",", ":"))) <= 8192 for frame in frames)
            assert frames[0]["seq"] == standing["seq"] + 1 and frames[0]["request"] == a.request
            assert (frames[0]["total"], frames[0]["good"], frames[-1]["hasMore"]) == (N, N, True)
            ops, started, received = len(session.ops), time.monotonic(), 0
            for offset in range(0, N, 50):
                frames, forwarded = await window(a, offset)
                assert not forwarded
                received += sum(len(json.dumps(frame, separators=(",", ":"))) for frame in frames)
            elapsed = time.monotonic() - started
            assert len(session.ops) == ops, "a cold copy of every shot asks the controller nothing"
            assert frames[-1]["hasMore"] is False

            # --- Each doubt sends the window to the controller ------------------------------------------
            await sql("update archive_records set rev = rev + 1 where id = ?", PAIRS[60][0])
            assert (await window(a, 50))[1], "a row under another revision"
            await sql("update archive_records set rev = rev - 1 where id = ?", PAIRS[60][0])
            await sql("delete from archive_records where id = ?", PAIRS[110][0])
            assert (await window(a, 100))[1], "a missing row"
            await copy(1, EPOCH)
            await sql("update archive_records set kept = 1 where id = ?", PAIRS[0][0])
            assert (await window(a, 0))[1], "a row the user is removing from the controller"
            await sql("update archive_records set kept = 0 where id = ?", PAIRS[0][0])
            await sql("update archive_records set body = json_remove(body, '$.badReason') where id = ?", PAIRS[5][0])
            assert (await window(a, 0))[1], "a row stored under other columns"
            await copy(1, EPOCH)
            companion.archive.on = False
            assert (await window(a, 0))[1], "the archive switch is off"
            companion.archive.on = True
            assert (await window(a, N - 10, 20))[1], "a window past the index"
            assert not (await window(a, N - 20, 20))[1]
            changes = companion.logs.connection.total_changes
            assert not (await window(a, 200))[1] and companion.logs.connection.total_changes == changes, \
                "serving writes nothing"

            # The controller's history restarted: until the archive has copied all of the new one, nothing is
            # served; neither while its last complete sync is at another epoch.
            await archive.restart(DEVICE, "shots", 1, [2401, 1])
            assert (await window(a, 0))[1], "a restarted history"
            await copy(2, 0)
            assert (await window(a, 0))[1], "a restarted history still being copied"
            await copy(2, EPOCH - 1)
            assert (await window(a, 0))[1], "an archive synced to another epoch"
            await copy(2, EPOCH)
            assert not (await window(a, 0))[1]

            # A Stats page names another store epoch: forwarded until the index answers again.
            view = companion.screens.mux.views["stats"]
            await session.send({**stats_page(session, {}, False, EPOCH + 1)[0], "request": view.request})
            await a.next("stats", 1)
            assert (await window(a, 0))[1], "the store epoch moved"
            assert "rows" not in await a.records(EPOCH)
            assert not (await window(a, 0))[1]
            # So does the link's notice.
            await companion._on_frame({"t": "rs", "sh": EPOCH + 1})
            assert (await window(a, 0))[1], "the notice named another store epoch"
            assert "rows" not in await a.records(EPOCH)
            assert not (await window(a, 0))[1]
            # A newer firmware's page shape is never imitated: forwarded until the controller's next page.
            for newer in ({"v": 2}, {"newer": 1}):
                await session.send({**stats_page(session, {}, False, EPOCH)[0], "request": view.request, **newer})
                await a.next("stats", 1)
                assert (await window(a, 0))[1], f"a newer page shape {newer}"
            assert not (await window(a, 0))[1]

            # A page to this screen half sent: the window waits for the controller's turn, as before.
            half = {**stats_page(session, {}, False, EPOCH)[0], "request": view.request, "more": True}
            await session.send(half)
            await a.next("stats", 1)
            assert (await window(a, 0))[1], "a page half sent"
            await session.send({**{key: value for key, value in half.items() if key not in ("stats", "cols", "tag")},
                                "rows": [], "rowBase": 10, "more": False})
            await a.next("stats", 1)
            assert not (await window(a, 0))[1]

            # A screen answered with another epoch than the companion's index now holds.
            fake.epoch, fake.indexes["shots"] = EPOCH + 2, (EPOCH + 2, FLAT)
            await copy(2, EPOCH + 2)
            b = await Browser(web, base, CLIENTS[1]).open()
            await b.send({"op": "stats", "on": True, "request": 1, "offset": 0, "limit": 10, "sort": "date",
                          "dir": "desc"})
            await b.next("stats", 1)
            assert (await b.records())["epoch"] == EPOCH + 2
            assert (await window(a, 0))[1], "a screen holding another epoch"
            assert not (await window(b, 0))[1]
            assert (await a.records(EPOCH))["epoch"] == EPOCH + 2
            assert not (await window(a, 0))[1]

            # An archive that cannot read: forwarded, said once in the log.
            reader = archive.window

            async def failing(*_):
                raise sqlite3.OperationalError("disk I/O error")
            archive.window = failing
            assert (await window(a, 0))[1] and (await window(a, 50))[1], "an archive read error"
            assert sum("could not answer an offline-copy window" in line for line in lines.lines) == 1
            # A doubt that arose while the archive read: the window goes to the controller after all.
            async def racing(*args):
                bodies = await reader(*args)
                companion.archive.on = False
                return bodies
            archive.window = racing
            assert (await window(a, 0))[1], "a doubt during the read"
            archive.window, companion.archive.on = reader, True
            # A read stuck behind the disk thread (a vacuum): forwarded in time; its late result is dropped.
            async def stuck(*args):
                await service.offload(time.sleep, 1)
                return await reader(*args)
            archive.window, mux.ARCHIVE_READ_S, started = stuck, 0.2, time.monotonic()
            assert (await window(a, 0))[1] and time.monotonic() - started < 1, "a read stuck behind the disk"
            await asyncio.sleep(1)
            while not a.frames.empty():
                frame = a.frames.get_nowait()
                assert not (frame and frame.get("request") == a.request), "one page"
            archive.window, mux.ARCHIVE_READ_S = reader, 2

            # An index no `sum` verified (a firmware without deltas): every window goes to the controller.
            async def unverified(controller_session, op):
                if op["op"] != "records":
                    return False
                await controller_session.send({"v": 1, "type": "records", "boot": 7, "store": "shots",
                                               "epoch": EPOCH + 3, "rows": FLAT})
                return True
            fake.handler, fake.epoch = unverified, EPOCH + 3
            await copy(2, EPOCH + 3)
            assert (await a.records(EPOCH + 2))["epoch"] == EPOCH + 3
            assert (await window(a, 0))[1], "an unverified index"
            fake.handler = None
            fake.epoch, fake.indexes["shots"] = EPOCH + 4, (EPOCH + 4, FLAT)
            await copy(2, EPOCH + 4)
            assert (await a.records(EPOCH + 3))["epoch"] == EPOCH + 4
            assert not (await window(a, 0))[1]

            # Home's hero fetch has the same shape: from a screen on Stats that was never given the index it goes
            # to the controller; once given it, the archive answers it like any window.
            c = await Browser(web, base, CLIENTS[2]).open()
            await c.send({"op": "stats", "on": True, "request": 1, "offset": 0, "limit": 10, "sort": "date",
                          "dir": "desc"})
            await c.next("stats", 1)
            assert (await window(c, 1, 2))[1], "a screen never given the index"
            await c.records()
            assert not (await window(c, 1, 2))[1]

            async def quiet(screen, during):
                """A window whose archive read ends with `during`: nothing reaches the controller or the screen."""
                done, before = asyncio.Event(), fetches(session)

                async def read(*args):
                    bodies = await reader(*args)
                    await during()
                    done.set()
                    return bodies
                archive.window = read
                screen.request += 1
                await screen.send({"op": "stats", "on": True, "fetch": True, "request": screen.request, "offset": 0,
                                   "limit": 50, "sort": "date", "dir": "desc", "filter": {}})
                await asyncio.wait_for(done.wait(), 3)
                await asyncio.sleep(0.2)
                archive.window, companion.archive.on = reader, True
                assert fetches(session) == before, "nothing asked of the controller"
                while not screen.frames.empty():
                    frame = screen.frames.get_nowait()
                    assert not (frame and frame.get("request") == screen.request), "no page"

            def mine(client):
                return next(screen for screen in companion.screens.mux.screens if screen.id == client)

            async def closed():  # Closed by the companion, and a doubt arose too.
                mine(CLIENTS[2]).close(4002)
                companion.archive.on = False
            await quiet(c, closed)

            async def answered(screen, during, offset=0, limit=50):
                """A window whose archive read ends with `during`: still answered, as `window` returns it."""
                async def read(*args):
                    bodies = await reader(*args)
                    await during()
                    return bodies
                archive.window = read
                try:
                    return await window(screen, offset, limit)
                finally:
                    archive.window, companion.archive.on = reader, True

            async def doubt():
                companion.archive.on = False

            # Home's hero fetch from a screen with no Stats view: the controller's until the screen was given the
            # index, then the archive's; a doubt during the read sends it to the controller, never drops it.
            d = await Browser(web, base, CLIENTS[3]).open()
            await d.next("home")
            assert (await window(d, 1, 2))[1], "a screen without Stats never given the index"
            await d.records()
            assert mine(CLIENTS[3]).records["stats"].group is None
            assert not (await window(d, 1, 2))[1], "a screen without Stats"
            assert (await answered(d, doubt, 1, 2))[1], "a doubt during the read, without Stats"

            await b.ws.close()
            await c.ws.close()
            await d.ws.close()
            await eventually(lambda: len(companion.screens.mux.bound()) == 1)

            async def left():  # The last screen left Stats: its window is still answered, by the controller, as
                await a.send({"op": "stats", "on": False})  # no Stats page names the columns any more.
                await eventually(lambda: mine(CLIENTS[0]).records["stats"].group is None)
            assert (await answered(a, left))[1], "left Stats during the read"
            # Back on Stats before the controller's page came: the window waits for the controller's turn.
            async def holding(_, op):  # The controller's page for this subscribe comes later, sent below.
                return op["op"] == "stats" and not op.get("fetch")
            fake.handler = holding
            await a.send({"op": "stats", "on": True, "request": 1, "offset": 0, "limit": 10, "sort": "date",
                          "dir": "desc"})
            await eventually(lambda: view.standing is not None)
            a.request, before = a.request + 1, fetches(session)
            op = {"op": "stats", "on": True, "fetch": True, "request": a.request, "offset": 0, "limit": 50,
                  "sort": "date", "dir": "desc", "filter": {}}
            await a.send(op)
            await asyncio.sleep(0.2)
            fake.handler = None
            await session.send({**stats_page(session, {}, True, EPOCH + 4)[0], "request": view.request})
            rows = [row for frame in await a.page(op) for row in frame["rows"]]
            assert fetches(session) == before + 1 and json.dumps(rows) == json.dumps(ROWS[:50]), "no page yet"
            assert not (await window(a, 0))[1]

            # --- Every other Stats op reaches the controller as before, its answer the screen ---------------
            standing_op = {"op": "stats", "on": True, "fetch": True, "offset": 0, "limit": 10, "sort": "date",
                           "dir": "desc", "filter": {}, "window": 10}
            for op, expected in (
                    ({"offset": 10, "limit": 10, "sort": "date", "dir": "desc"}, {"offset": 10}),  # A scroll page.
                    ({"offset": 0, "limit": 50, "sort": "rating", "dir": "desc", "filter": {}},
                     {"limit": 50, "sort": "rating"}),
                    ({"offset": 0, "limit": 50, "sort": "date", "dir": "asc", "filter": {}},
                     {"limit": 50, "dir": "asc"}),
                    ({"offset": 0, "limit": 50, "sort": "rating", "dir": "asc", "filter": {}},
                     {"limit": 50, "sort": "rating", "dir": "asc"}),
                    ({"offset": 0, "limit": 50, "sort": "date", "dir": "desc", "filter": {"result": ["fast"]}},
                     {"limit": 50, "filter": {"result": ["fast"]}}),
                    ({"offset": 0, "limit": 50, "sort": "date", "dir": "desc", "filter": {"preset": [1]}},
                     {"limit": 50, "filter": {"preset": [1]}}),
                    ({"offset": 0, "limit": 50, "sort": "date", "dir": "desc", "filter": {"scale": [5]}},
                     {"limit": 50, "filter": {"scale": [5]}}),
                    ({"offset": 0, "limit": 50, "sort": "date", "dir": "desc", "filter": {"bad": True}},
                     {"limit": 50, "filter": {"bad": True}}),  # Show bad shots.
                    ({"offset": 0, "limit": 50, "sort": "date", "dir": "desc", "filter": {"bad": False}},
                     {"limit": 50}),
                    ({"offset": 0, "limit": 51, "sort": "date", "dir": "desc", "filter": {}}, {"limit": 51}),
                    ({"offset": 0, "limit": 1000, "sort": "date", "dir": "desc", "filter": {}},  # CSV export.
                     {"limit": 1000}),
                    ({"offset": 0, "limit": 50, "dir": "desc", "filter": {}}, {"limit": 50}),
                    ({"offset": 0, "limit": 50, "sort": "date", "filter": {}}, {"limit": 50}),
                    ({"offset": 0, "sort": "date", "dir": "desc", "filter": {}}, {}),
                    ({"offset": 20, "limit": 50, "sort": "date", "dir": "desc", "filter": {}, "request": None},
                     {"offset": 20, "limit": 50})):
                a.request += 1
                op = {"op": "stats", "on": True, "fetch": True, "request": a.request, **op}
                op = {key: value for key, value in op.items() if value is not None}
                before = len(session.ops)
                await a.send(op)
                frames = await a.page(op)
                assert len(session.ops) == before + 1
                assert session.ops[-1] == {**standing_op, **expected, "request": session.ops[-1]["request"]}, op
                assert frames == [{**frame, "request": op.get("request", 0), "seq": frames[0]["seq"]}
                                  for frame in sent], op
            # A standing page in another order is the controller's, as before.
            before = len(session.ops)
            await a.send({"op": "stats", "on": True, "request": 2, "offset": 0, "limit": 10, "sort": "rating",
                          "dir": "desc"})
            assert (await a.next("stats", 2))["stats"] and session.ops[before:] == [
                {"op": "stats", "on": True, "request": session.ops[-1]["request"], "offset": 0, "limit": 10,
                 "sort": "rating", "dir": "desc"}]

            await a.ws.close()
            await pages.close()
            await companion.relay.close()
            await companion.logs.close()
    await server.close()
    print(f"Companion offline copy from the archive: a cold copy of {N} shots in {elapsed:.2f} s "
          f"({received // 1024} KiB, nothing asked of the controller), every guard and other Stats op OK")


asyncio.run(main())
