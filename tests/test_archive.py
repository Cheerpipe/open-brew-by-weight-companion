#!/usr/bin/env python3
"""The shot and activation archive against a scripted controller.

The controller's side follows the firmware's link record frames (`rx`, `rf`,
`rt` answered by `rec`, `trc` and `rs`, docs/COMPANION_LINK.md) and its store
rules (ids restart only after a clear, the oldest rotate out past the
capacity), written from the design, not from the companion's code. Frames go
straight through the companion's frame handler; the link's own transport is
test_link.py's. Offline, inside the image (see the README).
"""

import asyncio
import base64
import json
import logging
import sys
import tempfile
import zlib
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import aiohttp  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

from companion import archive, link, service, stats  # noqa: E402
from companion.service import Companion, web_app  # noqa: E402

DEVICE = "AA:BB:CC:DD:EE:FF"
COLS = ["id", "bootId", "endedAtMs", "hasWallTime", "endedAtUnixSec", "endedAtLocalSec", "rating", "badReason",
        "durationS", "actualG", "goalG", "avgFlowGS", "arrivalS", "cutLineG", "fastBeforeS", "slowAfterS",
        "verdict", "presetId", "presetName", "scaleName", "shotType", "stopDetail"]
archive.REQUEST_S = 0.5
archive.TRACE_RETRY_S = 0.2


class Lines(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.INFO)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class Upstream:
    """No La Marzocco in these tests."""

    sub = up = refused = False
    ep = tok = 0

    def __init__(self, store, events):
        pass

    def configure(self, *_):
        pass

    def stop(self):
        pass

    def erase(self):
        pass

    def rejected_for(self, _):
        return False

    def signed_in_for(self, _):
        return False


class Controller:
    """The controller's two record stores and its answers to the archive's requests."""

    def __init__(self, capacity=40):
        self.capacity, self.boot, self.clock = capacity, 7, 1789000000
        self.stores = {"shots": {}, "history": {}}
        self.next = {"shots": 1, "history": 1}
        self.epochs = {"shots": 11, "history": 21}
        self.traces = {}  # shot id -> bytes, None (no trace) or "busy"
        self.requests = []
        self.ignore = 0  # Index requests left unanswered (a lost frame).
        self.held = None  # A list while a hold keeps the requests back (and the pings unanswered).
        self.hold_next = False  # A hold starts right after the next index answer.

    def moved(self, store):
        self.epochs[store] += 1

    def add_shot(self, bad=None, trace=b"T", clock=True):
        rid = self.next["shots"]
        self.next["shots"] += 1
        end = rid * 1000 + 17
        self.stores["shots"][rid] = ({
            "id": rid, "bootId": self.boot, "endedAtMs": end, "hasWallTime": clock,
            "endedAtUnixSec": self.clock + rid * 3600 if clock else 0,
            "endedAtLocalSec": self.clock + rid * 3600 - 10800 if clock else 0, "rating": 0, "badReason": bad,
            "durationS": 9.0 if bad else 24.0 + rid % 7, "actualG": 36.0 + rid % 5 / 2, "goalG": 36,
            "avgFlowGS": 1.5 + rid % 4 / 10, "arrivalS": [None, 26.5, 28.0, 31.5][rid % 4], "cutLineG": None,
            "fastBeforeS": 25, "slowAfterS": 32, "verdict": ["on_recipe", "fast", "on_recipe", "slow"][rid % 4],
            "presetId": rid % 3 + 1, "presetName": f"Preset {rid % 3 + 1}", "scaleName": ["Lunar", "Pearl S"][rid % 2],
            "shotType": "auto", "stopDetail": "normal_target"}, {"wD": f"curve{rid}", "wBreakBefore": [], "wHeld": []})
        self.traces[rid] = trace + bytes([rid % 256]) if trace else trace
        self._rotate("shots")
        return rid

    def add_activation(self, kind="shot", clock=True, duration=25.0):
        rid = self.next["history"]
        self.next["history"] += 1
        self.stores["history"][rid] = {"id": rid, "type": kind, "durationS": duration, "hasWallTime": clock,
                                       "endedAtUnixSec": self.clock + rid if clock else 0,
                                       "endedAtLocalSec": self.clock + rid - 10800 if clock else 0}
        self._rotate("history")
        return rid

    def _rotate(self, store):
        while len(self.stores[store]) > self.capacity:
            del self.stores[store][min(self.stores[store])]
        self.moved(store)

    def clear(self, store):
        self.stores[store], self.next[store] = {}, 1
        self.moved(store)

    def rev(self, store, rid):
        record = self.stores[store][rid]
        return zlib.crc32(json.dumps(record, sort_keys=True).encode()) & 0xFFFFFF

    def newest_first(self, store):
        return sorted(self.stores[store], reverse=True)

    async def serve(self, companion, outbox):
        while True:
            frame = await outbox.get()
            if frame["t"] in ("rx", "rf", "rt", "logsub"):
                self.requests.append(frame)
                if self.held is not None:
                    self.held.append(frame)
                    continue
                if frame["t"] != "logsub":
                    await self.answer(companion, frame)

    async def release(self, companion):
        """The hold ends: what arrived meanwhile is answered, then the pings are answered again."""
        held, self.held = self.held, None
        for frame in held:
            if frame["t"] != "logsub":
                await self.answer(companion, frame)

    async def beat(self, companion):
        """The controller's reply to each companion ping: the hold frame, `sync` false while clear."""
        while True:
            await asyncio.sleep(0.05)
            if self.held is None:
                await companion._on_frame({"t": "hold", "on": False, "sync": False})

    async def answer(self, companion, frame):
        kind = frame["t"]
        if kind == "rx":
            if self.ignore:
                self.ignore -= 1
                return
            store, f = frame["s"], {"v": 1, "type": "records", "boot": self.boot, "store": frame["s"],
                                    "epoch": self.epochs[frame["s"]]}
            if frame["ep"] != self.epochs[store]:
                f["rows"] = [value for rid in self.newest_first(store) for value in (rid, self.rev(store, rid))]
            await companion._on_frame({"t": "rec", "f": f})
            if self.hold_next:  # A scaled shot starts: the controller tells the companion at once.
                self.hold_next, self.held = False, []
                await companion._on_frame({"t": "hold", "on": False, "sync": True})
        elif kind == "rf":
            store, ids = frame["s"], self.newest_first(frame["s"])[frame["o"]:frame["o"] + frame["n"]]
            if store == "history":
                await companion._on_frame({"t": "rec", "f": {
                    "v": 1, "type": "history", "boot": self.boot, "snapshot": False, "epoch": self.epochs[store],
                    "request": frame["r"], "records": [self.stores[store][rid] for rid in ids]}})
                return
            rows = [[self.stores[store][rid][0][key] for key in COLS] + [self.stores[store][rid][1]] for rid in ids]
            seq = len(self.requests)
            for base in range(0, max(len(rows), 1), 2):  # Two rows a frame: a page across frames.
                f = {"v": 1, "type": "stats", "boot": self.boot, "snapshot": False, "epoch": self.epochs[store],
                     "seq": seq, "request": frame["r"], "total": len(self.stores[store]), "offset": frame["o"],
                     "limit": frame["n"], "hasMore": False, "rows": rows[base:base + 2], "rowBase": base,
                     "more": base + 2 < len(rows)}
                if base == 0:
                    f.update(cols=",".join(COLS), tag=1)
                await companion._on_frame({"t": "rec", "f": f})
        else:
            identity = (frame["id"], frame["b"], frame["e"])
            record = self.stores["shots"].get(frame["id"])
            trace = self.traces.get(frame["id"]) if record and (
                record[0]["id"], record[0]["bootId"], record[0]["endedAtMs"]) == identity else None
            answer = {"t": "trc", "id": frame["id"], "b": frame["b"], "e": frame["e"]}
            if trace in ("busy", "saving"):
                answer["r"] = trace
            elif trace:
                answer.update(r="ok", d=base64.b64encode(trace).decode())
            else:
                answer["r"] = "none"
            await companion._on_frame(answer)

    async def notice(self, companion):
        await companion._on_frame({"t": "rs", "sh": self.epochs["shots"], "hi": self.epochs["history"]})


async def sql(companion, statement, *args):
    return await service.offload(lambda: [tuple(row) for row in companion.logs.connection.execute(statement, args)])


async def ids(companion, store, generation=None):
    """The ids of one store: of every generation, or of one."""
    return {row[0] for row in await sql(companion, "select id from archive_records where store = ? and "
                                                   "generation = coalesce(?, generation)", store, generation)}


async def row(companion, store, rid, generation=1):
    return json.loads((await sql(companion, "select body from archive_records where store = ? and id = ? "
                                            "and generation = ?", store, rid, generation))[0][0])


async def settled(companion):
    """The sync has nothing left to do."""
    for _ in range(300):
        await asyncio.sleep(0.02)
        if not companion.archive.wake.is_set() and companion.archive.syncing is None and \
                not companion.archive.wanted:
            await asyncio.sleep(0.05)
            if companion.archive.syncing is None and not companion.archive.wake.is_set():
                return
    raise AssertionError("the archive sync did not settle")


def firmware_key(row, sort, direction):
    """The controller's comparators, written from its code: date is (generation, id); rating puts
    unrated shots last whatever the direction, then the rating, then the newest first."""
    g, rid = row["archiveGeneration"], row["id"]
    if sort == "rating":
        rating = row["rating"]
        return (rating == 0, rating if direction == "asc" else -rating, -g, -rid)
    return (g, rid) if direction == "asc" else (-g, -rid)


def firmware_match(row, query):
    """shotListFilterMatches: AND across groups, OR within; a result needs an arrival."""
    if not query.get("bad") and row["badReason"] is not None:
        return False
    if query.get("result") and (not row["arrivalS"] or row["verdict"] not in query["result"]):
        return False
    if query.get("preset") and row["presetId"] not in query["preset"]:
        return False
    return not query.get("scale") or zlib.crc32(row["scaleName"].encode()) ^ 0xFFFFFFFF in query["scale"]


async def parity(companion, get):
    """A fixture of archive-only shots: a closed generation, the open one below its oldest, and kept rows
    the controller no longer lists (which interleave by date), plus rows that are not archive-only."""
    def fixture():
        connection = companion.logs.connection
        with connection:
            connection.execute("delete from archive_records")
            connection.execute("delete from archive_sync")
            connection.execute("insert into archive_sync values (?, 'shots', 1, 0, 1, '[]', null)", (DEVICE,))
            listed = [rid for rid in range(15, 31) if rid not in (22, 25)]
            connection.execute("insert into archive_sync values (?, 'shots', 2, 9, 15, ?, 1789000000)",
                               (DEVICE, json.dumps(listed)))
            for generation, first, last in ((1, 1, 20), (2, 5, 30)):
                for rid in range(first, last + 1):
                    n = rid * 7 + generation
                    body = {"id": rid, "rating": n % 6 if n % 4 else 0, "presetId": n % 3 + 1,
                            "presetName": f"Preset {n % 3 + 1} g{generation}", "scaleName": ["Lunar", "Pearl S", ""][n % 3],
                            "arrivalS": [None, 0, 28.5, 31.0][n % 4], "verdict": ["on_recipe", "fast", "slow"][n % 3],
                            "badReason": "short" if n % 5 == 0 else None, "endedAtUnixSec": 1789000000 + rid}
                    connection.execute("insert into archive_records values (?, 'shots', ?, ?, '', 0, 'good', ?, ?, ?)",
                                       (DEVICE, generation, rid, int(body["badReason"] is not None),
                                        int(rid in (22, 23, 25)), json.dumps(body)))
    await service.offload(fixture)
    everything = (await get("/shots?limit=50&bad=1&sort=date&dir=asc"))["rows"]
    only = {(r["archiveGeneration"], r["id"]) for r in everything}
    expected_only = {(1, rid) for rid in range(1, 21)} | {(2, rid) for rid in range(5, 15)} | {(2, 22), (2, 25)}
    assert only == expected_only, sorted(only ^ expected_only)
    lunar = zlib.crc32(b"Lunar") ^ 0xFFFFFFFF
    filters = [{}, {"bad": "1"}, {"result": "fast,slow"}, {"preset": "1,3"}, {"scale": str(lunar)},
               {"bad": "1", "result": "on_recipe", "preset": "2"}]
    for sort in ("date", "rating"):
        for direction in ("desc", "asc"):
            for given in filters:
                query = {"bad": given.get("bad") == "1",
                         "result": given.get("result", "").split(",") if given.get("result") else [],
                         "preset": [int(v) for v in given.get("preset", "").split(",") if v],
                         "scale": [int(v) for v in given.get("scale", "").split(",") if v]}
                params = "&".join(f"{k}={v}" for k, v in {**given, "sort": sort, "dir": direction}.items())
                want = sorted((r for r in everything if firmware_match(r, query)),
                              key=lambda r: firmware_key(r, sort, direction))
                whole = (await get(f"/shots?limit=50&{params}"))["rows"]
                assert [(r["archiveGeneration"], r["id"]) for r in whole] == [
                    (r["archiveGeneration"], r["id"]) for r in want], (sort, direction, given)
                paged, cursor = [], None
                while True:
                    page = await get(f"/shots?limit=3&{params}" + (f"&cursor={cursor}" if cursor else ""))
                    paged += page["rows"]
                    cursor = page["next"]
                    if cursor is None:
                        break
                assert paged == whole, (sort, direction, given)
    dated = [(r["archiveGeneration"], r["id"]) for r in (await get("/shots?limit=50&bad=1"))["rows"]]
    assert dated.index((2, 25)) < dated.index((2, 22)) < dated.index((2, 14)), "kept rows interleave by date"
    presets = (await get("/shots?limit=1"))["presets"]
    assert len(presets) == 3 and all(name.endswith("g2") for _, name in presets), "the newest name per preset"
    for bad in ("sort=rating&dir=up", "result=early", "preset=x", "cursor=1", "scale=" + ",".join(["1"] * 9)):
        assert (await get(f"/shots?limit=5&{bad}", 400)) is None, bad
    history = (await get("/history?limit=5&sort=rating", 400))
    assert history is None, "History has no rating order"


class Link:
    """A session: the companion's outbox and the controller answering it."""

    def __init__(self, companion, fake):
        self.companion, self.fake = companion, fake

    async def open(self, archive_on=True, log=False, cfg=None):
        self.outbox = asyncio.Queue()
        self.companion.outbox = self.outbox
        self.task = asyncio.create_task(self.fake.serve(self.companion, self.outbox))
        self.pings = asyncio.create_task(self.fake.beat(self.companion))
        await self.companion._on_frame({"t": "dev", "name": "Kitchen", "id": DEVICE})
        await self.companion._on_frame(cfg or {"t": "cfg", "ui": True, "log": log, "archive": archive_on})

    def close(self):
        self.task.cancel()
        self.pings.cancel()
        self.companion.sync_due, self.companion.clear_at = {}, None  # As a new session starts them.
        self.companion.log_subscribed = self.companion.log_identified = self.companion.configured = False
        self.companion.archive.stop()
        self.companion.outbox = None


async def main():
    lines = Lines()
    logging.getLogger("obbw").addHandler(lines)
    fake = Controller()
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-archive-") as temporary:
        data = Path(temporary)
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", data, http, Upstream)
            await companion.open_log()
            verdict = {"value": True}

            async def allows(headers):
                return verdict["value"]
            companion._web_ui_allows = allows
            pages = TestServer(web_app(companion), host="127.0.0.1")
            await pages.start_server()
            base = f"http://127.0.0.1:{pages.port}/__companion/archive"
            session = {"X-WebUI-Session": "token"}

            async def post(path, body, headers=session):
                async with http.post(base + path, json=body, headers=headers) as reply:
                    return reply.status, await reply.json()

            async def get(path, status=200):
                async with http.get(base + path, headers=session) as reply:
                    assert reply.status == status, (path, reply.status)
                    return await reply.json() if status == 200 else None

            def said(text):
                return sum(text in line for line in lines.lines)

            # --- An older controller: no `archive` in cfg, nothing asked, shown unavailable --
            companion.outbox = outbox = asyncio.Queue()
            await companion._on_frame({"t": "dev", "name": "Kitchen", "id": DEVICE})
            await companion._on_frame({"t": "cfg", "ui": True, "log": False})
            assert not any(outbox.get_nowait()["t"] in ("rx", "rf", "rt") for _ in range(outbox.qsize()))
            assert (await companion.status())["archive"]["available"] is False
            companion.outbox = None

            # --- Backfill after pairing: bad shots, traces ok / none / still saving -------
            for n in range(30):
                fake.add_shot(bad="short" if n % 7 == 3 else None, trace=None if n == 5 else b"T")
                fake.add_activation("rinse" if n % 3 else "shot")
            fake.traces[30] = "saving"
            link_ = Link(companion, fake)
            await link_.open()
            await settled(companion)
            assert await ids(companion, "shots") == set(range(1, 31))
            assert await ids(companion, "history") == set(range(1, 31))
            stores = [frame.get("s", "trace") for frame in fake.requests]
            assert stores == sorted(stores, key=["history", "shots", "trace"].index), "activations, shots, traces"
            assert fake.requests[0] == {"t": "rx", "s": "history", "ep": 0}
            traces = dict(await sql(companion, "select id, data from archive_traces"))
            assert len(traces) == 29 and traces[6] is None, "a shot without a trace is never asked again"
            assert 30 not in traces, "a trace still being saved is asked again later"
            fake.traces[30] = b"late"
            await asyncio.sleep(0.4)
            await settled(companion)
            assert dict(await sql(companion, "select id, data from archive_traces"))[30] == b"late"
            bad = await sql(companion, "select id, kind from archive_records where store = 'shots' and bad = 1")
            assert {rid for rid, _ in bad} == {4, 11, 18, 25} and all(kind == "short" for _, kind in bad)
            state = await companion.archive.store.sync_state(DEVICE, "shots")
            assert state[:3] == (1, fake.epochs["shots"], 1) and state[3] == list(range(30, 0, -1))

            # --- An unchanged store costs nothing; a new shot fetches only itself -------
            fake.requests.clear()
            await fake.notice(companion)
            await settled(companion)
            assert fake.requests == [], "the notice names the epochs the archive holds"
            fake.add_shot()
            await fake.notice(companion)
            await settled(companion)
            assert [(frame["t"], frame.get("o"), frame.get("n")) for frame in fake.requests] == [
                ("rx", None, None), ("rf", 0, 1), ("rt", None, None)], fake.requests

            # --- A rating updates the row; a recycled (empty) curve keeps the copy ------
            record, curve = fake.stores["shots"][5]
            record["rating"], curve["wD"] = 4, ""
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            body = await row(companion, "shots", 5)
            assert body["rating"] == 4 and body["wD"] == "curve5", body

            # --- Deletions mirror: one inside, and the newest, which is not a restart ---
            del fake.stores["shots"][12]
            del fake.stores["shots"][31]
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            held = await ids(companion, "shots")
            assert 12 not in held and 31 not in held and len(held) == 29, "deleting the newest is not a restart"
            assert not await sql(companion, "select 1 from archive_traces where id in (12, 31)")
            assert not said("restarted")

            # --- A deleted oldest record reads as rotation and is kept -------------------
            del fake.stores["shots"][1]
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            assert 1 in await ids(companion, "shots")

            # --- One record with another identity replaces that record alone (S1) --------
            fake.stores["shots"][20][0]["bootId"] = 99
            fake.traces[20] = b"new20"
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            assert len(await ids(companion, "shots")) == 29 and not said("restarted")
            assert (await sql(companion, "select ident from archive_records where store = 'shots' and id = 20")) == [
                ("99:20017",)]
            assert dict(await sql(companion, "select id, data from archive_traces where id = 20")) == {20: b"new20"}
            assert said("shot 20 is a different record") == 1

            # --- Away: more shots than the controller keeps; the hole is recorded -------
            link_.close()
            for _ in range(60):
                fake.add_shot()
            assert min(fake.stores["shots"]) == 52
            await link_.open()
            await settled(companion)
            held = await ids(companion, "shots")
            assert set(range(52, 92)) <= held and set(range(2, 31)) - {12} <= held, "rotation is not deletion"
            assert not said("restarted"), "everything missing is below the controller's oldest"
            assert await sql(companion, "select generation, below, above, count from archive_holes") == [
                (1, 30, 52, 21)], "shots 31 to 51 (31 deleted, the rest rotated) were never copied"
            tail = await get("/shots?limit=50&bad=1")
            assert tail["holes"] == [{"generation": 1, "below": 30, "above": 52, "count": 21}]
            assert tail["generations"] == [{"generation": 1, "count": 69, "restartedAt": None, "current": True}]
            assert [r["id"] for r in tail["rows"]][:3] == [30, 29, 28] and tail["next"] is None
            assert all(r["archiveTrace"] is (r["id"] != 6) and r["archiveGeneration"] == 1 for r in tail["rows"])
            assert 25 not in [r["id"] for r in (await get("/shots?limit=50"))["rows"]], "bad shots only with bad=1"
            page = await get("/shots?limit=5&cursor=-1:-20&bad=1")
            assert [r["id"] for r in page["rows"]] == [19, 18, 17, 16, 15] and page["next"] == "-1:-15"

            # --- Archive-only edits are the companion's; controller-held ones are not ---
            assert await post("/rate", {"id": 30, "rating": 5}) == (200, {"ok": True})
            assert await post("/rate", {"id": 60, "rating": 5}) == (404, {"error": "NOT_FOUND"})
            assert (await post("/rate", {"id": 30, "rating": 6}))[0] == 400
            assert (await row(companion, "shots", 30))["rating"] == 5
            for rid in range(2, 12):
                assert await post("/delete", {"store": "shots", "id": rid}) == (200, {"ok": True})
            assert not await sql(companion, "select * from archive_exclusions"), "nothing listed was removed"
            assert await post("/delete", {"store": "shots", "id": 999}) == (404, {"error": "NOT_FOUND"})
            async with http.get(base + "/trace?id=29&boot=7&end=29017", headers=session) as reply:
                assert reply.status == 200 and await reply.read() == b"T\x1d"
            async with http.get(base + "/trace?id=6&boot=7&end=6017", headers=session) as reply:
                assert reply.status == 404 and (await reply.json())["error"] == "NO_SHOT_TRACE"

            # --- Remove from the archive only: not copied again while the controller has it --
            assert await post("/delete", {"store": "shots", "id": 60}) == (200, {"ok": True})
            assert await sql(companion, "select id from archive_exclusions") == [(60,)]
            fake.requests.clear()
            fake.add_shot()  # 92; 52 rotates out
            await fake.notice(companion)
            await settled(companion)
            assert 60 not in await ids(companion, "shots") and {52, 92} <= await ids(companion, "shots")
            assert [frame.get("o") for frame in fake.requests if frame["t"] == "rf"] == [0]
            del fake.stores["shots"][60]
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            assert not await sql(companion, "select * from archive_exclusions"), "the id left the index"

            # --- Remove from the controller, keep in the archive: no inferred deletion ---
            assert await post("/keep", {"store": "shots", "id": 61}) == (200, {"ok": True})
            assert await post("/keep", {"store": "shots", "id": 999}) == (404, {"error": "NOT_FOUND"})
            del fake.stores["shots"][61]
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            assert 61 in await ids(companion, "shots")
            assert 61 in [r["id"] for r in (await get("/shots?limit=50&bad=1"))["rows"]], "kept and not listed"

            # --- Keep records deleted on the controller (S6): on keeps, off mirrors -----
            assert await post("/settings", {"keepDeleted": True}) == (200, {"ok": True})
            assert (await post("/settings", {"keepDeleted": 1}))[0] == 400
            assert (await companion.status())["archive"]["keepDeleted"] is True
            del fake.stores["shots"][62]
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            assert (await sql(companion, "select kept from archive_records where store = 'shots' and id = 62")) == [
                (1,)]
            assert await post("/settings", {"keepDeleted": False}) == (200, {"ok": True})
            del fake.stores["shots"][63]
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            assert 63 not in await ids(companion, "shots") and 62 in await ids(companion, "shots")

            # --- Access: reads keep a remembered grant; changes need the controller now --
            verdict["value"] = False
            companion.log_grants.clear()
            async with http.get(base + "/history?limit=5", headers={"X-WebUI-Session": "other"}) as reply:
                assert reply.status == 401 and (await reply.json())["error"] == "AUTH_REQUIRED"
            assert (await post("/rate", {"id": 30, "rating": 1}, {"X-WebUI-Session": "other"}))[0] == 401
            verdict["value"] = True
            await get("/history?limit=5")
            verdict["value"] = None  # The controller is off.
            companion.log_unreachable = 0
            await get("/history?limit=5")  # A browser it accepted keeps reading.
            assert await post("/rate", {"id": 30, "rating": 1}) == (503, {
                "error": "CONTROLLER_UNREACHABLE", "message": "The controller must be on to confirm your sign-in"})
            verdict["value"] = True
            async with http.post(base + "/rate", data="{}", headers=session) as reply:
                assert reply.status == 415

            # --- Clear history, then new shots: the generation closes, nothing goes (S4) --
            before = await ids(companion, "shots")
            fake.clear("shots")
            for _ in range(5):
                fake.add_shot()
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "shots", 1) == before, "the closed generation keeps every record"
            assert await ids(companion, "shots", 2) == set(range(1, 6))
            assert said("shot history restarted") == 1 and not await sql(companion, "select * from archive_holes "
                                                                                     "where generation = 2")
            generations = (await companion.status())["archive"]["generations"]["shots"]
            assert [(g["generation"], g["count"], g["current"]) for g in generations] == [
                (2, 5, True), (1, len(before), False)] and generations[0]["restartedAt"] > 0
            tail = await get("/shots?limit=50&bad=1")
            assert tail["rows"][0]["archiveGeneration"] == 1 and tail["rows"][0]["id"] == max(before), \
                "the closed generation is archive-only"
            assert len(await sql(companion, "select * from archive_traces where generation = 2")) == 5

            # --- Activations: more than half of the last index missing restarts (c) ------
            link_.close()
            fake.clear("history")
            for n in range(8):
                fake.add_activation(clock=False, duration=20.0 + n)
            await link_.open()
            await settled(companion)
            assert await ids(companion, "history", 1) == set(range(1, 31))
            assert await ids(companion, "history", 2) == set(range(1, 9))
            assert said("activation history restarted") == 1

            # --- Every shared id another record, on a store without a clock (S1 b, S2) ---
            fake.clear("history")
            for n in range(8):
                fake.add_activation(clock=False, duration=40.0 + n)
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "history", 2) == set(range(1, 9)) == await ids(companion, "history", 3)
            assert said("activation history restarted") == 2, "every immutable field tells clockless records apart"
            assert (await row(companion, "history", 1, 3))["durationS"] == 40.0
            assert (await row(companion, "history", 1, 2))["durationS"] == 20.0

            # --- An empty index after a clear keeps everything --------------------------
            fake.clear("history")
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "history", 3) == set(range(1, 9)) and said("activation history restarted") == 2

            # --- A lost answer is asked again; the first new record closes the generation --
            fake.ignore = 1
            fake.add_activation()
            await fake.notice(companion)
            await asyncio.sleep(0.8)
            await settled(companion)
            assert said("did not answer the archive's rx") >= 1
            assert await ids(companion, "history", 4) == {1} and await ids(companion, "history", 3) == set(range(1, 9))

            # --- The link closes mid-sync: nothing doubled, the epoch waits -------------
            for _ in range(6):
                fake.add_shot()
            fake.held = []
            await fake.notice(companion)
            await asyncio.sleep(0.2)
            link_.close()
            fake.held = None
            assert (await companion.archive.store.sync_state(DEVICE, "shots"))[1] != fake.epochs["shots"]
            await link_.open()
            await settled(companion)
            assert await ids(companion, "shots", 2) == set(range(1, 12))
            assert (await companion.archive.store.sync_state(DEVICE, "shots"))[1] == fake.epochs["shots"]

            # --- Switch off: nothing asked, everything kept; on again catches up --------
            await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": False})
            fake.requests.clear()
            fake.add_shot()
            await fake.notice(companion)
            await asyncio.sleep(0.2)
            assert fake.requests == [] and await ids(companion, "shots", 2) == set(range(1, 12))
            await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": True})
            await settled(companion)
            assert 12 in await ids(companion, "shots", 2)

            # --- Bulk deletes: the open generation (Clear's copy option), one, a range ---
            assert await post("/erase", {"store": "history", "current": True}) == (200, {"ok": True, "deleted": 1})
            assert await ids(companion, "history", 4) == set() and await ids(companion, "history", 1)
            fake.requests.clear()
            fake.add_activation()  # The cleared copy's record stays out while the controller holds it.
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "history", 4) == {2}
            first = len(await ids(companion, "shots", 1))
            assert await post("/erase", {"store": "shots", "generation": 1}) == (200, {"ok": True, "deleted": first})
            assert [g["generation"] for g in (await companion.status())["archive"]["generations"]["shots"]] == [2]
            clock = fake.clock
            assert await post("/erase", {"store": "shots", "from": clock + 3 * 3600, "to": clock + 4 * 3600}) == (
                200, {"ok": True, "deleted": 2})
            assert await ids(companion, "shots", 2) == set(range(1, 13)) - {3, 4}
            assert await post("/erase", {"from": 0, "to": 2 ** 32 - 1, "store": "history"}) == (
                200, {"ok": True, "deleted": 31}), "only records with a wall clock have a date"
            assert await ids(companion, "history", 2) and not await ids(companion, "history", 4)
            assert (await post("/erase", {"store": "milk"}))[0] == 400

            # --- Status and an export across generations -------------------------------
            facts = (await companion.status())["archive"]
            assert facts["on"] and facts["available"] and facts["shotsTotal"] == 10 and facts["bytes"] > 0
            async with http.get(base + "/export", headers=session) as reply:
                exported = json.loads(await reply.read())
            assert exported["format"] == "openbrewbyweight-companion-archive" and exported["device"] == DEVICE
            assert {r["archiveGeneration"] for r in exported["history"]} == {2, 3}
            assert [(r["archiveGeneration"], r["id"]) for r in exported["shots"]] == [
                (2, rid) for rid in sorted(set(range(1, 13)) - {3, 4})]
            assert exported["traces"][0]["generation"] == 2 and base64.b64decode(exported["traces"][0]["data"])

            # --- Delete everything: what the controller keeps comes back ----------------
            assert (await post("/erase", {}))[0] == 200
            assert not await sql(companion, "select * from archive_records")
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "shots", 1) == set(range(1, 13)) and await ids(companion, "history", 1) == {1, 2}

            # --- A factory reset, then pairing again: every record stays, closed (S8) ----
            link_.close()
            fake.clear("shots")
            fake.clear("history")
            fake.boot = 8
            await link_.open()  # Paired again: the same controller id reattaches to its archive.
            await settled(companion)
            assert await ids(companion, "shots", 1) == set(range(1, 13)), "an empty index changes nothing"
            fake.add_shot()
            fake.add_activation(duration=31.0)
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "shots", 1) == set(range(1, 13)) and await ids(companion, "shots", 2) == {1}
            assert await ids(companion, "history", 1) == {1, 2} and await ids(companion, "history", 2) == {1}

            # --- A hold mid-sync stops both directions, timers included (S17) ------------
            new = {fake.add_shot() for _ in range(4)}
            fake.hold_next = True
            seen = len(fake.requests)
            await fake.notice(companion)
            await asyncio.sleep(0.8)  # Past the 0.5 s re-ask: it is armed, not sent.
            assert len(fake.requests) == seen + 1 and fake.requests[-1]["t"] == "rx", fake.requests[seen:]
            assert companion.sync_due and not await ids(companion, "shots", 2) >= new
            await fake.release(companion)
            await settled(companion)
            assert await ids(companion, "shots", 2) >= new
            assert await sql(companion, "select count(*) from archive_records where store = 'shots' and "
                                        f"generation = 2 and id between {min(new)} and {max(new)}") == [(4,)], \
                "nothing lost, nothing doubled"
            assert (await companion.archive.store.sync_state(DEVICE, "shots"))[1] == fake.epochs["shots"]

            # --- The Stats header over the whole history (S13, S15, S16, S18) -----------
            synced = fake.epochs["shots"]
            async with http.get(base + f"/stats?window=10&active=2&epoch={synced}", headers=session) as reply:
                answer = await reply.json()
            merged = [json.loads(body) for (body,) in await sql(
                companion, "select body from archive_records where store = 'shots' order by generation desc, id desc")]
            assert reply.status == 200 and answer["epoch"] == synced
            assert answer["stats"] == stats.header(merged, 10, 2) and answer["stats"]["shotCount"] == 10
            assert answer["good"] == stats.good(merged, (), (), ()) > 10
            for window in (50, 100, 500, 1000):
                assert (await get(f"/stats?window={window}&active=2&epoch={synced}"))["stats"] == \
                    stats.header(merged, window, 2)
            fast = await get(f"/stats?window=10&active=2&epoch={synced}&result=fast&preset=1,2")
            assert fast["good"] == stats.good(merged, (1,), (1, 2), ()) and fast["stats"] == answer["stats"], \
                "filters choose the windows; the header covers every shot, as the controller's"
            for bad in ("window=20&epoch=1", "window=10", "window=10&epoch=1&result=early", "window=10&epoch=x"):
                await get(f"/stats?{bad}", 400)
            fake.add_shot()  # A new shot the copy has not seen: the header waits for it.
            answer = await get(f"/stats?window=10&active=2&epoch={fake.epochs['shots']}")
            assert answer["epoch"] == fake.epochs["shots"] and answer["good"] == stats.good(merged, (), (), ()) + 1
            archive.FRESH_S = 0.4
            fake.held = []
            fake.add_shot()
            await get(f"/stats?window=10&active=2&epoch={fake.epochs['shots']}", 503)
            assert said("the Stats header over the whole history is unavailable") == 1
            await fake.release(companion)
            await settled(companion)
            await get(f"/stats?window=10&active=2&epoch={fake.epochs['shots']}")
            view = companion.screens.mux.views["stats"]
            view.epoch = fake.epochs["shots"]
            fake.add_shot()  # A screen showing Stats sees the new shot in the live frames.
            view._standing({"type": "stats", "request": 0, "seq": 1, "rowBase": 0, "snapshot": False,
                            "epoch": fake.epochs["shots"], "rows": [], "more": False})
            await settled(companion)
            assert (await companion.archive.store.sync_state(DEVICE, "shots"))[1] == fake.epochs["shots"]

            # --- One history (S9, S12): the controller's filters and orders, ties included --
            await parity(companion, get)

            # --- The log asks only outside a hold too; an older controller as before --
            link_.close()
            fake.held = []  # A shot is on when the link opens: no ping is answered.
            seen = len(fake.requests)
            await link_.open(log=True)
            await asyncio.sleep(0.3)
            assert not [f for f in fake.requests[seen:] if f["t"] == "logsub"], "logsub waits for a clear frame"
            await fake.release(companion)
            await asyncio.sleep(0.2)
            assert [f["t"] for f in fake.requests[seen:]].count("logsub") == 1
            await companion._on_frame({"t": "hold", "on": False, "sync": True})
            fake.held = []
            await companion._log_subscribe(resync=True)  # A write failed: ask again from the stored cursor.
            await asyncio.sleep(0.2)
            assert [f["t"] for f in fake.requests[seen:]].count("logsub") == 1, "the resync waits for the hold"
            await fake.release(companion)
            await asyncio.sleep(0.2)
            assert [f["t"] for f in fake.requests[seen:]].count("logsub") == 2
            link_.close()
            fake.held = []  # An older controller never answers a ping: its logsub goes as it always did.
            seen = len(fake.requests)
            await link_.open(cfg={"t": "cfg", "ui": True, "log": True})
            await asyncio.sleep(0.1)
            assert [f["t"] for f in fake.requests[seen:]] == ["logsub"], fake.requests[seen:]
            fake.held = None

            # --- Forget erases it all --------------------------------------------------------
            link_.close()
            await companion.erase("forgotten for the test")
            assert not await sql(companion, "select * from archive_records") and \
                not await sql(companion, "select * from archive_sync")

            # --- The codec takes the controller's larger record frames only ---------------
            key = bytes(32)
            controller, mine = link.FrameCodec(key, send=b"f", receive=b"c"), link.FrameCodec(key)
            big = {"t": "rec", "f": {"rows": "x" * 20000}}
            assert mine.decode(controller.encode(big))["f"]["rows"] == big["f"]["rows"]
            try:
                mine.encode({"t": "rx", "pad": "x" * 5000})
                raise AssertionError("a companion frame over 4096 bytes was encoded")
            except ValueError:
                pass

            await pages.close()
            await companion.logs.close()
    print("Companion archive: backfill, catch-up, ratings, deletions, rotation, holes, generations, "
          "deletion scopes, keep setting, access, switch, bulk deletes, export and erase OK")


asyncio.run(main())
