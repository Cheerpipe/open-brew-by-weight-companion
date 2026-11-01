#!/usr/bin/env python3
"""The archive's sync driven by the firmware's own link frames.

`tests/fixtures/companion-records-v1.vectors.json` is the firmware's file
(docs/schemas/ in the firmware repository, written by its host test from the
real serializers): each case is a request the companion sends and the exact
frame text the controller answers with. Its checksum pins the copy. The only
thing put into the frames is this companion's own fetch request id. Its
browser_ cases (a browser session's index and offline-copy windows) pin the
page the companion builds from the archive it synced here. Offline, inside
the image (see the README).
"""

import asyncio
import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import aiohttp  # noqa: E402

from companion import index_mirror, mux, service  # noqa: E402
from companion.service import Companion  # noqa: E402

VECTORS = ROOT / "tests/fixtures/companion-records-v1.vectors.json"
SHA256 = "2673dc53c2275df5853d02c77f55b721e9ac8d226b0ffbc22b9d9f1336649437"
DEVICE = "AA:BB:CC:DD:EE:FF"


class Upstream:
    """No La Marzocco here."""

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


class Controller:
    """Answers each request with its case's frames, parsed from their exact text, `q` left out. Until
    the store `moved`, an index request's `d` changes nothing (a store at the epoch asked is unchanged
    either way); afterwards only the moved store's cases answer."""

    def __init__(self, cases):
        self.cases, self.used, self.requests, self.moved = cases, set(), [], False

    def frames(self, name):
        return [{key: value for key, value in json.loads(text).items() if key != "q"}
                for text in self.cases[name]["frames"]]

    async def serve(self, companion, outbox):
        while True:
            sent = await outbox.get()
            if sent["t"] not in ("rx", "rf", "rt"):
                continue
            self.requests.append(sent)
            name = next(name for name, case in self.cases.items() if case["request"] and
                        ("moved" in name or name.endswith("_delta")) == self.moved and
                        {k: v for k, v in case["request"].items() if k != "r"} ==
                        {k: v for k, v in sent.items() if k != "r" and (self.moved or k != "d")})
            self.used.add(name)
            for frame in self.frames(name):
                if sent["t"] == "rf":
                    frame["f"]["request"] = sent["r"]
                await companion._on_frame(frame)


async def settled(companion):
    for _ in range(300):
        await asyncio.sleep(0.02)
        if not companion.archive.wake.is_set() and companion.archive.syncing is None and \
                not companion.archive.wanted:
            await asyncio.sleep(0.05)
            if companion.archive.syncing is None and not companion.archive.wake.is_set():
                return
    raise AssertionError("the archive sync did not settle")


async def sql(companion, statement, *args):
    return await service.offload(lambda: [tuple(row) for row in companion.logs.connection.execute(statement, args)])


async def served(companion, cases, name):
    """A screen's offline-copy window answered by the mux from the archive, as parsed frames. The screen holds
    a standing Stats page (the firmware's browser frames) and the browser index."""
    the_mux, firmware = companion.screens.mux, [json.loads(text) for text in cases[name]["frames"]]
    screen = mux.Screen(the_mux, None, "test")
    screen.bound = True
    the_mux.screens.add(screen)
    view = the_mux.views["stats"]
    the_mux._op(screen, {"op": "stats", "on": True, "request": 1, "offset": 0, "limit": 10, "sort": "date",
                         "dir": "desc"})
    page = [json.loads(text) for text in cases["browser_fetch_shots"]["frames"]]
    for number, frame in enumerate(page):
        the_mux.on_frame({**frame, "request": view.request, "snapshot": not number}, None)
    the_mux._op(screen, {"op": "records", "shots": 0})
    index = cases["browser_index_shots"]["frames"][0]
    the_mux.on_frame(json.loads(index), index)
    screen.queue.clear()
    changes = companion.logs.connection.total_changes
    the_mux._op(screen, cases[name]["request"])
    for _ in range(100):
        if screen.queue and json.loads(screen.queue[-1])["more"] is False:
            break
        await asyncio.sleep(0.01)
    the_mux.screens.discard(screen)
    assert companion.logs.connection.total_changes == changes, "serving writes nothing"
    return [json.loads(text) for text in screen.queue], firmware


async def main():
    assert hashlib.sha256(VECTORS.read_bytes()).hexdigest() == SHA256, \
        "the vectors differ from the firmware's: copy its file again"
    vectors = json.loads(VECTORS.read_text())
    assert vectors["version"] == 1
    cases = {case["name"]: case for case in vectors["cases"]}
    fetch = [json.loads(text)["f"] for text in cases["fetch_shots"]["frames"]]
    assert "cols" in fetch[0] and "cols" not in fetch[1] and fetch[1]["rowBase"] > 0, "a page over two frames"
    controller = Controller(cases)
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-vectors-") as temporary:
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", Path(temporary), http, Upstream)
            await companion.open_log()
            # Shots 3 to 12 already hold their trace, so this pass asks the two the vectors answer.
            await service.offload(lambda: companion.logs.connection.executemany(
                "insert into archive_traces values (?, 1, ?, 43, ?, null)",
                [(DEVICE, rid, rid * 1000 + 600000) for rid in range(3, 13)]))
            companion.outbox = outbox = asyncio.Queue()
            serving = asyncio.create_task(controller.serve(companion, outbox))
            await companion._on_frame({"t": "dev", "name": "Kitchen", "id": DEVICE})
            await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": True})
            await asyncio.sleep(0.1)
            assert not controller.requests, "nothing leaves before a frame shows no hold"
            ping = controller.frames("ping_answer")[0]
            assert ping == {"t": "hold", "on": False, "sync": False}
            await companion._on_frame(ping)  # The controller's answer to the companion's ping.
            await settled(companion)
            assert controller.used == {"index_history", "fetch_history", "index_shots", "fetch_shots",
                                       "trace_none", "trace_ok"}, controller.used
            assert not any("d" in sent for sent in controller.requests), "no delta before a sum in this session"

            shots = await sql(companion, "select generation, id, ident, bad, kind, body from archive_records "
                                         "where store = 'shots' order by id")
            assert [row[1] for row in shots] == list(range(1, 13)) and {row[0] for row in shots} == {1}
            assert all(row[2] == f"43:{row[1] * 1000 + 600000}" for row in shots), "bootId:endedAtMs"
            assert [row[1] for row in shots if row[3]] == [12] and shots[-1][4] == "short"
            body = json.loads(shots[-1][5])
            assert body["presetName"] == 'Decaf "Night"' and body["durationS"] == 8.0 and "wD" in body
            assert type(body["durationS"]) is float, "numbers keep their form: parsed from the frames' text"
            history = await sql(companion, "select id, kind from archive_records where store = 'history' order by id")
            assert [row[0] for row in history] == [1, 2, 3, 4, 5] and history[3][1] == "rinse"
            for store, epoch, counters in (("shots", 7001, [2400, 13]), ("history", 7002, [1300, 6])):
                state = await companion.archive.store.sync_state(DEVICE, store)
                assert state[1] == epoch and state[4] == counters and state[2] == 1, state
            traces = dict(await sql(companion, "select id, data from archive_traces where id in (1, 2)"))
            ok = json.loads(cases["trace_ok"]["frames"][0])
            assert traces[1] == base64.b64decode(ok["d"]) and len(traces[1]) == 5000 and traces[2] is None

            # The offline copy's windows from this archive: the firmware's own browser page for the same window,
            # apart from the companion's seq and tag and the Stats header, which a fetch's reader skips (Home's
            # hero fetch, which has none, the same window shape from a screen also on Stats).
            for name in ("browser_fetch_shots", "browser_fetch_window", "browser_fetch_hero"):
                page, firmware = await served(companion, cases, name)
                assert [frame["rowBase"] for frame in page] == [frame["rowBase"] for frame in firmware], name
                for ours, theirs in zip(page, firmware):
                    # Compared as text: the same JSON types too (a bool is no 1, an 8.0 no 8).
                    assert json.dumps({k: v for k, v in ours.items() if k not in ("seq", "tag")}) == json.dumps(
                        {k: v for k, v in theirs.items() if k not in ("seq", "tag", "stats")}), name
                    assert ours["seq"] == page[0]["seq"] > 1 and type(ours.get("tag", 0)) is int
                assert len(firmware) > 1 or name != "browser_fetch_shots", "a page over two frames"
                assert ("stats" in firmware[0]) == (name != "browser_fetch_hero")

            # The notice names the epochs the archive holds: nothing is asked.
            asked = len(controller.requests)
            await companion._on_frame(controller.frames("notice")[0])
            await settled(companion)
            assert len(controller.requests) == asked
            # A screen's live frames name a newer epoch: the index answers that nothing changed.
            companion.archive.refresh("shots", 7099)
            await settled(companion)
            assert "index_shots_unchanged" in controller.used and len(controller.requests) == asked + 1
            assert (await companion.archive.store.sync_state(DEVICE, "shots"))[1] == 7001

            # A busy controller: the trace is asked once and again only after the wait.
            await service.offload(lambda: companion.logs.connection.execute(
                "delete from archive_traces where id = 3"))
            await companion._on_frame(controller.frames("notice")[0])
            await settled(companion)
            assert "trace_busy" in controller.used and companion.archive.busy_until > 0
            assert not await sql(companion, "select 1 from archive_traces where id = 3")
            assert sum(sent["t"] == "rt" and sent["id"] == 3 for sent in controller.requests) == 1

            # The store moved (shot 13 new, 9 rated again, 6 deleted): the index arrives as a delta
            # against the one this session received, and the archive follows it like a whole index.
            await service.offload(lambda: companion.logs.connection.execute(
                "insert into archive_traces values (?, 1, 13, 43, 613000, null)", (DEVICE,)))
            controller.moved = True
            companion.archive.refresh("shots", 7003)
            await settled(companion)
            assert {"index_shots_delta", "fetch_shot_9_moved", "fetch_shot_13_moved"} <= controller.used
            assert controller.requests[-3]["d"] == 1
            shots = dict(await sql(companion, "select id, json_extract(body, '$.rating') from archive_records "
                                              "where store = 'shots'"))
            assert sorted(shots) == [rid for rid in range(1, 14) if rid != 6] and shots[9] == 5, shots
            state = await companion.archive.store.sync_state(DEVICE, "shots")
            assert state[1] == 7003 and state[4] == [2400, 14], state
            # The same delta against another copy, or with another sum, rebuilds nothing.
            full, delta = (controller.frames(name)[0]["f"] for name in ("index_shots", "index_shots_delta"))
            mirror = index_mirror.IndexMirror("test index")
            assert mirror.apply(full)["rows"] == full["rows"] and mirror.supported
            assert mirror.apply({**delta, "sum": delta["sum"] ^ 1}) is None and mirror.pairs is None
            mirror.apply(full)
            assert mirror.apply({**delta, "base": 7000}) is None and not mirror.delta(7001)
            mirror.apply(full)
            assert index_mirror.checksum(mirror.apply(delta)["rows"]) == delta["sum"] and mirror.epoch == 7003
            serving.cancel()
            companion.archive.stop()
            await companion.logs.close()
    print(f"Companion archive from the firmware's link frames: {len(cases)} cases OK")


asyncio.run(main())
