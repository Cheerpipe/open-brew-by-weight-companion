#!/usr/bin/env python3
"""The archive's sync driven by the firmware's own link frames, and the replica's pages against the firmware's.

`tests/fixtures/companion-records-v1.vectors.json` is the firmware's file
(docs/schemas/ in the firmware repository, written by its host test from the
real serializers): each case is a request the companion sends and the exact
frame text the controller answers with. Its checksum pins the copy. The only
thing put into the frames is this companion's own fetch request id. Its
`page_*` cases are the controller's own Stats and History pages for a
screen's op over the same records: the mux serves each from the replica
frame for frame, every member but its own `tag`, `seq` and `request`.
Offline, inside the image (see the README).
"""

import asyncio
import base64
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from unittest import mock

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import aiohttp  # noqa: E402
from aiohttp.test_utils import make_mocked_request  # noqa: E402

from companion import archive, index_mirror, mux, service  # noqa: E402
from companion.service import Companion  # noqa: E402

VECTORS = ROOT / "tests/fixtures/companion-records-v1.vectors.json"
SHA256 = "32f382137e9148b27597c8ec212ea4e9dd37494e8d4ec924508415b0dcb7d105"
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
        self.mute = False  # A controller that stopped answering.

    def frames(self, name):
        return [
            {key: value for key, value in json.loads(text).items() if key != "q"}
            for text in self.cases[name]["frames"]
        ]

    async def serve(self, companion, outbox):
        while True:
            sent = await outbox.get()
            if sent["t"] not in ("rx", "rf", "rt"):
                continue
            self.requests.append(sent)
            if self.mute:
                continue
            name = next(
                (
                    name
                    for name, case in self.cases.items()
                    if case["request"]
                    and ("moved" in name or name.endswith("_delta")) == self.moved
                    and {k: v for k, v in case["request"].items() if k != "r"}
                    == {k: v for k, v in sent.items() if k != "r" and (self.moved or k != "d")}
                ),
                None,
            )
            if (
                name is None and sent["t"] == "rx" and sent["ep"]
            ):  # A store at the epoch asked: unchanged.
                index = self.frames(f"index_{sent['s']}")[0]
                index["f"] = {
                    **{
                        key: value
                        for key, value in index["f"].items()
                        if key not in ("rows", "sum")
                    },
                    "epoch": sent["ep"],
                }
                await companion._on_frame(index)
                continue
            self.used.add(name)
            for frame in self.frames(name):
                if sent["t"] == "rf":
                    frame["f"]["request"] = sent["r"]
                await companion._on_frame(frame)


async def settled(companion):
    for _ in range(300):
        await asyncio.sleep(0.02)
        if (
            not companion.archive.wake.is_set()
            and companion.archive.syncing is None
            and not companion.archive.wanted
        ):
            await asyncio.sleep(0.05)
            if companion.archive.syncing is None and not companion.archive.wake.is_set():
                return
    raise AssertionError("the archive sync did not settle")


IDENTITIES = re.compile(r'"(tag|seq|request)":\d+')


async def served(companion, case, wait=0.2):
    """The replica's frames for a page case's op, on a screen of the companion's mux."""
    view_mux = companion.screens.mux
    view_mux.home.apply(
        {
            "snapshot": True,
            "boot": 43,
            "changes": {"presets": {"activeId": case["request"].get("active", 0)}},
        }
    )
    screen = mux.Screen(view_mux, None, "192.168.1.9")
    op = {key: value for key, value in case["request"].items() if key not in ("active", "view")}
    if op.get("fetch") and case["request"].get("view"):
        view_mux._op(
            screen,
            {
                **{key: op[key] for key in ("op", "on", "sort", "dir", "filter") if key in op},
                "offset": 0,
                "limit": 10,
                **({"window": op.pop("window")} if "window" in op else {}),
            },
        )
        await asyncio.sleep(0.2)
        screen.queue.clear()
    view_mux._op(screen, op)
    await asyncio.sleep(wait)
    return list(screen.queue)


async def pages_match(companion, cases):
    """Every page case, frame for frame; the replica never asked the controller (no upstream op)."""
    sent = []
    companion.screens.mux.up = lambda op: sent.append(op) or True
    served_before = companion.archive.counters["served"]
    names = [name for name in cases if name.startswith("page_")]
    for name in names:
        frames = await served(companion, cases[name])
        expected = cases[name]["frames"]
        assert len(frames) == len(expected), (name, len(frames), len(expected))
        for mine, theirs in zip(frames, expected):
            assert IDENTITIES.sub(r'"\1":0', mine) == IDENTITIES.sub(r'"\1":0', theirs), (
                name,
                mine[:300],
                theirs[:300],
            )
            assert set(json.loads(mine)) == set(json.loads(theirs)), name
    assert not sent, f"the replica asked the controller: {sent}"
    assert companion.archive.counters["served"] >= served_before + len(names)
    return len(names)


async def waits_for_home(companion, cases):
    """The first screen after an idle close binds before the session's Home snapshot: its page waits for
    the controller's boot and then comes from the copy as a snapshot, nothing upstream; a new active
    preset in Home sends the Stats page again, as the controller does."""
    view_mux, sent = companion.screens.mux, []
    view_mux.up = lambda op: sent.append(op) or True
    fallbacks = companion.archive.counters["fallbacks"]
    view_mux.home.clear()
    screen = mux.Screen(view_mux, None, "192.168.1.9")
    screen.bound = True
    view_mux.screens.add(screen)
    same = lambda frames: [IDENTITIES.sub(r'"\1":0', text) for text in frames]  # noqa: E731
    view_mux._op(
        screen,
        {key: value for key, value in cases["page_stats"]["request"].items() if key != "active"},
    )
    await asyncio.sleep(0.2)
    assert not screen.queue and not sent, "no page before the controller's boot is known"
    view_mux._on_home(
        {"snapshot": True, "boot": 43, "changes": {"presets": {"activeId": 1}}}, "home"
    )
    await asyncio.sleep(0.2)
    assert same(list(screen.queue)[1:]) == same(cases["page_stats"]["frames"])
    screen.queue.clear()
    view_mux._on_home({"changes": {"presets.activeId": 2}}, "delta")
    await asyncio.sleep(0.2)
    assert same(list(screen.queue)[1:]) == same(
        text.replace('"snapshot":true', '"snapshot":false')
        for text in cases["page_stats_active_2"]["frames"]
    )
    assert not sent and companion.archive.counters["fallbacks"] == fallbacks
    view_mux.screens.discard(screen)


async def replica_rules(companion, cases, serving):
    """Hold, catch-up, fallback, switch, relayed changes and traces, on the replica the vectors filled."""
    view_mux, copy = companion.screens.mux, companion.archive
    sent = []
    view_mux.up = lambda op: sent.append(op) or True
    page = cases["page_stats"]

    # A shot: the copy serves as it is, even when not current; nothing goes upstream.
    await companion._on_frame({"t": "hold", "on": False, "sync": True})
    copy.invalidate("shots")
    assert copy.state("shots") == "catchingUp" and companion.sync_blocked()
    assert len(await served(companion, page)) == len(page["frames"]) and not sent, sent
    asked = len(serving.requests)
    copy.invalidate(
        "shots", done=True
    )  # A rating forwarded mid-shot: its catch-up waits for the hold.
    await asyncio.sleep(0.2)
    assert len(serving.requests) == asked and copy.state("shots") == "catchingUp"
    await companion._on_frame({"t": "hold", "on": False, "sync": False})
    await settled(companion)
    assert copy.state("shots") == "current" and serving.requests[asked]["t"] == "rx", (
        "caught up at the hold's end"
    )

    # Not current and the controller does not answer: the page comes whole from the controller.
    archive.CATCH_UP_S, archive.REQUEST_S = 0.3, 0.5  # The unanswered request is asked again soon.
    serving.mute = True
    copy.invalidate("shots", done=True)
    fallbacks = copy.counters["fallbacks"]
    assert await served(companion, page, 0.6) == [] and copy.counters["fallbacks"] == fallbacks + 1
    assert sent and sent[-1]["op"] == "stats" and "fetch" not in sent[-1], (
        "the whole page, upstream"
    )
    serving.mute = False
    copy.invalidate("shots", done=True)
    await settled(companion)
    assert copy.state("shots") == "current"

    # A rating relayed from a screen: not current while it leaves, caught up once answered.
    companion.controller = (
        "Kitchen",
        ("127.0.0.1", 9),
    )  # Nobody listens: the rating fails at once.
    asked = len(serving.requests)
    reply = await companion.screens.api(
        make_mocked_request(
            "POST", "/api/v1/stats/rate", headers={}, transport=mock.Mock(is_closing=lambda: False)
        )
    )
    assert reply.status in (502, 503), reply.status
    await settled(companion)
    assert [sent["t"] for sent in serving.requests[asked:]] == ["rx"] and copy.state(
        "shots"
    ) == "current"

    # A shot's trace the copy holds answers on the relay's own route, without the controller.
    session = {"X-WebUI-Session": "s" * 16}
    companion.log_grants[
        service.hashlib.sha256(session["X-WebUI-Session"].encode()).hexdigest()
    ] = service.time.time()
    reply = await companion.screens.api(
        make_mocked_request(
            "GET",
            "/api/v1/diagnostic/shot-trace?id=1&boot=43&end=601000",
            headers=session,
            transport=mock.Mock(is_closing=lambda: False),
        )
    )
    ok = json.loads(cases["trace_ok"]["frames"][0])
    assert reply.status == 200 and reply.body == base64.b64decode(ok["d"])

    facts = await copy.facts()
    assert (
        facts["replica"] == {"history": "current", "shots": "current"}
        and facts["served"] > 0
        and facts["fallbacks"] > 0
        and facts["catchUpFetches"] > 0
    )


async def switch_off(companion, serving):
    """The archive switch off: today's path, every page from the controller's own window. Turned on
    again, the stored copy is current after one unchanged index per store, nothing fetched (as after a
    companion restart)."""
    view_mux, copy = companion.screens.mux, companion.archive
    view_mux.up = lambda op: True
    await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": False})
    assert copy.state("shots") == "off"
    served_before = copy.counters["served"]
    await served(
        companion,
        {
            "request": {
                "op": "stats",
                "on": True,
                "request": 1,
                "offset": 0,
                "limit": 10,
                "sort": "date",
                "dir": "desc",
            }
        },
    )
    assert (
        copy.counters["served"] == served_before and view_mux.views["stats"].standing is not None
    ), "the controller's standing window serves it"
    asked = len(serving.requests)
    await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": True})
    assert copy.state("shots") == "catchingUp"
    await settled(companion)
    assert copy.state("shots") == copy.state("history") == "current", (
        "the next session catches up again"
    )
    assert sorted(sent["t"] for sent in serving.requests[asked:]) == ["rx", "rx"], serving.requests[
        asked:
    ]


async def sql(companion, statement, *args):
    return await service.offload(
        lambda: [tuple(row) for row in companion.logs.connection.execute(statement, args)]
    )


async def main():
    assert hashlib.sha256(VECTORS.read_bytes()).hexdigest() == SHA256, (
        "the vectors differ from the firmware's: copy its file again"
    )
    vectors = json.loads(VECTORS.read_text())
    assert vectors["version"] == 1
    cases = {case["name"]: case for case in vectors["cases"]}
    fetch = [json.loads(text)["f"] for text in cases["fetch_shots"]["frames"]]
    assert "cols" in fetch[0] and "cols" not in fetch[1] and fetch[1]["rowBase"] > 0, (
        "a page over two frames"
    )
    controller = Controller(cases)
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-vectors-") as temporary:
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", Path(temporary), http, Upstream)
            await companion.open_log()
            # Shots 3 to 12 already hold their trace, so this pass asks the two the vectors answer.
            await service.offload(
                lambda: companion.logs.connection.executemany(
                    "insert into archive_traces values (?, 1, ?, 43, ?, null)",
                    [(DEVICE, rid, rid * 1000 + 600000) for rid in range(3, 13)],
                )
            )
            companion.outbox = outbox = asyncio.Queue()
            serving = asyncio.create_task(controller.serve(companion, outbox))
            await companion._on_frame({"t": "dev", "name": "Kitchen", "id": DEVICE})
            await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": True})
            await asyncio.sleep(0.1)
            assert not controller.requests, "nothing leaves before a frame shows no hold"
            ping = controller.frames("ping_answer")[0]
            assert ping == {"t": "hold", "on": False, "sync": False, "sh": 7001, "hi": 7002}
            await companion._on_frame(ping)  # The controller's answer to the companion's ping.
            await settled(companion)
            assert controller.used == {
                "index_history",
                "fetch_history",
                "index_shots",
                "fetch_shots",
                "trace_none",
                "trace_ok",
            }, controller.used
            assert not any("d" in sent for sent in controller.requests), (
                "no delta before a sum in this session"
            )

            shots = await sql(
                companion,
                "select generation, id, ident, bad, kind, body from archive_records "
                "where store = 'shots' order by id",
            )
            assert [row[1] for row in shots] == list(range(1, 13)) and {
                row[0] for row in shots
            } == {1}
            assert all(row[2] == f"43:{row[1] * 1000 + 600000}" for row in shots), (
                "bootId:endedAtMs"
            )
            assert [row[1] for row in shots if row[3]] == [12] and shots[-1][4] == "short"
            body = json.loads(shots[-1][5])
            assert (
                body["presetName"] == 'Decaf "Night"' and body["durationS"] == 8.0 and "wD" in body
            )
            assert type(body["durationS"]) is float, (
                "numbers keep their form: parsed from the frames' text"
            )
            history = await sql(
                companion,
                "select id, kind from archive_records where store = 'history' order by id",
            )
            assert [row[0] for row in history] == [1, 2, 3, 4, 5] and history[3][1] == "rinse"
            # The index names the Clear count beside the counters (D8): the archive keeps all three.
            for store, epoch, counters in (
                ("shots", 7001, [2400, 13, 1]),
                ("history", 7002, [1300, 6, 0]),
            ):
                state = await companion.archive.store.sync_state(DEVICE, store)
                assert state[1] == epoch and state[4] == counters and state[2] == 1, state
            traces = dict(
                await sql(companion, "select id, data from archive_traces where id in (1, 2)")
            )
            ok = json.loads(cases["trace_ok"]["frames"][0])
            assert (
                traces[1] == base64.b64decode(ok["d"])
                and len(traces[1]) == 5000
                and traces[2] is None
            )

            assert (
                companion.archive.state("shots") == companion.archive.state("history") == "current"
            )
            pages = await pages_match(companion, cases)
            await waits_for_home(companion, cases)
            await replica_rules(companion, cases, controller)

            # The notice names the epochs the archive holds: nothing is asked.
            asked = len(controller.requests)
            await companion._on_frame(controller.frames("notice")[0])
            await settled(companion)
            assert len(controller.requests) == asked
            # A screen's live frames name a newer epoch: the index answers that nothing changed.
            companion.archive.refresh("shots", 7099)
            await settled(companion)
            assert (
                "index_shots_unchanged" in controller.used and len(controller.requests) == asked + 1
            )
            assert (await companion.archive.store.sync_state(DEVICE, "shots"))[1] == 7001

            # A busy controller: the trace is asked once and again only after the wait.
            await service.offload(
                lambda: companion.logs.connection.execute("delete from archive_traces where id = 3")
            )
            await companion._on_frame(controller.frames("notice")[0])
            await settled(companion)
            assert "trace_busy" in controller.used and companion.archive.busy_until > 0
            assert not await sql(companion, "select 1 from archive_traces where id = 3")
            assert sum(sent["t"] == "rt" and sent["id"] == 3 for sent in controller.requests) == 1

            # The store moved (shot 13 new, 9 rated again, 6 deleted): the index arrives as a delta
            # against the one this session received, and the archive follows it like a whole index.
            await service.offload(
                lambda: companion.logs.connection.execute(
                    "insert into archive_traces values (?, 1, 13, 43, 613000, null)", (DEVICE,)
                )
            )
            controller.moved = True
            companion.archive.refresh("shots", 7003)
            await settled(companion)
            assert {
                "index_shots_delta",
                "fetch_shot_9_moved",
                "fetch_shot_13_moved",
            } <= controller.used
            assert controller.requests[-3]["d"] == 1
            shots = dict(
                await sql(
                    companion,
                    "select id, json_extract(body, '$.rating') from archive_records "
                    "where store = 'shots'",
                )
            )
            assert sorted(shots) == [rid for rid in range(1, 14) if rid != 6] and shots[9] == 5, (
                shots
            )
            state = await companion.archive.store.sync_state(DEVICE, "shots")
            assert state[1] == 7003 and state[4] == [2400, 14, 1], state
            # The same delta against another copy, or with another sum, rebuilds nothing.
            full, delta = (
                controller.frames(name)[0]["f"] for name in ("index_shots", "index_shots_delta")
            )
            mirror = index_mirror.IndexMirror("test index")
            assert mirror.apply(full)["rows"] == full["rows"] and mirror.answered
            assert mirror.apply({**delta, "sum": delta["sum"] ^ 1}) is None and mirror.pairs is None
            mirror.apply(full)
            assert mirror.apply({**delta, "base": 7000}) is None and not mirror.delta(7001)
            mirror.apply(full)
            assert (
                index_mirror.checksum(mirror.apply(delta)["rows"]) == delta["sum"]
                and mirror.epoch == 7003
            )
            await switch_off(companion, controller)
            serving.cancel()
            companion.archive.stop()
            await companion.relay.close()
            await companion.logs.close()
    print(
        f"Companion archive from the firmware's link frames: {len(cases)} cases OK, {pages} replica pages "
        "frame for frame; hold, catch-up, fallback, relayed changes and traces, switch OK"
    )


asyncio.run(main())
