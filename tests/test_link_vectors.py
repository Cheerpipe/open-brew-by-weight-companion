"""The archive's sync driven by the firmware's own link frames, and the replica's pages against the
firmware's.

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
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict, cast
from unittest import mock

import aiohttp
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from companion import archive, index_mirror, mux
from companion.service import Companion
from companion.store import offload

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    import pytest

    from companion.service import Frame
    from companion.store import Store

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests/fixtures/companion-records-v1.vectors.json"
SHA256 = "32f382137e9148b27597c8ec212ea4e9dd37494e8d4ec924508415b0dcb7d105"
DEVICE = "AA:BB:CC:DD:EE:FF"


class Case(TypedDict):
    name: str
    request: dict[str, object] | None
    frames: list[str]


class Vectors(TypedDict):
    version: int
    cases: list[Case]


class Upstream:
    """No La Marzocco here."""

    sub = up = refused = policy = False
    ep = tok = 0

    def __init__(self, store: Store, events: Companion) -> None:
        pass

    def configure(self, *_: object) -> None:
        pass

    def stop(self) -> None:
        pass

    def erase(self) -> None:
        pass

    def signed_in_for(self, _: object) -> bool:
        raise AssertionError("no La Marzocco here")

    def rejected_for(self, _: object) -> bool:
        raise AssertionError("no La Marzocco here")

    async def read(self) -> tuple[int, dict[str, object] | None, int]:
        raise AssertionError("no La Marzocco here")

    async def command(self, *_: object) -> int:
        raise AssertionError("no La Marzocco here")


class Controller:
    """Answers each request with its case's frames, parsed from their exact text, `q` left out.
    Until the store `moved`, an index request's `d` changes nothing (a store at the epoch asked is
    unchanged either way); afterwards only the moved store's cases answer."""

    def __init__(self, cases: dict[str, Case]) -> None:
        self.cases, self.moved = cases, False
        self.used: set[str | None] = set()
        self.requests: list[Frame] = []
        self.mute = False  # A controller that stopped answering.

    def frames(self, name: str) -> list[dict[str, object]]:
        return [
            {key: value for key, value in json.loads(text).items() if key != "q"}
            for text in self.cases[name]["frames"]
        ]

    async def serve(self, companion: Companion, outbox: asyncio.Queue[Frame]) -> None:
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
                inner = index["f"]
                assert isinstance(inner, dict)
                index["f"] = {
                    **{key: value for key, value in inner.items() if key not in ("rows", "sum")},
                    "epoch": sent["ep"],
                }
                await companion._on_frame(index)
                continue
            self.used.add(name)
            assert name is not None, sent
            for frame in self.frames(name):
                if sent["t"] == "rf":
                    inner = frame["f"]
                    assert isinstance(inner, dict)
                    inner["request"] = sent["r"]
                await companion._on_frame(frame)


def sends_to(sent: list[Mapping[str, object]]) -> Callable[[Mapping[str, object]], bool]:
    """The mux's upstream op sender, keeping each op instead."""

    def up(op: Mapping[str, object]) -> bool:
        sent.append(op)
        return True

    return up


def quiet(copy: archive.Archive) -> bool:
    """No pass runs and none is due."""
    return copy.syncing is None and not copy.wake.is_set()


async def settled(companion: Companion) -> None:
    for _ in range(300):
        await asyncio.sleep(0.02)
        if quiet(companion.archive) and not companion.archive.wanted:
            await asyncio.sleep(0.05)
            if quiet(companion.archive):
                return
    raise AssertionError("the archive sync did not settle")


IDENTITIES = re.compile(r'"(tag|seq|request)":\d+')


async def served(
    companion: Companion, request: dict[str, object] | None, wait: float = 0.2
) -> list[str]:
    """The replica's frames for a page case's op (its `request`), on a screen of the companion's
    mux."""
    assert request is not None
    view_mux = companion.screens.mux
    view_mux.home.apply(
        {
            "snapshot": True,
            "boot": 43,
            "changes": {"presets": {"activeId": request.get("active", 0)}},
        }
    )
    screen = mux.Screen(view_mux, web.WebSocketResponse(), "192.168.1.9")
    op = {key: value for key, value in request.items() if key not in ("active", "view")}
    if op.get("fetch") and request.get("view"):
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


async def pages_match(
    companion: Companion, cases: dict[str, Case], monkeypatch: pytest.MonkeyPatch
) -> int:
    """Every page case, frame for frame; the replica never asked the controller (no upstream op)."""
    sent: list[Mapping[str, object]] = []
    monkeypatch.setattr(companion.screens.mux, "up", sends_to(sent))
    served_before = companion.archive.counters["served"]
    names = [name for name in cases if name.startswith("page_")]
    for name in names:
        frames = await served(companion, cases[name]["request"])
        expected = cases[name]["frames"]
        assert len(frames) == len(expected), (name, len(frames), len(expected))
        for mine, theirs in zip(frames, expected, strict=True):
            assert IDENTITIES.sub(r'"\1":0', mine) == IDENTITIES.sub(r'"\1":0', theirs), (
                name,
                mine[:300],
                theirs[:300],
            )
            assert set(json.loads(mine)) == set(json.loads(theirs)), name
    assert not sent, f"the replica asked the controller: {sent}"
    assert companion.archive.counters["served"] >= served_before + len(names)
    return len(names)


def same(frames: Iterable[str]) -> list[str]:
    return [IDENTITIES.sub(r'"\1":0', text) for text in frames]


async def waits_for_home(
    companion: Companion, cases: dict[str, Case], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first screen after an idle close binds before the session's Home snapshot: its page
    waits for the controller's boot and then comes from the copy as a snapshot, nothing upstream;
    a new active preset in Home sends the Stats page again, as the controller does."""
    view_mux = companion.screens.mux
    sent: list[Mapping[str, object]] = []
    monkeypatch.setattr(view_mux, "up", sends_to(sent))
    fallbacks = companion.archive.counters["fallbacks"]
    view_mux.home.clear()
    screen = mux.Screen(view_mux, web.WebSocketResponse(), "192.168.1.9")
    screen.bound = True
    view_mux.screens.add(screen)
    request = cases["page_stats"]["request"]
    assert request is not None
    view_mux._op(screen, {key: value for key, value in request.items() if key != "active"})
    await asyncio.sleep(0.2)
    assert not screen.queue, "no page before the controller's boot is known"
    assert not sent, "no page before the controller's boot is known"
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
    assert not sent
    assert companion.archive.counters["fallbacks"] == fallbacks
    view_mux.screens.discard(screen)


async def replica_rules(
    companion: Companion,
    cases: dict[str, Case],
    serving: Controller,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hold, catch-up, fallback, switch, relayed changes and traces, on the replica the vectors
    filled."""
    view_mux, copy = companion.screens.mux, companion.archive
    sent: list[Mapping[str, object]] = []
    monkeypatch.setattr(view_mux, "up", sends_to(sent))
    page = cases["page_stats"]

    # A shot: the copy serves as it is, even when not current; nothing goes upstream.
    await companion._on_frame({"t": "hold", "on": False, "sync": True})
    copy.invalidate("shots")
    assert copy.state("shots") == "catchingUp"
    assert companion.sync_blocked()
    assert len(await served(companion, page["request"])) == len(page["frames"]), sent
    assert not sent, sent
    asked = len(serving.requests)
    copy.invalidate(
        "shots", done=True
    )  # A rating forwarded mid-shot: its catch-up waits for the hold.
    await asyncio.sleep(0.2)
    assert len(serving.requests) == asked
    assert copy.state("shots") == "catchingUp"
    await companion._on_frame({"t": "hold", "on": False, "sync": False})
    await settled(companion)
    assert copy.state("shots") == "current", "caught up at the hold's end"
    assert serving.requests[asked]["t"] == "rx", "caught up at the hold's end"

    # Not current and the controller does not answer: the page comes whole from the controller.
    # The unanswered request is asked again soon.
    monkeypatch.setattr(archive, "CATCH_UP_S", 0.3)
    monkeypatch.setattr(archive, "REQUEST_S", 0.5)
    serving.mute = True
    copy.invalidate("shots", done=True)
    fallbacks = copy.counters["fallbacks"]
    assert await served(companion, page["request"], 0.6) == []
    assert copy.counters["fallbacks"] == fallbacks + 1
    assert sent, "the whole page, upstream"
    assert sent[-1]["op"] == "stats", "the whole page, upstream"
    assert "fetch" not in sent[-1], "the whole page, upstream"
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
    assert [sent["t"] for sent in serving.requests[asked:]] == ["rx"]
    assert copy.state("shots") == "current"

    # A shot's trace the copy holds answers on the relay's own route, without the controller.
    session = {"X-WebUI-Session": "s" * 16}
    companion.log_grants[hashlib.sha256(session["X-WebUI-Session"].encode()).hexdigest()] = (
        time.time()
    )
    reply = await companion.screens.api(
        make_mocked_request(
            "GET",
            "/api/v1/diagnostic/shot-trace?id=1&boot=43&end=601000",
            headers=session,
            transport=mock.Mock(is_closing=lambda: False),
        )
    )
    ok = json.loads(cases["trace_ok"]["frames"][0])
    assert reply.status == 200
    assert isinstance(reply, web.Response)
    assert reply.body == base64.b64decode(ok["d"])

    facts = await copy.facts()
    assert facts["replica"] == {"history": "current", "shots": "current"}
    for counter in ("served", "fallbacks", "catchUpFetches"):
        value = facts[counter]
        assert isinstance(value, int), counter
        assert value > 0, counter


async def switch_off(
    companion: Companion, serving: Controller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The archive switch off: today's path, every page from the controller's own window. Turned
    on again, the stored copy is current after one unchanged index per store, nothing fetched (as
    after a companion restart)."""
    view_mux, copy = companion.screens.mux, companion.archive
    monkeypatch.setattr(view_mux, "up", lambda _op: True)
    await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": False})
    assert copy.state("shots") == "off"
    served_before = copy.counters["served"]
    await served(
        companion,
        {
            "op": "stats",
            "on": True,
            "request": 1,
            "offset": 0,
            "limit": 10,
            "sort": "date",
            "dir": "desc",
        },
    )
    assert copy.counters["served"] == served_before, "the controller's standing window serves it"
    assert view_mux.views["stats"].standing is not None, (
        "the controller's standing window serves it"
    )
    asked = len(serving.requests)
    await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": True})
    assert copy.state("shots") == "catchingUp"
    await settled(companion)
    assert copy.state("shots") == copy.state("history") == "current", (
        "the next session catches up again"
    )
    assert sorted(str(sent["t"]) for sent in serving.requests[asked:]) == ["rx", "rx"], (
        serving.requests[asked:]
    )


async def sql(companion: Companion, statement: str, *args: object) -> list[tuple[object, ...]]:
    return await offload(lambda: [tuple(row) for row in companion.logs.db.execute(statement, args)])


async def scenario(monkeypatch: pytest.MonkeyPatch) -> None:
    assert hashlib.sha256(VECTORS.read_bytes()).hexdigest() == SHA256, (
        "the vectors differ from the firmware's: copy its file again"
    )
    vectors = cast("Vectors", json.loads(VECTORS.read_text()))
    assert vectors["version"] == 1
    cases = {case["name"]: case for case in vectors["cases"]}
    fetch = [json.loads(text)["f"] for text in cases["fetch_shots"]["frames"]]
    assert "cols" in fetch[0], "a page over two frames"
    assert "cols" not in fetch[1], "a page over two frames"
    assert fetch[1]["rowBase"] > 0, "a page over two frames"
    controller = Controller(cases)
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-vectors-") as temporary:
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", Path(temporary), http, Upstream)
            await companion.open_log()
            # Shots 3 to 12 already hold their trace, so this pass asks the two the vectors answer.
            await offload(
                lambda: companion.logs.db.executemany(
                    "insert into archive_traces values (?, 1, ?, 43, ?, null)",
                    [(DEVICE, rid, rid * 1000 + 600000) for rid in range(3, 13)],
                )
            )
            outbox: asyncio.Queue[Frame] = asyncio.Queue()
            companion.outbox = outbox
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
            assert [row[1] for row in shots] == list(range(1, 13))
            assert {row[0] for row in shots} == {1}
            assert all(
                isinstance(row[1], int) and row[2] == f"43:{row[1] * 1000 + 600000}"
                for row in shots
            ), "bootId:endedAtMs"
            assert [row[1] for row in shots if row[3]] == [12]
            assert shots[-1][4] == "short"
            text = shots[-1][5]
            assert isinstance(text, str)
            body = json.loads(text)
            assert body["presetName"] == 'Decaf "Night"'
            assert body["durationS"] == 8.0
            assert "wD" in body
            assert type(body["durationS"]) is float, (
                "numbers keep their form: parsed from the frames' text"
            )
            history = await sql(
                companion,
                "select id, kind from archive_records where store = 'history' order by id",
            )
            assert [row[0] for row in history] == [1, 2, 3, 4, 5]
            assert history[3][1] == "rinse"
            # The index names the Clear count beside the counters (D8): the archive keeps all
            # three.
            for store, epoch, counters in (
                ("shots", 7001, [2400, 13, 1]),
                ("history", 7002, [1300, 6, 0]),
            ):
                state = await companion.archive.store.sync_state(DEVICE, store)
                assert state[1] == epoch, state
                assert state[4] == counters, state
                assert state[2] == 1, state
            traces = {
                row[0]: row[1]
                for row in await sql(
                    companion, "select id, data from archive_traces where id in (1, 2)"
                )
            }
            ok = json.loads(cases["trace_ok"]["frames"][0])
            assert traces[1] == base64.b64decode(ok["d"])
            assert isinstance(traces[1], bytes)
            assert len(traces[1]) == 5000
            assert traces[2] is None

            assert (
                companion.archive.state("shots") == companion.archive.state("history") == "current"
            )
            await pages_match(companion, cases, monkeypatch)
            await waits_for_home(companion, cases, monkeypatch)
            await replica_rules(companion, cases, controller, monkeypatch)

            # The notice names the epochs the archive holds: nothing is asked.
            asked = len(controller.requests)
            await companion._on_frame(controller.frames("notice")[0])
            await settled(companion)
            assert len(controller.requests) == asked
            # A screen's live frames name a newer epoch: the index answers that nothing changed.
            companion.archive.refresh("shots", 7099)
            await settled(companion)
            assert "index_shots_unchanged" in controller.used
            assert len(controller.requests) == asked + 1
            assert (await companion.archive.store.sync_state(DEVICE, "shots"))[1] == 7001

            # A busy controller: the trace is asked once and again only after the wait.
            await offload(
                lambda: companion.logs.db.execute("delete from archive_traces where id = 3")
            )
            await companion._on_frame(controller.frames("notice")[0])
            await settled(companion)
            assert "trace_busy" in controller.used
            assert companion.archive.busy_until > 0
            assert not await sql(companion, "select 1 from archive_traces where id = 3")
            assert sum(sent["t"] == "rt" and sent["id"] == 3 for sent in controller.requests) == 1

            # The store moved (shot 13 new, 9 rated again, 6 deleted): the index arrives as a
            # delta against the one this session received, and the archive follows it like a
            # whole index.
            await offload(
                lambda: companion.logs.db.execute(
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
            ratings = {
                row[0]: row[1]
                for row in await sql(
                    companion,
                    "select id, json_extract(body, '$.rating') from archive_records "
                    "where store = 'shots'",
                )
            }
            assert set(ratings) == {rid for rid in range(1, 14) if rid != 6}, ratings
            assert ratings[9] == 5, ratings
            state = await companion.archive.store.sync_state(DEVICE, "shots")
            assert state[1] == 7003, state
            assert state[4] == [2400, 14, 1], state
            # The same delta against another copy, or with another sum, rebuilds nothing.
            full, delta = (
                controller.frames(name)[0]["f"] for name in ("index_shots", "index_shots_delta")
            )
            assert isinstance(full, dict)
            assert isinstance(delta, dict)
            mirror = index_mirror.IndexMirror("test index")
            rebuilt = mirror.apply(full)
            assert rebuilt is not None
            assert rebuilt["rows"] == full["rows"]
            assert mirror.answered
            assert mirror.apply({**delta, "sum": delta["sum"] ^ 1}) is None
            assert mirror.pairs is None
            mirror.apply(full)
            assert mirror.apply({**delta, "base": 7000}) is None
            assert not mirror.delta(7001)
            mirror.apply(full)
            rebuilt = mirror.apply(delta)
            assert rebuilt is not None
            rows = rebuilt["rows"]
            assert isinstance(rows, list)
            assert index_mirror.checksum(rows) == delta["sum"]
            assert mirror.epoch == 7003
            await switch_off(companion, controller, monkeypatch)
            serving.cancel()
            companion.archive.stop()
            await companion.relay.close()
            await companion.logs.close()


def test_link_vectors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Companion archive from the firmware's link frames: every case, the replica pages frame for
    frame; hold, catch-up, fallback, relayed changes and traces, switch."""
    asyncio.run(scenario(monkeypatch))
