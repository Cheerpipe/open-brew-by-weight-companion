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
import tempfile
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, TypedDict, TypeIs, cast

import aiohttp
import pytest
from aiohttp.test_utils import TestServer

from companion import archive, index_mirror, link, stats
from companion.service import Companion, web_app
from companion.store import offload
from fake_controller import index_answer

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from companion.service import Frame
    from companion.store import Store

DEVICE = "AA:BB:CC:DD:EE:FF"
COLS = [
    "id",
    "bootId",
    "endedAtMs",
    "hasWallTime",
    "endedAtUnixSec",
    "endedAtLocalSec",
    "rating",
    "badReason",
    "durationS",
    "actualG",
    "goalG",
    "avgFlowGS",
    "arrivalS",
    "cutLineG",
    "fastBeforeS",
    "slowAfterS",
    "verdict",
    "presetId",
    "presetName",
    "scaleName",
    "shotType",
    "stopDetail",
]

type StoreName = Literal["shots", "history"]
type Shot = tuple[dict[str, object], dict[str, object]]  # The record and its curve.
STORE_NAMES: tuple[StoreName, ...] = ("shots", "history")


def is_store(value: object) -> TypeIs[StoreName]:
    return value in STORE_NAMES


class Stores(TypedDict):
    shots: dict[int, Shot]
    history: dict[int, dict[str, object]]


class Row(TypedDict, total=False):
    """An archive row as the page lists it (the members these checks read)."""

    id: int
    archiveGeneration: int
    archiveOnly: bool
    archiveTrace: bool
    rating: int
    badReason: str | None
    arrivalS: float | None
    verdict: str
    presetId: int
    scaleName: str


class PageJson(TypedDict, total=False):
    """A page's answer: Shots or History rows, or the Stats header (the members read here)."""

    rows: list[Row]
    next: str | None
    holes: list[dict[str, int]]
    generations: list[dict[str, int | bool | None]]
    presets: list[list[int | str]]
    stats: stats.Header
    good: int
    epoch: int


class Filter(TypedDict):
    bad: bool
    result: list[str]
    preset: list[int]
    scale: list[int]


class Receiver(Protocol):
    """Whoever takes the controller's frames: the companion, or a recorder in its place."""

    async def _on_frame(self, frame: Frame) -> None: ...


class Lines(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


class Upstream:
    """No La Marzocco in these tests."""

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

    def rejected_for(self, _: object) -> bool:
        return False

    def signed_in_for(self, _: object) -> bool:
        return False

    async def read(self) -> tuple[int, dict[str, object] | None, int]:
        raise AssertionError("no La Marzocco in these tests")

    async def command(self, *_: object) -> int:
        raise AssertionError("no La Marzocco in these tests")


class Controller:
    """The controller's two record stores and its answers to the archive's requests."""

    def __init__(self, capacity: int = 40) -> None:
        self.capacity, self.boot, self.clock = capacity, 7, 1789000000
        self.stores: Stores = {"shots": {}, "history": {}}
        self.next = {"shots": 1, "history": 1}
        self.epochs = {"shots": 11, "history": 21}
        self.gen = {"shots": 1, "history": 1}  # The store header's write counter: Clear keeps it.
        # D8: the user's Clear count and newest deleted ids.
        self.clears = {"shots": 0, "history": 0}
        self.gone: dict[str, list[int]] = {"shots": [], "history": []}
        self.traces: dict[
            int, bytes | str | None
        ] = {}  # shot id -> bytes, None (no trace) or "busy"
        self.requests: list[Frame] = []
        self.ignore = 0  # Index requests left unanswered (a lost frame).
        # A list while a hold keeps the requests back (and the pings unanswered).
        self.held: list[Frame] | None = None
        self.hold_next = False  # A hold starts right after the next index answer.
        self.hold_page = False  # ...or right after the next page.
        # Index deltas (`sum`, `d`): the link session's baselines, and the field the next delta
        # answer corrupts.
        self.baselines: dict[str, tuple[int, list[int]]] = {}
        self.tamper: str | None = None

    def moved(self, store: StoreName) -> None:
        self.epochs[store] += 1
        self.gen[store] += 1

    def add_shot(
        self, bad: str | None = None, trace: bytes | None = b"T", clock: bool = True
    ) -> int:
        rid = self.next["shots"]
        self.next["shots"] += 1
        end = rid * 1000 + 17
        self.stores["shots"][rid] = (
            {
                "id": rid,
                "bootId": self.boot,
                "endedAtMs": end,
                "hasWallTime": clock,
                "endedAtUnixSec": self.clock + rid * 3600 if clock else 0,
                "endedAtLocalSec": self.clock + rid * 3600 - 10800 if clock else 0,
                "rating": 0,
                "badReason": bad,
                "durationS": 9.0 if bad else 24.0 + rid % 7,
                "actualG": 36.0 + rid % 5 / 2,
                "goalG": 36,
                "avgFlowGS": 1.5 + rid % 4 / 10,
                "arrivalS": [None, 26.5, 28.0, 31.5][rid % 4],
                "cutLineG": None,
                "fastBeforeS": 25,
                "slowAfterS": 32,
                "verdict": ["on_recipe", "fast", "on_recipe", "slow"][rid % 4],
                "presetId": rid % 3 + 1,
                "presetName": f"Preset {rid % 3 + 1}",
                "scaleName": ["Lunar", "Pearl S"][rid % 2],
                "shotType": "auto",
                "stopDetail": "normal_target",
            },
            {"wD": f"curve{rid}", "wBreakBefore": [], "wHeld": []},
        )
        self.traces[rid] = trace + bytes([rid % 256]) if trace else trace
        self._rotate("shots")
        return rid

    def add_activation(self, kind: str = "shot", clock: bool = True, duration: float = 25.0) -> int:
        rid = self.next["history"]
        self.next["history"] += 1
        self.stores["history"][rid] = {
            "id": rid,
            "type": kind,
            "durationS": duration,
            "hasWallTime": clock,
            "endedAtUnixSec": self.clock + rid if clock else 0,
            "endedAtLocalSec": self.clock + rid - 10800 if clock else 0,
        }
        self._rotate("history")
        return rid

    def _rotate(self, store: StoreName) -> None:
        while len(self.stores[store]) > self.capacity:
            del self.stores[store][min(self.stores[store])]
        self.moved(store)

    def delete(self, store: StoreName, rid: int) -> None:
        """The user deletes a record: named in `gone`, newest first, at most 16."""
        del self.stores[store][rid]
        self.gone[store] = ([rid] + self.gone[store])[:16]
        self.moved(store)

    def clear(self, store: StoreName, user: bool = True) -> None:
        """Clear history: the records and the id counter go; the write counter keeps counting. A
        user's Clear raises the Clear count; a factory reset's keeps it."""
        self.stores[store], self.next[store], self.gone[store] = {}, 1, []
        self.clears[store] += int(user)
        self.moved(store)

    def factory_reset(self) -> None:
        """Every record and both counters start again."""
        for store in STORE_NAMES:
            self.clear(store, user=False)
            self.gen[store] = 1

    def rev(self, store: StoreName, rid: int) -> int:
        record = self.stores[store][rid]
        return zlib.crc32(json.dumps(record, sort_keys=True).encode()) & 0xFFFFFF

    def newest_first(self, store: StoreName) -> list[int]:
        return sorted(self.stores[store], reverse=True)

    async def serve(self, companion: Receiver, outbox: asyncio.Queue[Frame]) -> None:
        while True:
            frame = await outbox.get()
            if frame["t"] in ("rx", "rf", "rt", "logsub"):
                self.requests.append(frame)
                if self.held is not None:
                    self.held.append(frame)
                    continue
                if frame["t"] != "logsub":
                    await self.answer(companion, frame)

    async def _page_hold(self, companion: Receiver) -> None:
        if self.hold_page:
            self.hold_page, self.held = False, []
            await companion._on_frame({"t": "hold", "on": False, "sync": True})

    async def release(self, companion: Receiver) -> None:
        """The hold ends: the controller says so at once, answers what arrived meanwhile, then the
        pings are answered again."""
        held, self.held = self.held, None
        assert held is not None
        await companion._on_frame({"t": "hold", "on": False, "sync": False})
        for frame in held:
            if frame["t"] != "logsub":
                await self.answer(companion, frame)

    async def beat(self, companion: Receiver) -> None:
        """The controller's reply to each companion ping: the hold frame, `sync` false while
        clear."""
        while True:
            await asyncio.sleep(0.05)
            if self.held is None:
                await companion._on_frame({"t": "hold", "on": False, "sync": False})

    async def answer(self, companion: Receiver, frame: Frame) -> None:
        kind = frame["t"]
        if kind == "rx":
            if self.ignore:
                self.ignore -= 1
                return
            store = frame["s"]
            assert is_store(store)
            f: Frame = {
                "v": 1,
                "type": "records",
                "boot": self.boot,
                "store": store,
                "epoch": self.epochs[store],
                "gen": self.gen[store],
                "next": self.next[store],
                "clr": self.clears[store],
                "gone": self.gone[store],
            }
            rows = [
                value for rid in self.newest_first(store) for value in (rid, self.rev(store, rid))
            ]
            f.update(
                index_answer(
                    self.baselines, store, frame["ep"], frame.get("d"), self.epochs[store], rows
                )
            )
            if "base" in f and self.tamper:
                value = f[self.tamper]
                assert isinstance(value, int)
                f[self.tamper] = value ^ 1
                self.tamper = None
            await companion._on_frame({"t": "rec", "f": f})
            if self.hold_next:  # A scaled shot starts: the controller tells the companion at once.
                self.hold_next, self.held = False, []
                await companion._on_frame({"t": "hold", "on": False, "sync": True})
        elif kind == "rf":
            store, offset, count = frame["s"], frame["o"], frame["n"]
            assert is_store(store)
            assert isinstance(offset, int)
            assert isinstance(count, int)
            ids = self.newest_first(store)[offset : offset + count]
            if store == "history":
                await companion._on_frame(
                    {
                        "t": "rec",
                        "f": {
                            "v": 1,
                            "type": "history",
                            "boot": self.boot,
                            "snapshot": False,
                            "epoch": self.epochs[store],
                            "request": frame["r"],
                            "records": [self.stores[store][rid] for rid in ids],
                        },
                    }
                )
                await self._page_hold(companion)
                return
            shots = [
                [self.stores[store][rid][0][key] for key in COLS] + [self.stores[store][rid][1]]
                for rid in ids
            ]
            seq = len(self.requests)
            for base in range(0, max(len(shots), 1), 2):  # Two rows a frame: a page across frames.
                f = {
                    "v": 1,
                    "type": "stats",
                    "boot": self.boot,
                    "snapshot": False,
                    "epoch": self.epochs[store],
                    "seq": seq,
                    "request": frame["r"],
                    "total": len(self.stores[store]),
                    "offset": offset,
                    "limit": count,
                    "hasMore": False,
                    "rows": shots[base : base + 2],
                    "rowBase": base,
                    "more": base + 2 < len(shots),
                }
                if base == 0:
                    f.update(cols=",".join(COLS), tag=1)
                await companion._on_frame({"t": "rec", "f": f})
            await self._page_hold(companion)
        else:
            identity = (frame["id"], frame["b"], frame["e"])
            rid = frame["id"]
            assert isinstance(rid, int)
            record = self.stores["shots"].get(rid)
            trace = (
                self.traces.get(rid)
                if record
                and (record[0]["id"], record[0]["bootId"], record[0]["endedAtMs"]) == identity
                else None
            )
            answer: Frame = {"t": "trc", "id": frame["id"], "b": frame["b"], "e": frame["e"]}
            if trace in ("busy", "saving"):
                answer["r"] = trace
            elif trace:
                assert isinstance(trace, bytes)
                answer.update(r="ok", d=base64.b64encode(trace).decode())
            else:
                answer["r"] = "none"
            await companion._on_frame(answer)

    async def notice(self, companion: Receiver) -> None:
        await companion._on_frame(
            {"t": "rs", "sh": self.epochs["shots"], "hi": self.epochs["history"]}
        )


async def sql(companion: Companion, statement: str, *args: object) -> list[tuple[object, ...]]:
    return await offload(lambda: [tuple(row) for row in companion.logs.db.execute(statement, args)])


async def ids(companion: Companion, store: str, generation: int | None = None) -> set[int]:
    """The ids of one store: of every generation, or of one."""
    found: set[int] = set()
    for (rid,) in await sql(
        companion,
        "select id from archive_records where store = ? and generation = coalesce(?, generation)",
        store,
        generation,
    ):
        assert isinstance(rid, int)
        found.add(rid)
    return found


def text(value: object) -> str:
    """A TEXT column's value."""
    assert isinstance(value, str)
    return value


async def row(companion: Companion, store: str, rid: int, generation: int = 1) -> dict[str, object]:
    body: dict[str, object] = json.loads(
        text(
            (
                await sql(
                    companion,
                    "select body from archive_records where store = ? and id = ? "
                    "and generation = ?",
                    store,
                    rid,
                    generation,
                )
            )[0][0]
        )
    )
    return body


def quiet(copy: archive.Archive) -> bool:
    """No pass runs and none is due."""
    return copy.syncing is None and not copy.wake.is_set()


async def settled(companion: Companion) -> None:
    """The sync has nothing left to do."""
    for _ in range(300):
        await asyncio.sleep(0.02)
        if quiet(companion.archive) and not companion.archive.wanted:
            await asyncio.sleep(0.05)
            if quiet(companion.archive):
                return
    raise AssertionError("the archive sync did not settle")


def firmware_key(row: Row, sort: str, direction: str) -> tuple[int, ...]:
    """The controller's comparators, written from its code: date is (generation, id); rating puts
    unrated shots last whatever the direction, then the rating, then the newest first."""
    g, rid = row["archiveGeneration"], row["id"]
    if sort == "rating":
        rating = row["rating"]
        return (rating == 0, rating if direction == "asc" else -rating, -g, -rid)
    return (g, rid) if direction == "asc" else (-g, -rid)


def firmware_match(row: Row, query: Filter) -> bool:
    """shotListFilterMatches: AND across groups, OR within; a result needs an arrival."""
    if not query.get("bad") and row["badReason"] is not None:
        return False
    if query.get("result") and (not row["arrivalS"] or row["verdict"] not in query["result"]):
        return False
    if query.get("preset") and row["presetId"] not in query["preset"]:
        return False
    return (
        not query.get("scale")
        or zlib.crc32(row["scaleName"].encode()) ^ 0xFFFFFFFF in query["scale"]
    )


async def parity(
    companion: Companion,
    get: Callable[[str], Awaitable[PageJson]],
    refused: Callable[[str, int], Awaitable[None]],
) -> None:
    """A fixture of archive-only shots: a closed generation and the open one below its oldest, plus
    rows that are not archive-only."""

    def fixture() -> None:
        connection = companion.logs.db
        with connection:
            connection.execute("delete from archive_records")
            connection.execute("delete from archive_sync")
            connection.execute(
                "insert into archive_sync values (?, 'shots', 1, 0, 1, '[]', null, null)", (DEVICE,)
            )
            listed = [rid for rid in range(15, 31) if rid not in (22, 25)]
            connection.execute(
                "insert into archive_sync values (?, 'shots', 2, 9, 15, ?, 1789000000, null)",
                (DEVICE, json.dumps(listed)),
            )
            for generation, first, last in ((1, 1, 20), (2, 5, 30)):
                for rid in range(first, last + 1):
                    n = rid * 7 + generation
                    body = {
                        "id": rid,
                        "rating": n % 6 if n % 4 else 0,
                        "presetId": n % 3 + 1,
                        "presetName": f"Preset {n % 3 + 1} g{generation}",
                        "scaleName": ["Lunar", "Pearl S", ""][n % 3],
                        "arrivalS": [None, 0, 28.5, 31.0][n % 4],
                        "verdict": ["on_recipe", "fast", "slow"][n % 3],
                        "badReason": "short" if n % 5 == 0 else None,
                        "endedAtUnixSec": 1789000000 + rid,
                    }
                    connection.execute(
                        "insert into archive_records "
                        "values (?, 'shots', ?, ?, '', 0, 'good', ?, 0, ?)",
                        (
                            DEVICE,
                            generation,
                            rid,
                            int(body["badReason"] is not None),
                            json.dumps(body),
                        ),
                    )

    await offload(fixture)
    everything = (await get("/shots?limit=50&bad=1&sort=date&dir=asc"))["rows"]
    only = {(r["archiveGeneration"], r["id"]) for r in everything}
    expected_only = {(1, rid) for rid in range(1, 21)} | {(2, rid) for rid in range(5, 15)}
    assert only == expected_only, sorted(only ^ expected_only)
    history = (await get("/shots?limit=50&bad=1&all=1&sort=date&dir=asc"))["rows"]
    assert len(history) == 46, "both generations, the controller's rows included"
    lunar = zlib.crc32(b"Lunar") ^ 0xFFFFFFFF
    filters: list[dict[str, str]] = [
        {},
        {"bad": "1"},
        {"result": "fast,slow"},
        {"preset": "1,3"},
        {"scale": str(lunar)},
        {"bad": "1", "result": "on_recipe", "preset": "2"},
    ]
    for sort in ("date", "rating"):
        for direction in ("desc", "asc"):
            for given in filters:
                query: Filter = {
                    "bad": given.get("bad") == "1",
                    "result": given.get("result", "").split(",") if given.get("result") else [],
                    "preset": [int(v) for v in given.get("preset", "").split(",") if v],
                    "scale": [int(v) for v in given.get("scale", "").split(",") if v],
                }
                params = "&".join(
                    f"{k}={v}" for k, v in {**given, "sort": sort, "dir": direction}.items()
                )
                want = sorted(
                    (r for r in everything if firmware_match(r, query)),
                    key=lambda r: firmware_key(r, sort, direction),
                )
                whole = (await get(f"/shots?limit=50&{params}"))["rows"]
                assert [(r["archiveGeneration"], r["id"]) for r in whole] == [
                    (r["archiveGeneration"], r["id"]) for r in want
                ], (sort, direction, given)
                paged: list[Row] = []
                cursor = None
                while True:
                    page = await get(
                        f"/shots?limit=3&{params}" + (f"&cursor={cursor}" if cursor else "")
                    )
                    paged += page["rows"]
                    cursor = page["next"]
                    if cursor is None:
                        break
                assert paged == whole, (sort, direction, given)
                # The replica's page (the mux serves it): the whole history in the controller's
                # order, the rows only the archive keeps marked, the window sliced like
                # shotLogPageSlice.
                listed = sorted(
                    (r for r in history if firmware_match(r, query)),
                    key=lambda r: firmware_key(r, sort, direction),
                )
                total, good, start, rows, meta = await companion.archive.store.page(
                    DEVICE, "shots", {**query, "sort": sort, "dir": direction}, 2, 7
                )
                assert (total, start) == (len(listed), min(2, len(listed))), (
                    sort,
                    direction,
                    given,
                )
                assert good == sum(r["badReason"] is None for r in listed)
                assert [(g, rid, only) for g, rid, _, only, _ in rows] == [
                    (
                        r["archiveGeneration"],
                        r["id"],
                        (r["archiveGeneration"], r["id"]) in expected_only,
                    )
                    for r in listed[2:9]
                ], (sort, direction, given)
                assert (meta is None) == (not any(only for *_, only, _ in rows))
    presets = (await get("/shots?limit=1"))["presets"]
    assert len(presets) == 3, "the newest name per preset"
    assert all(isinstance(name, str) and name.endswith("g2") for _, name in presets), (
        "the newest name per preset"
    )
    for bad in (
        "sort=rating&dir=up",
        "result=early",
        "preset=x",
        "cursor=1",
        "scale=" + ",".join(["1"] * 9),
    ):
        await refused(f"/shots?limit=5&{bad}", 400)
    await refused("/history?limit=5&sort=rating", 400)  # History has no rating order.


class Recorded(TypedDict):
    request: Frame
    frames: list[Frame]


class Recorder:
    """Stands in for the companion while the scripted controller answers, keeping each answer:
    the shape of the firmware's link vectors (the request, then the controller's frames)."""

    def __init__(self, companion: Companion) -> None:
        self.companion = companion
        self.cases: list[Recorded] = []

    async def _on_frame(self, frame: Frame) -> None:
        self.cases[-1]["frames"].append(frame)
        await self.companion._on_frame(frame)


class Replay:
    """A controller made of recorded cases (the firmware's companion-records vectors when they
    come): each request the companion sends is answered with its case's frames, its own request id
    put in."""

    def __init__(self, cases: list[Recorded]) -> None:
        self.cases, self.answered = cases, 0

    @staticmethod
    def same(sent: Mapping[str, object], recorded: Mapping[str, object]) -> bool:
        return {k: v for k, v in sent.items() if k not in ("q", "r")} == {
            k: v for k, v in recorded.items() if k not in ("q", "r")
        }

    async def serve(self, companion: Companion, outbox: asyncio.Queue[Frame]) -> None:
        while True:
            frame = await outbox.get()
            if frame["t"] not in ("rx", "rf", "rt"):
                continue
            case = next(c for c in self.cases if self.same(frame, c["request"]))
            for recorded in case["frames"]:
                answer: Frame = json.loads(
                    json.dumps({k: v for k, v in recorded.items() if k != "q"})
                )
                inner = answer.get("f")
                if (
                    answer.get("t") == "rec"
                    and isinstance(inner, dict)
                    and "request" in inner
                    and "r" in frame
                ):
                    inner["request"] = frame["r"]
                await companion._on_frame(answer)
            self.answered += 1


async def replayed(companion: Companion, cases: list[Recorded]) -> int:
    """The archive a recorded session leaves, from those frames alone."""
    replay = Replay(cases)
    outbox: asyncio.Queue[Frame] = asyncio.Queue()
    companion.outbox = outbox
    task = asyncio.create_task(replay.serve(companion, outbox))
    await companion._on_frame({"t": "dev", "name": "Kitchen", "id": DEVICE})
    await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": True})
    await companion._on_frame({"t": "hold", "on": False, "sync": False})
    await settled(companion)
    task.cancel()
    companion.archive.stop()
    companion.outbox = None
    return replay.answered


class Link:
    """A session: the companion's outbox and the controller answering it."""

    outbox: asyncio.Queue[Frame]
    task: asyncio.Task[None]
    pings: asyncio.Task[None]

    def __init__(self, companion: Companion, fake: Controller) -> None:
        self.companion, self.fake = companion, fake

    async def open(
        self, archive_on: bool = True, log: bool = False, cfg: Frame | None = None
    ) -> None:
        self.fake.baselines = {}  # A new link session: the controller's baselines start again.
        self.outbox = asyncio.Queue()
        self.companion.outbox = self.outbox
        self.task = asyncio.create_task(self.fake.serve(self.companion, self.outbox))
        self.pings = asyncio.create_task(self.fake.beat(self.companion))
        await self.companion._on_frame({"t": "dev", "name": "Kitchen", "id": DEVICE})
        await self.companion._on_frame(
            cfg or {"t": "cfg", "ui": True, "log": log, "archive": archive_on}
        )

    def close(self) -> None:
        self.task.cancel()
        self.pings.cancel()
        self.companion.sync_due, self.companion.sync_hold = (
            {},
            None,
        )  # As a new session starts them.
        self.companion.log_subscribed = self.companion.log_identified = (
            self.companion.configured
        ) = False
        self.companion.archive.stop()
        self.companion.outbox = None


async def scenario(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive, "REQUEST_S", 0.5)
    monkeypatch.setattr(archive, "TRACE_RETRY_S", 0.2)
    lines = Lines()
    logging.getLogger("obbw").addHandler(lines)
    fake = Controller()
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-archive-") as temporary:
        data = Path(temporary)
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", data, http, Upstream)
            companion.pairing.state = "paired"  # The archive's reads belong to a paired companion.
            await companion.open_log()
            verdict: dict[str, bool | None] = {"value": True}
            admin = {"value": True}

            # (signed in, Admin unlocked for that screen, login off), None when unreachable
            async def allows(_headers: Mapping[str, str]) -> tuple[bool, bool, bool] | None:
                return (
                    None if verdict["value"] is None else (verdict["value"], admin["value"], False)
                )

            monkeypatch.setattr(companion, "_web_ui_allows", allows)
            pages = TestServer(web_app(companion), host="127.0.0.1")
            await pages.start_server()
            base = f"http://127.0.0.1:{pages.port}/__companion/archive"
            session = {"X-WebUI-Session": "token"}

            async def post(
                path: str, body: Mapping[str, object], headers: Mapping[str, str] = session
            ) -> tuple[int, object]:
                async with http.post(base + path, json=body, headers=headers) as reply:
                    return reply.status, await reply.json()

            async def get(path: str) -> PageJson:
                async with http.get(base + path, headers=session) as reply:
                    assert reply.status == 200, (path, reply.status)
                    return cast("PageJson", await reply.json())

            async def refused(path: str, status: int) -> None:
                async with http.get(base + path, headers=session) as reply:
                    assert reply.status == status, (path, reply.status)

            def said(text: str) -> int:
                return sum(text in line for line in lines.lines)

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
            stores = [str(frame.get("s", "trace")) for frame in fake.requests]
            assert stores == sorted(stores, key=["history", "shots", "trace"].index), (
                "activations, shots, traces"
            )
            assert fake.requests[0] == {"t": "rx", "s": "history", "ep": 0}
            traces = {
                r[0]: r[1] for r in await sql(companion, "select id, data from archive_traces")
            }
            assert len(traces) == 29, "a shot without a trace is never asked again"
            assert traces[6] is None, "a shot without a trace is never asked again"
            assert 30 not in traces, "a trace still being saved is asked again later"
            seen = len(fake.requests)
            companion.archive.wake.set()  # Another pass before the deadline does not ask again.
            await asyncio.sleep(0.05)
            assert not [f for f in fake.requests[seen:] if f["t"] == "rt"], fake.requests[seen:]
            fake.traces[30] = b"late"
            await asyncio.sleep(0.4)
            await settled(companion)
            assert {
                r[0]: r[1] for r in await sql(companion, "select id, data from archive_traces")
            }[30] == b"late"
            bad = await sql(
                companion, "select id, kind from archive_records where store = 'shots' and bad = 1"
            )
            assert {rid for rid, _ in bad} == {4, 11, 18, 25}
            assert all(kind == "short" for _, kind in bad)
            state = await companion.archive.store.sync_state(DEVICE, "shots")
            assert state[:3] == (1, fake.epochs["shots"], 1)
            assert state[3] == list(range(30, 0, -1))

            # --- An unchanged store costs nothing; a new shot fetches only itself -------
            fake.requests.clear()
            await fake.notice(companion)
            await settled(companion)
            assert fake.requests == [], "the notice names the epochs the archive holds"
            fake.add_shot()
            await fake.notice(companion)
            await settled(companion)
            assert [(frame["t"], frame.get("o"), frame.get("n")) for frame in fake.requests] == [
                ("rx", None, None),
                ("rf", 0, 1),
                ("rt", None, None),
            ], fake.requests

            # --- A rating updates the row; a recycled (empty) curve keeps the copy ------
            record, curve = fake.stores["shots"][5]
            record["rating"], curve["wD"] = 4, ""
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            body = await row(companion, "shots", 5)
            assert body["rating"] == 4, body
            assert body["wD"] == "curve5", body

            # --- Deletions mirror: one inside, and the newest, which is not a restart ---
            del fake.stores["shots"][12]
            del fake.stores["shots"][31]
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            held = await ids(companion, "shots")
            assert 12 not in held, "deleting the newest is not a restart"
            assert 31 not in held, "deleting the newest is not a restart"
            assert len(held) == 29, "deleting the newest is not a restart"
            assert not await sql(companion, "select 1 from archive_traces where id in (12, 31)")
            assert not said("restarted")

            # --- A firmware that names no deletions: a deleted oldest record reads as rotation --
            del fake.stores["shots"][1]
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            assert 1 in await ids(companion, "shots")

            # --- One record with another identity: both are kept, nothing restarts (S19) --
            fake.stores["shots"][20][0]["bootId"] = 99
            fake.traces[20] = b"new20"
            fake.moved("shots")
            del fake.stores["shots"][
                19
            ]  # A deletion in the same pass waits: the pass could not tell.
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            assert len(await ids(companion, "shots", 1)) == 29
            assert not said("restarted")
            assert await sql(
                companion,
                "select generation, ident from archive_records where store = 'shots' "
                "and id = 20 order by generation",
            ) == [(0, "7:20017"), (1, "99:20017")]
            assert {
                r[0]: r[1]
                for r in await sql(
                    companion, "select generation, data from archive_traces where id = 20"
                )
            } == {0: b"T\x14", 1: b"new20"}, "the old record keeps its trace aside"
            assert said("shot 20 may be a different record now") == 1
            assert 19 in await ids(companion, "shots", 1)
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            assert 19 not in await ids(companion, "shots", 1), (
                "the next clear pass mirrors the deletion"
            )

            # --- Away: more shots than the controller keeps; the hole is recorded -------
            link_.close()
            for _ in range(60):
                fake.add_shot()
            assert min(fake.stores["shots"]) == 52
            await link_.open()
            await settled(companion)
            held = await ids(companion, "shots")
            assert set(range(52, 92)) <= held, "rotation is not deletion"
            assert set(range(2, 31)) - {12, 19} <= held, "rotation is not deletion"
            assert not said("restarted"), "everything missing is below the controller's oldest"
            assert await sql(
                companion, "select generation, below, above, count from archive_holes"
            ) == [(1, 30, 52, 21)], (
                "shots 31 to 51 (31 deleted, the rest rotated) were never copied"
            )
            tail = await get("/shots?limit=50&bad=1")
            assert tail["holes"] == [{"generation": 1, "below": 30, "above": 52, "count": 21}]
            assert tail["generations"] == [
                {"generation": 1, "count": 68, "restartedAt": None, "current": True},
                {"generation": 0, "count": 1, "restartedAt": None, "current": False},
            ]
            assert [r["id"] for r in tail["rows"]][:3] == [30, 29, 28]
            assert tail["next"] is None
            assert all(r["archiveTrace"] is (r["id"] != 6) for r in tail["rows"])
            assert [(r["archiveGeneration"], r["id"]) for r in tail["rows"]][-1] == (0, 20), (
                "the set-aside copy"
            )
            assert 25 not in [r["id"] for r in (await get("/shots?limit=50"))["rows"]], (
                "bad shots only with bad=1"
            )
            page = await get("/shots?limit=5&cursor=-1:-20&bad=1")
            assert [r["id"] for r in page["rows"]] == [18, 17, 16, 15, 14]
            assert page["next"] == "-1:-14"

            # --- Archive-only edits are the companion's; controller-held ones are not ---
            assert await post("/rate", {"id": 30, "rating": 5}) == (200, {"ok": True})
            assert await post("/rate", {"id": 60, "rating": 5}) == (404, {"error": "NOT_FOUND"})
            assert (await post("/rate", {"id": 30, "rating": 6}))[0] == 400
            assert (await row(companion, "shots", 30))["rating"] == 5
            for rid in range(2, 12):
                assert await post("/delete", {"store": "shots", "id": rid}) == (200, {"ok": True})
            assert await post("/delete", {"store": "shots", "generation": 0, "id": 999}) == (
                404,
                {"error": "NOT_FOUND"},
            )
            async with http.get(base + "/trace?id=29&boot=7&end=29017", headers=session) as reply:
                assert reply.status == 200
                assert await reply.read() == b"T\x1d"
            async with http.get(base + "/trace?id=6&boot=7&end=6017", headers=session) as reply:
                assert reply.status == 404
                assert (await reply.json())["error"] == "NO_SHOT_TRACE"

            # --- A record the controller holds is the controller's to delete (AC8) ----------
            assert await post("/delete", {"store": "shots", "id": 60}) == (
                404,
                {"error": "NOT_FOUND"},
            )
            assert 60 in await ids(companion, "shots")
            for removed in ("/keep", "/erase", "/settings"):
                async with http.post(
                    base + removed, json={"store": "shots", "id": 30}, headers=session
                ) as reply:
                    assert reply.status in (404, 405), (removed, reply.status)

            # --- Deleting needs Admin unlocked on that screen, confirmed live (AC8) ------
            admin["value"] = False
            assert await post("/delete", {"store": "shots", "id": 30}) == (
                401,
                {
                    "error": "ADMIN_LOCKED",
                    "message": "Unlock Admin in the Web UI opened through the companion, "
                    "then try again",
                },
            )
            assert said("refused /__companion/archive/delete: Admin is not unlocked") == 1
            assert await post("/rate", {"id": 30, "rating": 3}) == (200, {"ok": True}), (
                "rating needs no unlock"
            )
            verdict["value"] = None
            assert (await post("/delete", {"store": "shots", "id": 30}))[0] == 503, (
                "no answer: nothing deleted"
            )
            verdict["value"], admin["value"] = True, True
            companion.log_unreachable = 0  # The controller answers again.

            # Without a relay session the controller is asked as nobody: nothing counts as unlocked,
            # whatever it answers.
            class Reply:
                status = 200
                data = json.dumps(
                    {"loginRequired": False, "signedIn": False, "adminUnlocked": True}
                ).encode()

                def release(self) -> None:
                    pass

            async def passthrough(*_: object) -> Reply:
                return Reply()

            with monkeypatch.context() as patch:
                patch.setattr(companion.relay, "mode", "disabled")
                patch.setattr(companion.relay, "passthrough", passthrough)
                patch.setattr(companion, "controller", ("Kitchen", ("127.0.0.1", 9)))
                assert await Companion._web_ui_allows(
                    companion, {"X-WebUI-Client": "0123456789abcdef"}
                ) == (True, False, True)
            assert 30 in await ids(companion, "shots")

            # --- Access: reads keep a remembered grant; changes need the controller now --
            verdict["value"] = False
            companion.log_grants.clear()
            async with http.get(
                base + "/history?limit=5", headers={"X-WebUI-Session": "other"}
            ) as reply:
                assert reply.status == 401
                assert (await reply.json())["error"] == "AUTH_REQUIRED"
            assert (await post("/rate", {"id": 30, "rating": 1}, {"X-WebUI-Session": "other"}))[
                0
            ] == 401
            verdict["value"] = True
            await get("/history?limit=5")
            verdict["value"] = None  # The controller is off.
            companion.log_unreachable = 0
            await get("/history?limit=5")  # A browser it accepted keeps reading.
            # ...every copied row too, for its read-only view: the open history's newest first, each
            # one marked whether the controller still lists it.
            only = {
                (r["archiveGeneration"], r["id"])
                for r in (await get("/shots?limit=50&bad=1"))["rows"]
            }
            every = (await get("/shots?limit=50&bad=1&all=1"))["rows"]
            assert every[0]["id"] == max(await ids(companion, "shots", 1))
            assert every[0]["archiveOnly"] is False
            assert all(
                r["archiveOnly"] is ((r["archiveGeneration"], r["id"]) in only) for r in every
            )
            assert await post("/rate", {"id": 30, "rating": 1}) == (
                503,
                {
                    "error": "CONTROLLER_UNREACHABLE",
                    "message": "The controller must be on to confirm your sign-in",
                },
            )
            verdict["value"] = True
            async with http.post(base + "/rate", data="{}", headers=session) as reply:
                assert reply.status == 415

            # --- A restarted history (the Clear count unchanged): the generation closes, nothing
            # goes (S4) --
            before = await ids(companion, "shots")
            fake.clear("shots", user=False)
            for _ in range(5):
                fake.add_shot()
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "shots", 1) == before, (
                "the closed generation keeps every record"
            )
            assert await ids(companion, "shots", 2) == set(range(1, 6))
            assert said("shot history restarted") == 1
            assert not await sql(companion, "select * from archive_holes where generation = 2")
            facts = (await companion.status())["archive"]
            assert isinstance(facts, dict)
            generations = facts["generations"]["shots"]
            assert [(g["generation"], g["count"], g["current"]) for g in generations] == [
                (2, 5, True),
                (1, len(before), False),
                (0, 1, False),
            ]
            assert generations[0]["restartedAt"] > 0
            tail = await get("/shots?limit=50&bad=1")
            assert tail["rows"][0]["archiveGeneration"] == 1, (
                "the closed generation is archive-only"
            )
            assert tail["rows"][0]["id"] == max(before), "the closed generation is archive-only"
            assert (
                len(await sql(companion, "select * from archive_traces where generation = 2")) == 5
            )

            # --- Activations: the controller's id counter fell back (S19) ---------------
            link_.close()
            fake.clear("history", user=False)
            for n in range(8):
                fake.add_activation(clock=False, duration=20.0 + n)
            await link_.open()
            await settled(companion)
            assert await ids(companion, "history", 1) == set(range(1, 31))
            assert await ids(companion, "history", 2) == set(range(1, 9))
            assert said("activation history restarted") == 1

            # --- A lost answer is asked again --------------------------------------------
            fake.ignore = 1
            fake.add_activation()
            await fake.notice(companion)
            await asyncio.sleep(0.8)
            await settled(companion)
            assert said("did not answer the archive's rx") >= 1
            assert await ids(companion, "history", 2) == set(range(1, 10))

            # --- The link closes mid-sync: nothing doubled, the epoch waits -------------
            for _ in range(6):
                fake.add_shot()
            fake.held = []
            await fake.notice(companion)
            await asyncio.sleep(0.2)
            link_.close()
            fake.held = None
            assert (await companion.archive.store.sync_state(DEVICE, "shots"))[1] != fake.epochs[
                "shots"
            ]
            await link_.open()
            await settled(companion)
            assert await ids(companion, "shots", 2) == set(range(1, 12))
            assert (await companion.archive.store.sync_state(DEVICE, "shots"))[1] == fake.epochs[
                "shots"
            ]

            # --- Switch off: nothing asked, everything kept; on again catches up --------
            await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": False})
            fake.requests.clear()
            fake.add_shot()
            await fake.notice(companion)
            await asyncio.sleep(0.2)
            assert fake.requests == []
            assert await ids(companion, "shots", 2) == set(range(1, 12))
            # ...and the controller-off view (every copied row) follows the switch; the merged rows
            # stay.
            async with http.get(base + "/shots?limit=5&all=1", headers=session) as reply:
                assert reply.status == 409
                assert (await reply.json())["error"] == "ARCHIVE_OFF"
            await get("/shots?limit=5")

            # The switch as a companion restarted now, with the controller off, knows it.
            async def kept() -> tuple[bool, bool]:
                restarted = Companion("Kitchen server", data, http, Upstream)
                restarted.pairing.state = "paired"
                await restarted.open_log()
                await restarted.logs.close()
                await restarted.relay.close()
                return restarted.archive.available, restarted.archive.on

            assert await kept() == (True, False)
            await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": True})
            await settled(companion)
            assert 12 in await ids(companion, "shots", 2)
            assert await kept() == (True, True)

            # --- Status and an export across generations -------------------------------
            facts = (await companion.status())["archive"]
            assert isinstance(facts, dict)
            assert facts["on"]
            assert facts["available"]
            assert facts["bytes"] > 0
            assert (
                facts["shotsTotal"]
                == (
                    await sql(
                        companion, "select count(*) from archive_records where store = 'shots'"
                    )
                )[0][0]
            )
            assert "keepDeleted" not in facts
            # A record set aside twice sits below generation 0: exported and editable (review C4).
            opened = (await companion.archive.store.sync_state(DEVICE, "shots"))[0]
            await sql(
                companion,
                "insert into archive_records select device_id, store, -1, id, ident, rev, kind, "
                "bad, ended_at, body from archive_records where store = 'shots' and "
                f"generation = {opened} and id = 1",
            )
            assert await post("/rate", {"generation": -1, "id": 1, "rating": 4}) == (
                200,
                {"ok": True},
            )
            async with http.get(base + "/export", headers=session) as reply:
                exported = json.loads(await reply.read())
            assert exported["format"] == "openbrewbyweight-companion-archive"
            assert exported["device"] == DEVICE
            assert {r["archiveGeneration"] for r in exported["history"]} == {
                g
                for (g,) in await sql(
                    companion,
                    "select distinct generation from archive_records where store = 'history'",
                )
            }
            assert [(r["archiveGeneration"], r["id"]) for r in exported["shots"]] == await sql(
                companion,
                "select generation, id from archive_records where store = 'shots' "
                "order by generation, id",
            )
            assert not any("archiveKept" in r for r in exported["shots"])
            assert await post("/delete", {"store": "shots", "generation": -1, "id": 1}) == (
                200,
                {"ok": True},
            )
            assert base64.b64decode(exported["traces"][0]["data"])

            # --- A factory reset, then pairing again: every record stays, closed (S8, D9) --
            shots_open = (await companion.archive.store.sync_state(DEVICE, "shots"))[0]
            history_open = (await companion.archive.store.sync_state(DEVICE, "history"))[0]
            shots_before = await ids(companion, "shots", shots_open)
            history_before = await ids(companion, "history", history_open)
            link_.close()
            fake.factory_reset()
            fake.boot = 8
            await link_.open()  # Paired again: the same controller id reattaches to its archive.
            await settled(companion)
            assert await ids(companion, "shots", shots_open) == shots_before, (
                "an empty index changes nothing"
            )
            fake.add_shot()
            fake.add_activation(duration=31.0)
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "shots", shots_open) == shots_before
            assert await ids(companion, "shots", shots_open + 1) == {1}
            assert await ids(companion, "history", history_open) == history_before
            assert await ids(companion, "history", history_open + 1) == {1}
            shots_open += 1

            # --- A hold mid-sync stops both directions, timers included (S17) ------------
            new = {fake.add_shot() for _ in range(4)}
            fake.hold_next = True
            seen = len(fake.requests)
            await fake.notice(companion)
            await asyncio.sleep(0.8)  # Past the 0.5 s re-ask: it is armed, not sent.
            assert len(fake.requests) == seen + 1, fake.requests[seen:]
            assert fake.requests[-1]["t"] == "rx", fake.requests[seen:]
            assert companion.sync_due
            assert not await ids(companion, "shots", shots_open) >= new
            await fake.release(companion)
            await settled(companion)
            assert await ids(companion, "shots", shots_open) >= new
            assert await sql(
                companion,
                "select count(*) from archive_records where store = 'shots' and "
                f"generation = {shots_open} and id between {min(new)} and {max(new)}",
            ) == [(4,)], "nothing lost, nothing doubled"
            assert (await companion.archive.store.sync_state(DEVICE, "shots"))[1] == fake.epochs[
                "shots"
            ]

            # --- The Stats header over the whole history (S13, S15, S16, S18) -----------
            synced = fake.epochs["shots"]
            async with http.get(
                base + f"/stats?window=10&active=2&epoch={synced}", headers=session
            ) as reply:
                answer = cast("PageJson", await reply.json())
            merged = [
                json.loads(text(body))
                for (body,) in await sql(
                    companion,
                    "select body from archive_records where store = 'shots' "
                    "order by generation desc, id desc",
                )
            ]
            assert reply.status == 200
            assert answer["epoch"] == synced
            assert answer["stats"] == stats.header(merged, 10, 2)
            assert answer["stats"]["shotCount"] == 10
            assert answer["good"] == stats.good(merged, (), (), ()) > 10
            for window in (50, 100, 500, 1000):
                assert (await get(f"/stats?window={window}&active=2&epoch={synced}"))[
                    "stats"
                ] == stats.header(merged, window, 2)
            fast = await get(f"/stats?window=10&active=2&epoch={synced}&result=fast&preset=1,2")
            assert fast["good"] == stats.good(merged, (1,), (1, 2), ()), (
                "filters choose the windows; the header covers every shot, as the controller's"
            )
            assert fast["stats"] == answer["stats"], (
                "filters choose the windows; the header covers every shot, as the controller's"
            )
            for wrong in (
                "window=20&epoch=1",
                "window=10",
                "window=10&epoch=1&result=early",
                "window=10&epoch=x",
            ):
                await refused(f"/stats?{wrong}", 400)
            fake.add_shot()  # A new shot the copy has not seen: the header waits for it.
            answer = await get(f"/stats?window=10&active=2&epoch={fake.epochs['shots']}")
            assert answer["epoch"] == fake.epochs["shots"]
            assert answer["good"] == stats.good(merged, (), (), ()) + 1
            monkeypatch.setattr(archive, "FRESH_S", 0.4)
            complete = answer
            fake.held = []
            await companion._on_frame({"t": "hold", "on": False, "sync": True})
            fake.add_shot()
            began = asyncio.get_running_loop().time()
            held_header = await get(f"/stats?window=10&active=2&epoch={fake.epochs['shots']}")
            assert held_header == complete, (
                "during a hold the newest complete header answers at once, with its own epoch"
            )
            assert asyncio.get_running_loop().time() - began < 0.3, (
                "during a hold the newest complete header answers at once, with its own epoch"
            )
            await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": False})
            for _ in range(2):
                await refused(f"/stats?window=10&active=2&epoch={fake.epochs['shots']}", 503)
            assert said("the Stats header over the whole history is unavailable") == 1, (
                "rate-limited"
            )
            await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": True})
            await fake.release(companion)
            await settled(companion)
            await get(f"/stats?window=10&active=2&epoch={fake.epochs['shots']}")
            view = companion.screens.mux.views["stats"]
            view.epoch = fake.epochs["shots"]
            fake.add_shot()  # A screen showing Stats sees the new shot in the live frames.
            view._standing(
                {
                    "type": "stats",
                    "request": 0,
                    "seq": 1,
                    "rowBase": 0,
                    "snapshot": False,
                    "epoch": fake.epochs["shots"],
                    "rows": [],
                    "more": False,
                }
            )
            await settled(companion)
            assert (await companion.archive.store.sync_state(DEVICE, "shots"))[1] == fake.epochs[
                "shots"
            ]

            # --- One history (S9, S12): the controller's filters and orders, ties included --
            await parity(companion, get, refused)

            # --- The log asks only outside a hold too ----------------------------------------
            link_.close()
            fake.held = []  # A shot is on when the link opens: no ping is answered.
            seen = len(fake.requests)
            await link_.open(log=True)
            await asyncio.sleep(0.3)
            assert not [f for f in fake.requests[seen:] if f["t"] == "logsub"], (
                "logsub waits for the hold's end"
            )
            await fake.release(companion)
            await asyncio.sleep(0.2)
            assert [f["t"] for f in fake.requests[seen:]].count("logsub") == 1
            await companion._on_frame({"t": "hold", "on": False, "sync": True})
            fake.held = []
            await companion._log_subscribe(
                resync=True
            )  # A write failed: ask again from the stored cursor.
            await asyncio.sleep(0.2)
            assert [f["t"] for f in fake.requests[seen:]].count("logsub") == 1, (
                "the resync waits for the hold"
            )
            await fake.release(companion)
            await asyncio.sleep(0.2)
            assert [f["t"] for f in fake.requests[seen:]].count("logsub") == 2
            fake.held = None

            # --- Forget erases it all --------------------------------------------------------
            link_.close()
            await companion.erase("forgotten for the test")
            companion.pairing.state = "paired"  # Paired again, for what follows.
            assert not await sql(companion, "select * from archive_records")
            assert not await sql(companion, "select * from archive_sync")

            # --- S19 on a small store: the controller's counters decide restarts ----------
            fake = Controller()
            link_ = Link(companion, fake)
            for _ in range(4):
                fake.add_shot()
            await link_.open()
            await settled(companion)
            assert await ids(companion, "shots", 1) == {1, 2, 3, 4}
            restarts = said("restarted")
            for rid in (2, 3, 4):  # Most of a small store deleted: not a restart.
                del fake.stores["shots"][rid]
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            assert await sql(
                companion, "select generation, id from archive_records where store = 'shots'"
            ) == [(1, 1)]
            assert said("restarted") == restarts

            # --- A counter decrease restarts before any page; the pass breaks off --------
            monkeypatch.setitem(archive.FETCH_MAX, "shots", 2)
            fake.clear("shots", user=False)
            fake.boot = 9
            for _ in range(3):
                fake.add_shot()
            fake.hold_page = True
            await fake.notice(companion)
            await asyncio.sleep(0.3)
            link_.close()
            fake.held = None
            assert await ids(companion, "shots", 1) == {1}, (
                "no row of the new history lands in the closed one"
            )
            assert await ids(companion, "shots", 2) == {2, 3}
            assert said("restarted") == restarts + 1
            # Before a full sync the open generation's records may be the controller's: never the
            # companion's.
            assert await post("/delete", {"store": "shots", "id": 3}) == (
                404,
                {"error": "NOT_FOUND"},
            )
            await link_.open()
            await settled(companion)
            monkeypatch.setitem(archive.FETCH_MAX, "shots", 50)
            assert await ids(companion, "shots", 2) == {1, 2, 3}
            assert said("restarted") == restarts + 1

            # --- A deletion on the controller leaves the whole-history header (C9) -------
            epoch = fake.epochs["shots"]
            assert (await get(f"/stats?window=10&active=1&epoch={epoch}"))["good"] == 4
            del fake.stores["shots"][3]
            fake.moved("shots")
            await fake.notice(companion)
            await settled(companion)
            assert (await get(f"/stats?window=10&active=1&epoch={fake.epochs['shots']}"))[
                "good"
            ] == 3

            # --- A change the user makes mid-pass starts it again from the index (C3) ----
            fake.add_shot()
            fake.hold_next, seen = True, len(fake.requests)
            await fake.notice(companion)
            await asyncio.sleep(0.2)
            assert await post("/rate", {"generation": 1, "id": 1, "rating": 2}) == (
                200,
                {"ok": True},
            )
            await fake.release(companion)
            await settled(companion)
            assert await ids(companion, "shots", 2) == {1, 2, 4}
            assert not said("archive sync stopped")
            assert [f["t"] for f in fake.requests[seen:] if f.get("s") == "shots"].count(
                "rx"
            ) == 2, "the pass started over from the index"

            # --- A long absence: both counters overtook; identities decide (fallback) ----
            link_.close()
            fake.clear("shots", user=False)
            fake.boot = 10
            for _ in range(10):
                fake.add_shot()
            await link_.open()
            await settled(companion)
            assert await ids(companion, "shots", 2) == {1, 2, 4}
            assert await ids(companion, "shots", 3) == set(range(1, 11))
            assert said("restarted") == restarts + 2

            # --- A clockless restart with an identical record: the counters still see it ---
            for _ in range(2):
                fake.add_activation(clock=False, duration=20.0)
            await fake.notice(companion)
            await settled(companion)
            fake.clear("history", user=False)
            fake.add_activation(
                clock=False, duration=20.0
            )  # Identical to the cleared activation 1.
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "history", 1) == {1, 2}
            assert await ids(companion, "history", 2) == {1}

            # --- An empty pass between a clockless clear and an identical record (review C1) --
            opened = (await companion.archive.store.sync_state(DEVICE, "history"))[0]
            fake.add_activation(clock=False, duration=20.0)
            await fake.notice(companion)
            await settled(companion)
            before = await ids(companion, "history", opened)
            fake.clear("history", user=False)
            await fake.notice(companion)
            await settled(companion)
            assert (await companion.archive.store.sync_state(DEVICE, "history"))[0] == opened + 1, (
                "the empty index's counters close the generation at once"
            )
            fake.add_activation(
                clock=False, duration=20.0
            )  # Identical to the cleared activation 1.
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "history", opened) == before, "nothing deleted"
            assert len(before) > 1, "nothing deleted"
            assert await ids(companion, "history", opened + 1) == {1}

            # --- Index deltas: `d` only after a listed answer in this link session, every answer
            # checked ---
            link_.close()
            await link_.open()
            await settled(companion)

            async def change(*kinds: str) -> tuple[list[tuple[object, object]], list[str]]:
                """Shots change; the index the notice brings in, as the requests and answers
                went."""
                answers: list[str] = []
                requests = len(fake.requests)
                original = companion.archive.on_rec

                def seen(frame: Mapping[str, object]) -> None:
                    inner = frame["f"]
                    assert isinstance(inner, dict)
                    if inner.get("type") == "records":
                        answers.append(
                            "delta" if "base" in inner else "rows" if "rows" in inner else "same"
                        )
                    original(frame)

                with monkeypatch.context() as patch:
                    patch.setattr(companion.archive, "on_rec", seen)
                    for kind in kinds:
                        if kind == "new":
                            fake.add_shot()
                        elif kind == "rating":
                            record = fake.stores["shots"][sorted(fake.stores["shots"])[-3]][0]
                            rating = record["rating"]
                            assert isinstance(rating, int)
                            record["rating"] = (rating + 1) % 6
                        else:
                            del fake.stores["shots"][sorted(fake.stores["shots"])[-2]]
                    fake.moved("shots")
                    await fake.notice(companion)
                    await settled(companion)
                expected = {rid: fake.rev("shots", rid) for rid in fake.stores["shots"]}
                pairs = companion.archive.mirrors["shots"].pairs
                assert pairs is not None
                assert dict(pairs) == expected
                for rid, (record, _) in fake.stores["shots"].items():
                    assert (await row(companion, "shots", rid, generation))["rating"] == record[
                        "rating"
                    ], rid
                asked = [
                    (frame["ep"], frame.get("d"))
                    for frame in fake.requests[requests:]
                    if frame["t"] == "rx"
                ]
                return asked, answers

            generation = (await companion.archive.store.sync_state(DEVICE, "shots"))[0]
            since = fake.epochs["shots"]
            assert await change("new") == ([(since, None)], ["rows"]), (
                "the session's first index is whole"
            )
            since = fake.epochs["shots"]
            assert await change("new", "rating", "gone") == ([(since, 1)], ["delta"])
            gone, since = sorted(fake.stores["shots"])[-2], fake.epochs["shots"]
            assert await change("gone") == ([(since, 1)], ["delta"])
            assert gone not in await ids(companion, "shots")
            for field in (
                "sum",
                "base",
            ):  # Rebuilt wrong, or against another index: the whole index, once.
                fake.tamper = field
                since = fake.epochs["shots"]
                assert await change("rating") == ([(since, 1), (0, None)], ["delta", "rows"]), field
            assert said("archive's shots index did not match") == 2
            link_.close()  # A new link session, then a companion restart (its copy is memory only).
            await link_.open()
            await settled(companion)
            since = fake.epochs["shots"]
            assert await change("new") == ([(since, None)], ["rows"])
            companion.archive.mirrors["shots"] = index_mirror.IndexMirror("archive's shots index")
            since = fake.epochs["shots"]
            assert await change("new") == ([(since, None)], ["rows"])
            since = fake.epochs["shots"]
            assert await change("rating") == ([(since, 1)], ["delta"])

            # --- The page's erase keeps the log history and the archive (review C2) -------
            records_kept = await sql(companion, "select count(*) from archive_records")
            link_.close()
            await companion.erase("erased on the page", history=False)
            companion.pairing.state = "paired"  # Paired again, for what follows.
            assert await sql(companion, "select count(*) from archive_records") == records_kept
            assert await companion.logs.meta("device") == DEVICE, (
                "the log store keeps the controller and its history"
            )
            await link_.open()
            await settled(companion)

            # --- D8: the controller names the user's deletions and Clears --------------------
            link_.close()
            await companion.erase("forgotten for the deletion marks")
            companion.pairing.state = "paired"  # Paired again, for what follows.
            fake = Controller(capacity=10)
            link_ = Link(companion, fake)
            for _ in range(12):  # 1 and 2 rotate out before the companion copies anything.
                fake.add_shot()
            await link_.open()
            await settled(companion)
            assert await ids(companion, "shots", 1) == set(range(3, 13))
            fake.add_shot()
            fake.add_shot()  # 13 and 14: 3 and 4 rotate out and stay.
            fake.delete("shots", 5)  # The controller's oldest, deleted by the user: not rotation.
            fake.delete("shots", 9)
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "shots", 1) == {3, 4, 6, 7, 8, 10, 11, 12, 13, 14}
            # While the companion is away: a record made and deleted before it was copied is never
            # copied; the oldest deleted, then passed by rotation, is still a deletion.
            link_.close()
            made = fake.add_shot()
            fake.delete("shots", made)
            fake.delete("shots", min(fake.stores["shots"]))
            for _ in range(4):  # 7 rotates out after 6 was deleted.
                fake.add_shot()
            await link_.open()
            await settled(companion)
            held = await ids(companion, "shots", 1)
            assert made not in held, held
            assert 6 not in held, held
            assert {3, 4, 7, 8} <= held, held
            # A Clear while away: every generation of that store goes, nothing of the other (AC5,
            # AC6).
            fake.add_activation()
            await fake.notice(companion)
            await settled(companion)
            link_.close()
            fake.clear("shots")
            fake.add_shot()
            await link_.open()
            await settled(companion)
            assert await sql(
                companion, "select generation, id from archive_records where store = 'shots'"
            ) == [(2, 1)]
            assert await ids(companion, "history") == {1}
            assert said("shot history was cleared on the controller") == 1
            assert not await sql(companion, "select * from archive_traces where generation = 1")
            # A factory reset keeps the count: the history closes and stays (D9)...
            fake.factory_reset()
            fake.add_shot()
            await fake.notice(companion)
            await settled(companion)
            assert await sql(
                companion,
                "select generation, id from archive_records where store = 'shots' "
                "order by generation",
            ) == [(2, 1), (3, 1)]
            # ...and a Clear after it empties every generation, the one before the reset included.
            fake.clear("shots")
            fake.add_shot()
            await fake.notice(companion)
            await settled(companion)
            assert await sql(
                companion, "select generation, id from archive_records where store = 'shots'"
            ) == [(4, 1)]
            # A lower count (a rolled-back controller, a store it had to reset) deletes nothing.
            fake.clears["shots"] = 0
            fake.add_shot()
            await fake.notice(companion)
            await settled(companion)
            assert await ids(companion, "shots", 4) == {1, 2}
            assert said("cleared on the controller") == 2

            # --- The link-frame harness: a recorded session replays into the same archive (X1) --
            link_.close()
            fresh = Controller()
            for n in range(5):
                fresh.add_shot(trace=None if n == 2 else b"T")
                fresh.add_activation()
            recorder = Recorder(companion)
            original = fresh.answer

            async def recording(_: Receiver, frame: Frame) -> None:
                recorder.cases.append({"request": dict(frame), "frames": []})
                await original(recorder, frame)

            monkeypatch.setattr(fresh, "answer", recording)
            await companion.erase("forgotten for the replay")
            companion.pairing.state = "paired"  # Paired again, for what follows.
            link_ = Link(companion, fresh)
            await link_.open()
            await settled(companion)
            link_.close()
            expected = await sql(
                companion,
                "select store, generation, id, ident, body from archive_records "
                "order by store, generation, id",
            )
            await companion.erase("forgotten for the replay")
            companion.pairing.state = "paired"  # Paired again, for what follows.
            assert await replayed(companion, recorder.cases) == len(recorder.cases)
            assert (
                await sql(
                    companion,
                    "select store, generation, id, ident, body from archive_records "
                    "order by store, generation, id",
                )
                == expected
            )

            await pages.close()
            await companion.logs.close()


def test_archive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Companion archive: backfill, catch-up, ratings, deletions followed, rotation, holes,
    generations, Clear and factory reset, Admin-gated delete, access, switch, export and erase."""
    asyncio.run(scenario(monkeypatch))


def test_codec_takes_the_controllers_larger_frames_only() -> None:
    """The codec takes the controller's larger record frames only."""
    key = bytes(32)
    controller, mine = link.FrameCodec(key, send=b"f", receive=b"c"), link.FrameCodec(key)
    rows = "x" * 20000
    big = {"t": "rec", "f": {"rows": rows}}
    inner = mine.decode(controller.encode(big))["f"]
    assert isinstance(inner, dict)
    assert inner["rows"] == rows
    with pytest.raises(ValueError, match="exceeds"):  # A companion frame over 4096 bytes.
        mine.encode({"t": "rx", "pad": "x" * 5000})
