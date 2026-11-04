"""The multiplexer: every screen's views on the companion's one ui-stream session.

The controller keeps one claim and one stream session for all companion
screens. The companion builds every upstream op itself from validated screen
ops, keeps what a late screen needs (merged Home, Settings and Diagnostic
models, the shot card since its last snapshot, the log ring, the record
views' standing pages) and answers each screen from it, so the controller's
cost does not grow with the number of screens. With the shot archive on,
Shots and History come from the archive's replica instead (archive.py), the
whole history in one list; a page whose store cannot catch up in time comes
whole from the controller.
"""

import asyncio
import collections
import json
import sqlite3
from collections.abc import Mapping
from typing import TYPE_CHECKING, Literal, NoReturn, NotRequired, TypedDict, TypeIs, overload

from . import log, pages
from .archive import UnavailableError
from .upstream import Upstream, dumps

if TYPE_CHECKING:
    from aiohttp import web

    from .relay import Relay
    from .service import Companion

U32 = 0xFFFFFFFF
FRAME_BUDGET = 20 * 1024
SCREEN_BYTES = 1 << 20
CARD_FRAMES, CARD_BYTES = 512, 256 * 1024
RECORD_PAGES, RECORD_BYTES = 16, 512 * 1024
LOG_EVENTS, LOG_BYTES = 1024, 512 * 1024
BIND_S, IDLE_S, DIAGNOSTIC_LINGER_S = 5, 5, 5
FETCH_TIMEOUT_S = 120
RESYNC_REPEAT_S, RESYNC_UPSTREAM_S = 30, 60
ATTRIBUTION_S = 1
HISTORY_TYPES = ("shot", "rinse", "other", "power_on", "no_scale_guard_aborted", "backflush")
STATS_RESULTS = ("on_recipe", "fast", "slow")
HISTORY_CAPACITY, HISTORY_PAGE_MAX, SHOT_LOG_CAPACITY = 1000, 120, 1000
STATS_WINDOWS, FILTER_MAX = (10, 50, 100), 8
# Home fields the controller computes per stream session and every page runs locally: a replay
# moves them on (the firmware's src/tests/fixtures/companion_replay_v1.json lists them).
CLOCKS = ("timeUtcSec",)
FINAL = frozenset({"APPLIED", "PERSISTED", "FAILED", "CANCELED"})

# A JSON object as it came, from the controller or a screen: its fields are checked where they are
# read.
type Frame = Mapping[str, object]
# A History or a Stats group: its parameters in View.key's order.
type HistoryKey = tuple[int, int, str, tuple[str, ...]]
type StatsKey = tuple[int, int, str, str, str, int]
type Group = HistoryKey | StatsKey


class Op(TypedDict):
    """A screen's op: a JSON object naming it; its other fields are validated where they are
    read."""

    op: str


class Params(TypedDict, total=False):
    """A record view's parameters: History's or Stats' (DEFAULTS)."""

    offset: int
    limit: int
    dir: str
    types: tuple[str, ...]
    sort: str
    filter: str  # Canonical JSON (_filter).
    window: int


class Parked(TypedDict):
    """A parked page (View._page): its group, tag, boot, epoch and whole rows by id."""

    group: Group
    tag: object
    boot: object
    epoch: object
    rows: dict[int, object]
    request: NotRequired[int]  # The standing subscribe that named its tag.


class Status(TypedDict):
    screens: int
    owner: bool
    views: dict[str, int]


DEFAULTS: dict[str, Params] = {
    "history": {"offset": 0, "limit": 20, "dir": "desc", "types": ()},
    "stats": {
        "offset": 0,
        "limit": 10,
        "sort": "date",
        "dir": "desc",
        "filter": "{}",
        "window": 10,
    },
}
ROWS: dict[str, Literal["records", "rows"]] = {"history": "records", "stats": "rows"}
STORE = {"history": "history", "stats": "shots"}
CAPACITY = {"history": HISTORY_CAPACITY, "stats": SHOT_LOG_CAPACITY}


class InvalidOpError(Exception):
    """An op the controller would reject: the screen is closed with 4003."""


def _now() -> float:
    return asyncio.get_running_loop().time()


def _newer(a: int, b: int) -> bool:
    """a comes after b in uint32 sequence order."""
    return 0 < (a - b) & U32 < 0x80000000


def _reject(_: str) -> NoReturn:
    raise ValueError("not a JSON number")


def _row_id(row: object) -> object:
    """A whole row's id: a History record names it, a Stats row starts with it."""
    return (
        row.get("id")
        if isinstance(row, dict)
        else row[0]
        if isinstance(row, list) and row
        else None
    )


# --- Op validation (the firmware's whitelists and ranges) -------------------------
def _fields(message: Frame, allowed: set[str]) -> None:
    if not set(message) <= allowed:
        raise InvalidOpError


def _number(message: Frame, name: str, low: int, high: int) -> int | None:
    if name not in message:
        return None
    return _integer(message[name], low, high)


def _integer(value: object, low: int, high: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not low <= value <= high  # First: int() cannot take infinity.
        or value != int(value)
    ):
        raise InvalidOpError
    return int(value)


@overload
def _flag(message: Frame, name: str, required: Literal[True]) -> bool: ...
@overload
def _flag(message: Frame, name: str, required: bool = False) -> bool | None: ...
def _flag(message: Frame, name: str, required: bool = False) -> bool | None:
    if name not in message:
        if required:
            raise InvalidOpError
        return None
    value = message[name]
    if not isinstance(value, bool):
        raise InvalidOpError
    return value


def _choice(message: Frame, name: str, choices: tuple[str, ...]) -> str | None:
    if name not in message:
        return None
    value = message[name]
    if not isinstance(value, str) or value not in choices:  # Every choice is a str.
        raise InvalidOpError
    return value


def _list(value: object, limit: int) -> list[object]:
    if not isinstance(value, list) or len(value) > limit:
        raise InvalidOpError
    return value


def _types(message: Frame) -> tuple[str, ...] | None:
    if "types" not in message:
        return None
    names = _list(message["types"], len(HISTORY_TYPES))
    if not all(isinstance(name, str) and name in HISTORY_TYPES for name in names):
        raise InvalidOpError
    return tuple(name for name in HISTORY_TYPES if name in names)


def _filter(message: Frame) -> str | None:
    """The Stats filter as canonical JSON (empty lists and bad:false dropped), or None when
    absent."""
    if "filter" not in message:
        return None
    value = message["filter"]
    if not isinstance(value, dict) or not set(value) <= {"result", "preset", "scale", "bad"}:
        raise InvalidOpError
    canonical: dict[str, object] = {}
    if _flag(value, "bad"):
        canonical["bad"] = True
    results = _list(value.get("result", []), FILTER_MAX)
    if not all(isinstance(name, str) and name in STATS_RESULTS for name in results):
        raise InvalidOpError
    if results:
        canonical["result"] = [name for name in STATS_RESULTS if name in results]
    for name, high in (("preset", 255), ("scale", U32)):
        items = _list(value.get(name, []), FILTER_MAX)
        numbers = sorted({_integer(item, 0, high) for item in items})
        if numbers:
            canonical[name] = numbers
    return dumps(dict(sorted(canonical.items())))


def _is_op(value: object) -> TypeIs[Op]:
    return isinstance(value, dict) and isinstance(value.get("op"), str)


def parse(text: str) -> Op:
    """A screen's op, validated; ValueError when it is not a JSON object."""
    message = json.loads(text, parse_constant=_reject)
    if not _is_op(message):
        raise ValueError("not an op")
    return message


# --- Merged `changes` models (Home, Settings, Diagnostic) [D2] -----------------------
class Merged:
    """A flat `changes` map: a snapshot replaces it, an increment updates it in place.

    A key replaces its descendants ("a" drops "a.b"), so replaying the map in order
    rebuilds exactly the model the frames built, and keys keep their first position.
    """

    boot: object
    changes: dict[str, object]
    clock_at: dict[str, float]  # When each of CLOCKS arrived.

    def __init__(self) -> None:
        self.boot, self.changes, self.ready, self.clock_at = None, {}, False, {}

    def apply(self, frame: Frame) -> bool:
        changes = frame.get("changes")
        if not isinstance(changes, dict):
            return False
        if frame.get("snapshot") is True:
            self.boot, self.changes, self.ready = frame.get("boot"), {}, True
        elif not self.ready:
            return False
        for key, value in changes.items():
            prefix = key + "."
            for stale in [name for name in self.changes if name.startswith(prefix)]:
                del self.changes[stale]
            self.changes[key] = value
        self.clock_at.update((key, _now()) for key in CLOCKS if key in changes)
        return True

    def clear(self) -> None:
        self.boot, self.changes, self.ready = None, {}, False

    def frames(self, kind: str, extra: Frame | None = None, split: bool = False) -> list[str]:
        """The model as one synthesized snapshot, or split into ≤ FRAME_BUDGET frames."""
        head = {"v": 1, "type": kind, "boot": self.boot, "snapshot": True}
        if not split:
            return [dumps({**head, "changes": self.changes, **(extra or {})})]
        frames: list[dict[str, object]]
        part: dict[str, object]
        frames, part, size = [], {}, 0
        for key, value in self.changes.items():
            item = len(dumps({key: value}))
            if part and size + item > FRAME_BUDGET:
                frames.append(part)
                part, size = {}, 0
            part[key], size = value, size + item
        frames.append(part)
        return [dumps({**head, "changes": frames[0]})] + [
            dumps({"type": kind, "changes": changes}) for changes in frames[1:]
        ]


# --- Screens ----------------------------------------------------------------------------
class Record:
    """One screen's History or Stats view: its parameters, group and request id."""

    def __init__(self, kind: str) -> None:
        self.params = DEFAULTS[kind].copy()
        self.group: Group | None = None  # Parameter group while subscribed.
        self.request, self.synced = 0, False
        # Served by the archive's replica (never by an upstream window), and the standing page's
        # serial.
        self.replica, self.serial = False, 0


class Screen:
    id: str | None  # Its browser's client id, once bound.
    stats_map: dict[object, int]  # The controller's Stats seq -> this screen's.
    queue: collections.deque[str]

    def __init__(self, mux: Mux, ws: web.WebSocketResponse, addr: str) -> None:
        self.mux, self.ws, self.addr = mux, ws, addr
        self.id, self.bound, self.closed = None, False, False
        self.presets_tag: int | None = None
        self.home = self.card = False  # Holds a snapshot of each.
        self.settings = self.settings_synced = False
        self.diagnostic = self.diagnostic_synced = False
        self.log, self.log_after, self.log_owed, self.log_invalid, self.log_missed = (
            False,
            0,
            False,
            False,
            0,
        )
        self.records = {"history": Record("history"), "stats": Record("stats")}
        self.stats_seq, self.stats_map = 0, {}
        self.until, self.hidden = 0.0, False
        self.active_at = self.resync_at = float("-inf")
        self.queue, self.queued = collections.deque(), 0
        self.wake = asyncio.Event()

    def send(self, text: str) -> None:
        if self.closed:
            return
        self.queue.append(text)
        self.queued += len(text)
        if self.queued > SCREEN_BYTES:  # A screen that cannot keep up reconnects quietly.
            log("a screen fell 1 MiB behind; closing it so it reconnects")
            self.close(4002)
            return
        self.wake.set()

    def close(self, code: int, reason: str = "") -> None:
        if not self.closed:
            self.closed = True
            self.wake.set()
            _ = self.mux.companion.spawn(self.ws.close(code=code, message=reason.encode()))

    async def writer(self) -> None:
        while not self.closed:
            await self.wake.wait()
            self.wake.clear()
            while self.queue and not self.closed:
                text = self.queue.popleft()
                self.queued -= len(text)
                try:
                    await self.ws.send_str(text)
                except ConnectionError, RuntimeError:
                    self.closed = True
                    return

    def seconds(self, now: float) -> int:
        return max(0, int(self.until - now + 0.999))


# --- History and Stats ---------------------------------------------------------------------
class Fetch:
    """One upstream fetch: a group's first page and/or screens' own windows, coalesced."""

    targets: list[tuple[Screen, int]]  # Screens' own windows: the screen and its request.
    timer: asyncio.TimerHandle | None

    def __init__(
        self, key: Group, group: Group | None = None, target: tuple[Screen, int] | None = None
    ) -> None:
        self.key, self.group, self.targets = key, group, [target] if target else []
        self.id, self.timer, self.started = 0, None, False


class View:
    """History or Stats: one standing upstream window for the owner group, fetches for the others.

    When no screen holds the view its last whole standing page stays parked: the next subscribe to
    that group names the page's tag, and the controller's kept answer (rows as bare ids) is made
    whole from it before any screen sees it.
    """

    standing: Group | None  # The owner group's, while the upstream window stands.
    parked: Parked | None
    epoch: object  # The standing window's store epoch, once it answered.
    buffer: list[Frame]
    buffer_state: str  # waiting, valid or over
    pages: dict[Group, tuple[list[Frame], bool]]
    queue: list[Fetch]
    inflight: Fetch | None

    def __init__(self, mux: Mux, kind: str) -> None:
        self.mux, self.kind = mux, kind
        self.next_id, self.standing, self.parked, self.inflight = 0, None, None, None
        self.clear()

    def clear(self, park: bool = True) -> None:
        """Forget the standing window; with `park` its last whole page stays for the next
        subscribe."""
        if self.inflight and self.inflight.timer:
            self.inflight.timer.cancel()
        self.parked = (self._page() or self.parked) if park else None
        self.standing, self.request, self.epoch, self.awaiting = None, 0, None, False
        self.buffer, self.buffer_bytes, self.buffer_pages, self.buffer_state = [], 0, 0, "waiting"
        self.pages = {}  # Non-owner group -> (frames of its last page, complete)
        self.queue, self.inflight = [], None

    def _id(self) -> int:
        self.next_id = self.next_id % U32 + 1
        return self.next_id

    # Parameters and ops
    def key(self, params: Params) -> Group:
        if self.kind == "history":
            return (params["offset"], params["limit"], params["dir"], params["types"])
        return (
            params["offset"],
            params["limit"],
            params["sort"],
            params["dir"],
            params["filter"],
            params["window"],
        )

    def op(self, key: Group, request: int, fetch: bool = False) -> dict[str, object]:
        op: dict[str, object] = {"op": self.kind, "on": True}
        if fetch:
            op["fetch"] = True
        # The whole history may page past the controller's own records; it answers those empty.
        key = (min(key[0], CAPACITY[self.kind]), *key[1:])
        if len(key) == 4:  # History's group; Stats' has six parameters.
            offset, limit, direction, types = key
            op.update(request=request, offset=offset, limit=limit, dir=direction)
            if types or fetch:
                op["types"] = list(types)
        else:
            offset, limit, sort, direction, criteria, window = key
            op.update(request=request, offset=offset, limit=limit, sort=sort, dir=direction)
            if criteria != "{}" or fetch:
                op["filter"] = json.loads(criteria)
            if window != 10 or fetch:  # A fetch names its window: its header follows it [D3].
                op["window"] = window
        return op

    def standing_op(self, standing: Group) -> dict[str, object]:
        """The standing subscribe (to `standing`, the view's): on the parked page's group it names
        that page's tag."""
        op = self.op(standing, self.request)
        if self.parked and self.parked["group"] == standing:
            op["tag"], self.parked["request"] = self.parked["tag"], self.request
        return op

    def members(self, group: Group | None) -> list[Screen]:
        return [
            screen
            for screen in self.mux.bound()
            if screen.records[self.kind].group == group and not screen.records[self.kind].replica
        ]

    def _start(self, frame: Frame) -> bool:
        return self.kind == "history" or frame.get("rowBase") == 0

    def deliver(
        self, screen: Screen, frame: Frame, request: int, snapshot: bool | None = None
    ) -> None:
        out = dict(frame, request=request)
        if self.kind == "stats":  # Each screen sees its own monotonic page sequence.
            if frame.get("rowBase") == 0:
                screen.stats_seq += 1
                screen.stats_map[frame.get("seq")] = screen.stats_seq
                if len(screen.stats_map) > 8:
                    del screen.stats_map[next(iter(screen.stats_map))]
            if frame.get("seq") not in screen.stats_map:
                return
            out["seq"] = screen.stats_map[frame.get("seq")]
        if snapshot and self._start(frame):
            out["snapshot"] = True
        screen.send(dumps(out))

    # Screen ops
    def on_op(self, screen: Screen, message: Frame) -> None:
        on = _flag(message, "on", required=True)
        request = _number(message, "request", 1, U32)
        tag = _number(message, "tag", 1, U32)
        offset = _number(message, "offset", 0, U32)
        limit = _number(
            message, "limit", 1, HISTORY_PAGE_MAX if self.kind == "history" else SHOT_LOG_CAPACITY
        )
        direction = _choice(message, "dir", ("asc", "desc"))
        fetch = _flag(message, "fetch")
        record = screen.records[self.kind]
        given: Params = {}  # The parameters the op names, in DEFAULTS' order.
        if offset is not None:
            given["offset"] = offset
        if limit is not None:
            given["limit"] = limit
        if self.kind == "history":
            _fields(
                message, {"op", "on", "offset", "limit", "dir", "fetch", "request", "types", "tag"}
            )
            types = _types(message)
            if direction is not None:
                given["dir"] = direction
            if types is not None:
                given["types"] = types
            replaced: Params = {"types": ()}
        else:
            _fields(
                message,
                {
                    "op",
                    "on",
                    "offset",
                    "limit",
                    "sort",
                    "dir",
                    "fetch",
                    "request",
                    "filter",
                    "window",
                    "tag",
                },
            )
            window = _number(message, "window", 0, U32)
            if window is not None and window not in STATS_WINDOWS:
                raise InvalidOpError
            sort, criteria = _choice(message, "sort", ("date", "rating")), _filter(message)
            if sort is not None:
                given["sort"] = sort
            if direction is not None:
                given["dir"] = direction
            if criteria is not None:
                given["filter"] = criteria
            if window is not None:
                given["window"] = window
            replaced = {"filter": "{}", "window": 10}
        if not on:
            if set(message) - {"op", "on"}:
                raise InvalidOpError
            self.unsubscribe(screen)
        elif (
            fetch
        ):  # Without a view of its own it is Home's rows-only Stats fetch, as on the controller.
            if offset is None or tag is not None or (self.kind == "stats" and "window" in given):
                raise InvalidOpError
            self.fetch(screen, request or 0, {**record.params, **given})
        elif (
            self.kind == "stats"
            and record.group is not None
            and set(given) == {"window"}
            and request is None
            and tag is None
        ):
            self.subscribe(
                screen,
                record.request,
                {**record.params, "window": given["window"]},
                window_only=True,
            )
        else:
            self.subscribe(
                screen, request or 0, {**record.params, **replaced, **given}, tag=tag or 0
            )

    # The replica: pages from the archive's copy, no upstream window
    def fetch(self, screen: Screen, request: int, params: Params) -> None:
        if self.mux.companion.archive.serving():
            _ = self.mux.companion.spawn(self._serve(screen, request, params, False, fetch=True))
        else:
            self.mux.attribute(
                screen
            )  # What it leaves out is its own window's, not the controller's.
            self._queue(self.key(params), target=(screen, request))

    def refresh(self) -> None:
        """The copy changed (or the active preset, for Stats, or Home named the controller's boot):
        every page it serves is built again, superseding one still being built; a screen with none
        yet gets its snapshot."""
        for screen in self.mux.bound():
            record = screen.records[self.kind]
            if record.replica and record.group is not None:
                record.serial += 1
                _ = self.mux.companion.spawn(
                    self._serve(screen, record.request, record.params, not record.synced)
                )

    async def _serve(
        self,
        screen: Screen,
        request: int,
        params: Params,
        snapshot: bool,
        fetch: bool = False,
        tag: int = 0,
    ) -> None:
        """One page from the replica; when its store cannot catch up in time (link down, no answer
        within CATCH_UP_S) the page comes whole from the controller instead, never mixed."""
        archive, record = self.mux.companion.archive, screen.records[self.kind]
        serial = record.serial
        page = header = None
        ready = await archive.ready(STORE[self.kind])
        if ready and self.mux.home.boot is None and not fetch:
            # A page carries the controller's boot: it goes with Home's snapshot (Mux._on_home).
            return
        if ready and self.mux.home.boot is not None:
            try:
                page = await archive.page(
                    STORE[self.kind],
                    self._query(params),
                    params["offset"],
                    params["limit"],
                    self.mux.home.boot,
                )
                if self.kind == "stats" and (not fetch or record.group is not None):
                    header = (
                        await archive.header(
                            params["window"], self.mux.active_preset(), page["epoch"], ((), (), ())
                        )
                    )[0]
            except (sqlite3.Error, UnavailableError, ValueError) as error:
                log(
                    f"the archive could not build a {self.kind} page ({error}); "
                    "the controller sends it"
                )
                page = None
        if screen.closed or (not fetch and (record.serial != serial or not record.replica)):
            return
        if page is None:
            archive.counters["fallbacks"] += 1
            if fetch:
                self.mux.attribute(screen)
                self._queue(self.key(params), target=(screen, request))
            else:
                self._upstream_subscribe(screen, request, params)
            return
        archive.counters["served"] += 1
        if self.kind == "stats":
            screen.stats_seq += 1
            frames, tag = pages.stats_frames(page, screen.stats_seq, request, snapshot, header, tag)
        else:
            frame, tag = pages.history_frame(page, request, snapshot, tag)
            frames = [frame]
        if (
            page["archive"] is not None
        ):  # Rows only the archive keeps: its histories and gaps name them.
            frames[0] = frames[0][:-1] + ',"archive":' + dumps(page["archive"]) + "}"
        for text in frames:
            screen.send(text)
        if not fetch:
            record.synced = True

    def _query(self, params: Params) -> dict[str, object]:
        if self.kind == "history":
            return {"dir": params["dir"], "types": list(params["types"])}
        criteria = json.loads(params["filter"])
        return {
            "sort": params["sort"],
            "dir": params["dir"],
            "bad": criteria.get("bad", False),
            "result": criteria.get("result", []),
            "preset": criteria.get("preset", []),
            "scale": criteria.get("scale", []),
        }

    def subscribe(
        self, screen: Screen, request: int, params: Params, window_only: bool = False, tag: int = 0
    ) -> None:
        record = screen.records[self.kind]
        if self.mux.companion.archive.serving():
            record.params, record.group, record.request = params, self.key(params), request
            record.replica, record.synced = True, False
            record.serial += 1
            self.mux.attribute(screen)
            self.settle()  # Its upstream window, if it held one, is no longer its.
            _ = self.mux.companion.spawn(
                self._serve(screen, request, params, not window_only, tag=0 if window_only else tag)
            )
            return
        self._upstream_subscribe(screen, request, params, window_only)

    def _upstream_subscribe(
        self, screen: Screen, request: int, params: Params, window_only: bool = False
    ) -> None:
        record = screen.records[self.kind]
        record.replica = False
        old, group = record.group, self.key(params)
        # Nobody else holds the standing window: this screen may move it.
        alone = self.standing is not None and not any(
            s is not screen for s in self.members(self.standing)
        )
        record.params, record.group, record.request = params, group, request
        self._forget(old)
        self.mux.attribute(screen)
        if self.standing is None:
            record.synced = False
            self._subscribe_upstream(group)
        elif window_only and old == self.standing and alone:
            self.standing = group  # The header follows; the held rows stay [Stats window-only].
            self.mux.up({"op": "stats", "on": True, "window": params["window"]})
        elif group == self.standing:
            record.synced = False
            self._replay(screen)
        elif alone:
            record.synced = False
            self._subscribe_upstream(group)
        else:
            record.synced = False
            self._join(screen, group)

    def unsubscribe(self, screen: Screen, settle: bool = True) -> None:
        record = screen.records[self.kind]
        old = record.group
        record.group, record.synced, record.replica = None, False, False
        self._forget(old)
        record.serial += 1
        for fetch in [self.inflight, *self.queue]:
            if fetch:
                fetch.targets = [target for target in fetch.targets if target[0] is not screen]
        if settle:
            self.settle()

    def _forget(self, group: Group | None) -> None:
        """A group's last screen left: its page copy goes, once no fetch is still filling it."""
        if (
            group is not None
            and group != self.standing
            and not self.members(group)
            and not (self.inflight and self.inflight.group == group)
        ):
            self.pages.pop(group, None)

    def resync(self, screen: Screen) -> None:
        record = screen.records[self.kind]
        if record.group is None:
            return
        record.synced = False
        if record.replica:
            record.serial += 1
            _ = self.mux.companion.spawn(self._serve(screen, record.request, record.params, True))
        elif record.group == self.standing:
            self._replay(screen)
        else:
            self._join(screen, record.group)

    def settle(self) -> None:
        """After a screen left: promote another group, or end the upstream window."""
        screens = [
            screen
            for screen in self.mux.bound()
            if screen.records[self.kind].group is not None and not screen.records[self.kind].replica
        ]
        if not screens:
            if self.standing is not None:
                self.mux.up({"op": self.kind, "on": False})
                self.clear()
            return
        if not any(screen.records[self.kind].group == self.standing for screen in screens):
            newest = max(screens, key=lambda screen: screen.active_at)
            group = newest.records[self.kind].group
            if group is not None:  # Each of `screens` holds one.
                self._subscribe_upstream(group)

    def _subscribe_upstream(self, group: Group) -> None:
        self.standing, self.request, self.awaiting = group, self._id(), True
        self.buffer, self.buffer_bytes, self.buffer_pages, self.buffer_state = [], 0, 0, "waiting"
        self.pages.pop(group, None)
        for screen in self.members(group):
            screen.records[self.kind].synced = False
        self.dropped()
        self.mux.up(self.standing_op(group))

    def dropped(self) -> None:
        """An upstream subscribe or resync drops the controller's fetch: ask again after its
        snapshot."""
        self.awaiting = True
        if self.inflight is not None:
            fetch, self.inflight = self.inflight, None
            if fetch.timer:
                fetch.timer.cancel()
            fetch.started = False
            self.queue.insert(0, fetch)

    def upstream_resync(self) -> None:
        self.buffer, self.buffer_bytes, self.buffer_pages, self.buffer_state = [], 0, 0, "waiting"
        for screen in self.members(self.standing):
            screen.records[self.kind].synced = False
        self.dropped()

    def _replay(self, screen: Screen) -> None:
        record = screen.records[self.kind]
        if self.buffer_state == "valid" and self.buffer:
            for frame in self.buffer:
                self.deliver(screen, frame, record.request)
            record.synced = True
        elif self.buffer_state == "over" and self.standing is not None:
            # Over the bound: one fresh snapshot, without a tag.
            self._subscribe_upstream(self.standing)

    def _join(self, screen: Screen, group: Group) -> None:
        frames, complete = self.pages.get(group, ((), False))
        if complete:
            record = screen.records[self.kind]
            for frame in frames:
                self.deliver(screen, frame, record.request, snapshot=True)
            record.synced = True
        else:
            self._queue(group, group=group)

    # Fetch queue: one in flight, identical ones coalesced
    def _queue(
        self,
        key: Group,
        group: Group | None = None,
        target: tuple[Screen, int] | None = None,
        behind_inflight: bool = False,
    ) -> None:
        candidates = (
            self.queue
            if behind_inflight
            else [*([self.inflight] if self.inflight else ()), *self.queue]
        )
        for fetch in candidates:
            if fetch.key == key:
                fetch.group = fetch.group or group
                if target:
                    fetch.targets.append(target)
                return
        self.queue.append(Fetch(key, group, target))
        self.pump()

    def _wanted(self, fetch: Fetch) -> list[tuple[Screen, int]] | bool | list[Screen]:
        return fetch.targets or (
            fetch.group is not None and fetch.group != self.standing and self.members(fetch.group)
        )

    def pump(self) -> None:
        if self.inflight is not None or self.awaiting or self.mux.upstream.state != "open":
            return
        while self.queue:
            fetch = self.queue.pop(0)
            if self._wanted(fetch):
                fetch.id = self._id()
                fetch.timer = asyncio.get_running_loop().call_later(
                    FETCH_TIMEOUT_S, self._expired, fetch
                )
                self.inflight = fetch
                self.mux.up(self.op(fetch.key, fetch.id, fetch=True))
                return

    def _expired(self, fetch: Fetch) -> None:
        """Stats fetches wait silently while a shot's trace capture is open; never resent."""
        if self.inflight is fetch:
            self.inflight = None
            self.pump()

    # Upstream frames
    def on_frame(self, frame: Frame) -> None:
        request = frame.get("request")
        if not isinstance(request, int) or (
            self.kind == "stats" and not isinstance(frame.get("seq"), int)
        ):
            return
        if self.standing is not None and request == self.request:
            self._standing(frame)
        elif self.inflight is not None and request == self.inflight.id:
            self._fetched(self.inflight, frame)

    def _standing(self, frame: Frame) -> None:
        if self.parked and self.parked.get("request") == self.request:
            whole = self._unpark(self.parked, frame)
            if whole is None:
                return
            frame = whole
        start, snapshot = self._start(frame), frame.get("snapshot") is True
        if start and snapshot:
            self.buffer, self.buffer_bytes, self.buffer_pages, self.buffer_state = [], 0, 0, "valid"
            self.awaiting = False
        if self.buffer_state == "valid":
            self.buffer.append(frame)
            self.buffer_bytes += len(dumps(frame))
            self.buffer_pages += start
            if self.buffer_pages > RECORD_PAGES or self.buffer_bytes > RECORD_BYTES:
                self.buffer, self.buffer_bytes, self.buffer_state = [], 0, "over"
        if start:
            epoch = frame.get("epoch")
            if self.epoch is not None and epoch != self.epoch:
                self._epoch_moved()
                if (
                    self.kind == "stats"
                ):  # A new shot while a screen shows Stats: the archive catches up now.
                    self.mux.companion.archive.refresh("shots", epoch)
            self.epoch = epoch
        for screen in self.members(self.standing):
            record = screen.records[self.kind]
            if record.synced or (start and snapshot):
                self.deliver(screen, frame, record.request)
                record.synced = True
        self.pump()

    # Parked page
    def _page(self) -> Parked | None:
        """The last whole standing page as a parked page: its group, tag, boot, epoch and rows by
        id."""
        if self.standing is None or self.buffer_state != "valid" or not self.buffer:
            return None
        known: dict[int, object]
        page: Parked | None
        known, page, done = {}, None, False
        for frame in self.buffer:  # A valid buffer starts with a page's first frame.
            if self._start(frame):
                page = {
                    "group": self.standing,
                    "tag": frame.get("tag"),
                    "boot": frame.get("boot"),
                    "epoch": frame.get("epoch"),
                    "rows": {},
                }
            rows = frame.get(ROWS[self.kind]) or []
            if page is None or not isinstance(rows, list):
                return None
            for row in rows:
                whole = known.get(row) if type(row) is int else row
                rid = _row_id(whole)
                if type(rid) is not int:
                    return None
                known[rid] = page["rows"][rid] = whole
            done = self.kind == "history" or frame.get("more") is False
        if page is None:
            return None
        tag = page["tag"]
        return page if done and type(tag) is int and 0 < tag <= U32 else None

    def _unpark(self, parked: Parked, frame: Frame) -> Frame | None:
        """The answer to the `parked` page's tag, its bare ids whole again from that page. One
        answer revalidates it; ids it cannot resolve (or another boot) ask for the page again
        without the tag."""
        name = ROWS[self.kind]
        rows = value if isinstance(value := frame.get(name), list) else []
        if self.kind == "history" or frame.get("more") is False:
            self.parked = None
        if not any(type(row) is int for row in rows):
            return frame
        if frame.get("boot") == parked["boot"] and all(
            type(row) is not int or row in parked["rows"] for row in rows
        ):
            return {
                **frame,
                name: [parked["rows"][row] if type(row) is int else row for row in rows],
            }
        self.parked = None
        if self.standing is not None:  # It answers the standing subscribe.
            self._subscribe_upstream(self.standing)
        return None

    def unpark(self, epoch: object = None) -> None:
        """Drop the parked page, or with `epoch` only when its store moved, unless a revalidation
        runs."""
        parked = self.parked
        if (
            parked
            and parked.get("request") != self.request
            and (epoch is None or epoch != parked["epoch"])
        ):
            self.parked = None

    def _epoch_moved(self) -> None:
        """The store changed: every other group's page is out of date; one fetch per group."""
        self.pages.clear()
        groups = {
            group
            for screen in self.mux.bound()
            if (group := screen.records[self.kind].group) is not None
        } - {self.standing}
        for group in sorted(groups, key=repr):
            self._queue(group, group=group, behind_inflight=True)

    def _fetched(self, fetch: Fetch, frame: Frame) -> None:
        """A frame answering `fetch`, the one in flight."""
        start = self._start(frame)
        done = self.kind == "history" or frame.get("more") is False
        if start:
            fetch.started = True
        if fetch.started and fetch.group is not None and fetch.group != self.standing:
            frames = [frame] if start else [*self.pages.get(fetch.group, ((), False))[0], frame]
            self.pages[fetch.group] = (frames, done)
            for screen in self.members(fetch.group):
                record = screen.records[self.kind]
                if start or record.synced:
                    self.deliver(screen, frame, record.request, snapshot=True)
                    record.synced = record.synced or start
        if fetch.started:
            for screen, request in fetch.targets:
                if not screen.closed:
                    self.deliver(screen, frame, request)
        if done:
            if fetch.timer:
                fetch.timer.cancel()
            self.inflight = None
            self._forget(fetch.group)
            self.pump()


# --- The multiplexer ---------------------------------------------------------------------------
class Mux:
    idle: asyncio.TimerHandle | None
    linger: asyncio.TimerHandle | None
    settings_tag: object  # The Settings model's tag, as the controller named it.
    card: list[str]
    ring: collections.deque[tuple[int, object, int]]  # The log: (sequence, event, its size).
    log_meta: dict[str, object] | None
    alive_waiters: list[Screen]

    def __init__(self, companion: Companion, relay: Relay) -> None:
        self.companion, self.relay = companion, relay
        self.screens: set[Screen] = set()
        # Browser ids whose relayed claim (or sign-in) the controller accepted.
        self.claimed: set[str] = set()
        self.upstream = Upstream(companion, relay, self)
        self.views = {"history": View(self, "history"), "stats": View(self, "stats")}
        self.home, self.settings, self.diagnostic = Merged(), Merged(), Merged()
        self.idle = self.linger = None
        self.changed = asyncio.Event()
        # (time, screen) of ops sent upstream for a screen
        self.attributed: collections.deque[tuple[float, Screen]] = collections.deque(maxlen=64)
        self._reset()

    def _reset(self, park: bool = True) -> None:
        self.home.clear()
        self.settings.clear()
        self.diagnostic.clear()
        self.settings_tag, self.settings_on, self.diagnostic_on, self.log_on = (
            None,
            False,
            False,
            False,
        )
        self.card, self.card_bytes, self.card_valid, self.card_live = [], 0, False, False
        self.card_resync_at = self.resync_at = float("-inf")
        self.ring, self.ring_bytes, self.log_meta, self.log_more = (
            collections.deque(),
            0,
            None,
            False,
        )
        self.alive_waiters = []
        for view in self.views.values():
            view.clear(park)

    def bound(self) -> list[Screen]:
        return [screen for screen in self.screens if screen.bound and not screen.closed]

    def status(self) -> Status:
        screens = self.bound()
        views = {
            "home": len(screens),
            "settings": sum(screen.settings for screen in screens),
            "diagnostic": sum(screen.diagnostic for screen in screens),
            "log": sum(screen.log for screen in screens),
        }
        for kind in self.views:
            views[kind] = sum(screen.records[kind].group is not None for screen in screens)
        return {"screens": len(screens), "owner": bool(self.claimed), "views": views}

    # --- Upstream ops ----------------------------------------------------------------
    def up(self, op: Frame) -> bool:
        return self.upstream.send(op)

    def attribute(self, screen: Screen) -> None:
        """Note that this screen's op led to upstream ops (a 4003 then names it)."""
        now = _now()
        screen.active_at = now
        self.attributed.append((now, screen))

    def bind_ops(self) -> list[dict[str, object]]:
        screens = self.bound()
        ops: list[dict[str, object]] = []
        self.settings_on = any(screen.settings for screen in screens)
        if self.settings_on:
            ops.append({"op": "settings", "on": True})
        self.diagnostic_on = any(screen.diagnostic for screen in screens)
        if self.diagnostic_on:
            ops.append({"op": "diagnostic", "on": True})
        self.log_on = any(screen.log for screen in screens)
        if self.log_on:
            ops.append({"op": "log", "on": True, "after": self.ring[-1][0] if self.ring else 0})
        for view in self.views.values():
            if view.standing is not None:
                view.awaiting = True
                ops.append(view.standing_op(view.standing))
        return ops

    def upstream_opened(self) -> None:
        for view in self.views.values():
            view.pump()
        if not self.bound() and not self.idle:
            self.idle = asyncio.get_running_loop().call_later(IDLE_S, self._idle)

    def upstream_closed(self, code: int | None, deliberate: bool, heard: bool = False) -> None:
        screens = list(self.screens)
        if (
            code == 4001
        ):  # The controller gave the Web UI to a direct browser, or forgot the claim (reboot).
            self.claimed.clear()
            log(
                "the controller ended the companion's Web UI session; "
                "every companion screen offers Reload"
            )
            for screen in screens:
                screen.close(4001, "direct" if heard else "")
        elif (
            code == 4003
        ):  # An op failed the controller's validation: name the screens that sent one.
            log("the controller rejected an op on the shared live updates")
            recent = {screen for at, screen in self.attributed if _now() - at <= ATTRIBUTION_S}
            for screen in screens:
                screen.close(4003 if screen in recent else 4002)
        elif not deliberate:
            if code is not None:  # A failed open is already named where it failed.
                log(
                    f"the shared live updates ended (code {code}, "
                    f"{'heard' if heard else 'never heard'}); the screens reconnect"
                )
            for screen in screens:
                screen.close(4002 if code == 4002 else 1001)
        self.attributed.clear()
        self._reset(
            park=deliberate
        )  # An idle close keeps the parked pages; a lost session may be a reboot.

    def replica_changed(self, store: str | None = None) -> None:
        """The replica's copy changed or stopped serving: the pages it serves are built again."""
        for kind, view in self.views.items():
            if store in (None, STORE[kind]):
                view.refresh()

    def active_preset(self) -> object:
        """The active preset, from Home's model: the Stats header's "This preset" chart follows
        it."""
        changes = self.home.changes
        if "presets.activeId" in changes:
            return changes["presets.activeId"]
        presets = changes.get("presets")
        return presets.get("activeId", 0) if isinstance(presets, dict) else 0

    def unpark(self, notice: Frame | None = None) -> None:
        """Drop the parked pages (Forget, a link reset), or with an `rs` notice those whose store
        moved."""
        for kind, key in (("stats", "sh"), ("history", "hi")):
            if notice is None or type(notice.get(key)) is int:
                self.views[kind].unpark(None if notice is None else notice[key])

    def signed_out(self, client: str | None) -> None:
        """This browser's session ended: its claim goes and so do its pages' live updates."""
        self.claimed.discard(client or "")
        for screen in list(self.screens):
            if screen.id == client:
                screen.close(4001)

    def relay_ended(self) -> None:
        """The relay session ended (a Forget, an erase, the Web UI turned off): no screen stays."""
        self.claimed.clear()
        for screen in list(self.screens):
            screen.close(4001)
        self.upstream.close()

    def takeover(self) -> None:
        """A relayed call answered UI_TAKEN_OVER: the claim moved, not always to a direct page."""
        self.claimed.clear()
        for screen in list(self.screens):
            screen.close(4001)
        self.upstream.close()

    # --- Screens ---------------------------------------------------------------------
    def connect(self, ws: web.WebSocketResponse, addr: str) -> Screen:
        screen = Screen(self, ws, addr)
        self.screens.add(screen)
        if self.idle:
            self.idle.cancel()
            self.idle = None

        def unbound() -> None:
            if not screen.bound:
                screen.close(1008)

        loop = asyncio.get_running_loop()
        loop.call_later(BIND_S, unbound)
        _ = self.companion.spawn(screen.writer())
        return screen

    def disconnect(self, screen: Screen) -> None:
        screen.closed = True
        screen.wake.set()
        self.screens.discard(screen)
        if not screen.bound:
            return
        screen.bound = screen.log = screen.diagnostic = False
        remaining = bool(
            self.bound()
        )  # The last screen leaving: the session closes soon, nothing to send.
        for view in self.views.values():
            view.unsubscribe(screen, settle=remaining)
        if remaining:
            self._settle()
            self.upstream.sync_activity()
        else:
            self.idle = asyncio.get_running_loop().call_later(IDLE_S, self._idle)

    def _settle(self) -> None:
        """Drop upstream subscriptions no screen holds any more."""
        for view in self.views.values():
            view.settle()
        self._log_settle()
        self._diagnostic_settle()

    def _idle(self) -> None:
        self.idle = None
        if not self.bound():
            self.upstream.close()  # The claim stays: the next screen binds a new session.

    def on_message(self, screen: Screen, text: str) -> None:
        try:
            message = parse(text)
        except ValueError:
            screen.close(1007)
            return
        op = message["op"]
        try:
            if not screen.bound:
                if op != "bind":
                    raise ValueError
                self._bind(screen, message)
            else:
                self._op(screen, message)
        except ValueError:
            screen.close(1008)
        except InvalidOpError:
            log(
                f"a screen's {op[:12]} op failed validation; closing it so it resets its list views"
            )
            screen.close(4003)

    def _bind(self, screen: Screen, message: Op) -> None:
        client = message.get("client")
        if not isinstance(client, str) or client not in self.claimed:
            screen.close(4001)
            return
        if (
            self.upstream.state == "closing"
        ):  # Caught the idle close: reconnect quietly in a moment.
            screen.close(4002)
            return
        screen.id, screen.bound = client, True
        screen.active_at = _now()
        tag = message.get("presetsTag")
        if isinstance(tag, int) and not isinstance(tag, bool) and 1 <= tag <= U32:
            screen.presets_tag = tag
        self._send_home(screen, presets=True)
        self._send_card(screen)
        ops = message.get("ops", [])
        if not isinstance(ops, list):
            raise InvalidOpError
        for op in ops:
            if not _is_op(op) or op["op"] == "bind":
                raise InvalidOpError
            self._op(screen, op)
        self._settle()
        self.upstream.open()

    def _op(self, screen: Screen, message: Frame) -> None:
        op = message["op"]
        if op == "activity":
            _fields(message, {"op", "seconds", "hidden"})
            seconds, hidden = _number(message, "seconds", 0, 30), _flag(message, "hidden")
            if seconds is None:
                raise InvalidOpError
            now = _now()
            screen.until = now + seconds
            if hidden is not None:
                screen.hidden = hidden
            if not screen.hidden:
                screen.active_at = now
            if self.upstream.alive():
                screen.send('{"v":1,"type":"alive"}')
            else:
                self.alive_waiters.append(screen)
            self.upstream.sync_activity(probe=screen in self.alive_waiters)
            return
        screen.active_at = _now()
        if op == "resync":
            _fields(message, {"op"})
            self._resync(screen)
        elif op == "settings":
            _fields(message, {"op", "on", "tag"})
            tag = _number(message, "tag", 0, U32)
            if message.get("on") is not True:
                raise InvalidOpError
            self._settings_subscribe(screen, tag)
        elif op == "diagnostic":
            _fields(message, {"op", "on"})
            self._diagnostic_subscribe(screen, _flag(message, "on", required=True))
        elif op == "log":
            _fields(message, {"op", "on", "after"})
            on, after = _flag(message, "on", required=True), _number(message, "after", 0, U32)
            if not on and after is not None:
                raise InvalidOpError
            self._log_subscribe(screen, on, after or 0)
        elif op in self.views:
            self.views[op].on_op(screen, message)
        elif op != "records":  # An older page's record index request: ignored, never closed.
            raise InvalidOpError

    def aggregate(self) -> tuple[int, bool]:
        """(seconds, hidden) for the upstream: the most of the visible screens, hidden only when all
        are."""
        now, screens = _now(), self.bound()
        visible = [screen for screen in screens if not screen.hidden]
        return max((screen.seconds(now) for screen in visible), default=0), bool(
            screens
        ) and not visible

    def _resync(self, screen: Screen) -> None:
        """Answered from what the companion holds; the same screen again within 30 s asks the
        controller."""
        now = _now()
        repeated, screen.resync_at = now - screen.resync_at < RESYNC_REPEAT_S, now
        if repeated and now - self.resync_at >= RESYNC_UPSTREAM_S and self._resync_upstream():
            return
        self._send_home(screen)
        screen.card = False
        self._send_card(screen)
        if screen.settings and self.settings.ready:
            screen.settings_synced = True
            for text in self.settings.frames("settings", {"tag": self.settings_tag}):
                screen.send(text)
        if screen.diagnostic:
            self._send_diagnostic(screen)
        for view in self.views.values():
            view.resync(screen)

    def _resync_upstream(self) -> bool:
        if not self.up({"op": "resync"}):
            return False
        self.resync_at = self.card_resync_at = _now()
        for view in self.views.values():
            view.upstream_resync()
        return True

    # --- Home, shot card --------------------------------------------------------------
    def _send_home(self, screen: Screen, presets: bool = False) -> None:
        if not self.home.ready:
            screen.home = False
            return
        changes = self.home.changes
        changes = {
            **changes,
            **{
                key: value + int(_now() - self.home.clock_at[key])
                for key in CLOCKS
                if type(value := changes.get(key)) is int
            },
        }
        if (
            presets
            and screen.presets_tag is not None
            and changes.get("presetsTag") == screen.presets_tag
        ):
            changes = {key: value for key, value in changes.items() if key != "presets"}
        screen.send(
            dumps(
                {
                    "v": 1,
                    "type": "home",
                    "boot": self.home.boot,
                    "snapshot": True,
                    "changes": changes,
                }
            )
        )
        screen.home = True

    def _send_card(self, screen: Screen) -> None:
        if self.card_valid:
            for text in self.card:
                screen.send(text)
            screen.card = True
        else:
            self._card_recover()

    def _card_recover(self) -> None:
        """Over its bound the card cannot serve a new screen: one upstream resync, at most once a
        minute."""
        if (
            not self.card_live
            and _now() - self.card_resync_at >= RESYNC_UPSTREAM_S
            and self.upstream.heard
        ):
            self._resync_upstream()

    def _on_home(self, frame: Frame, text: str) -> None:
        active, boot = self.active_preset(), self.home.boot
        if not self.home.apply(frame):
            return
        if (
            self.home.boot != boot
        ):  # Replica pages carry the controller's boot: those waiting for it go now.
            self.replica_changed()
        elif (
            self.active_preset() != active
        ):  # The controller sends its Stats page again; so does the replica.
            self.views["stats"].refresh()
        snapshot = frame.get("snapshot") is True
        for screen in self.bound():
            if screen.home or snapshot:
                screen.send(text)
                screen.home = True
        self.changed.set()
        self.changed = asyncio.Event()

    def _on_card(self, frame: Frame, text: str) -> None:
        snapshot = frame.get("snapshot") is True
        if "phase" in frame:
            self.card_live = frame["phase"] in ("active", "pending")
        if snapshot:
            self.card, self.card_bytes, self.card_valid = [text], len(text), True
        elif self.card_valid:
            self.card.append(text)
            self.card_bytes += len(text)
            if len(self.card) > CARD_FRAMES or self.card_bytes > CARD_BYTES:
                self.card, self.card_bytes, self.card_valid = [], 0, False
        for screen in self.bound():
            if screen.card or snapshot:
                screen.send(text)
                screen.card = True
        if not self.card_valid and any(not screen.card for screen in self.bound()):
            self._card_recover()

    async def command_done(self, request_id: int) -> bool:
        """Wait until Home's lastCommand settles this request (or a newer one); the caller bounds
        the wait (asyncio.timeout)."""
        while self.upstream.state == "open":
            current = self.home.changes.get("lastCommand.requestId")
            if isinstance(current, int) and (
                _newer(current, request_id)
                or (current == request_id and self.home.changes.get("lastCommand.state") in FINAL)
            ):
                return True
            await self.changed.wait()
        return False

    # --- Settings, Diagnostic --------------------------------------------------------------
    def _settings_subscribe(self, screen: Screen, tag: int | None) -> None:
        screen.settings = True
        if not self.settings_on:
            self.settings_on = True
            screen.settings_synced = False
            self.attribute(screen)
            self.up({"op": "settings", "on": True})
        elif self.settings.ready:
            screen.settings_synced = True
            if not tag or tag != self.settings_tag:
                for text in self.settings.frames("settings", {"tag": self.settings_tag}):
                    screen.send(text)

    def _on_settings(self, frame: Frame, text: str) -> None:
        if not self.settings.apply(frame):
            return
        if "tag" in frame:
            self.settings_tag = frame["tag"]
        snapshot = frame.get("snapshot") is True
        for screen in self.bound():
            if screen.settings and (screen.settings_synced or snapshot):
                screen.send(text)
                screen.settings_synced = True

    def _diagnostic_subscribe(self, screen: Screen, on: bool) -> None:
        screen.diagnostic = on
        if not on:
            self._diagnostic_settle()
            return
        if self.linger:
            self.linger.cancel()
            self.linger = None
        if not self.diagnostic_on:
            self.diagnostic_on = True
            self.diagnostic.clear()
            screen.diagnostic_synced = False
            self.attribute(screen)
            self.up({"op": "diagnostic", "on": True})
        else:
            self._send_diagnostic(screen)

    def _send_diagnostic(self, screen: Screen) -> None:
        if self.diagnostic.ready:
            for text in self.diagnostic.frames("diagnostic", split=True):
                screen.send(text)
            screen.diagnostic_synced = True
        else:
            screen.diagnostic_synced = False

    def _diagnostic_settle(self) -> None:
        if (
            self.diagnostic_on
            and not any(screen.diagnostic for screen in self.bound())
            and not self.linger
        ):
            self.linger = asyncio.get_running_loop().call_later(
                DIAGNOSTIC_LINGER_S, self._diagnostic_off
            )

    def _diagnostic_off(self) -> None:
        self.linger = None
        if self.diagnostic_on and not any(screen.diagnostic for screen in self.bound()):
            self.diagnostic_on = False
            self.diagnostic.clear()
            self.up({"op": "diagnostic", "on": False})

    def _on_diagnostic(self, frame: Frame, text: str) -> None:
        if not self.diagnostic_on or not self.diagnostic.apply(frame):
            return
        snapshot = frame.get("snapshot") is True
        for screen in self.bound():
            if screen.diagnostic and (screen.diagnostic_synced or snapshot):
                screen.send(text)
                screen.diagnostic_synced = True

    # --- Log ---------------------------------------------------------------------------
    def _log_subscribe(self, screen: Screen, on: bool, after: int) -> None:
        if not on:
            screen.log = False
            self._log_settle()
            return
        screen.log, screen.log_after, screen.log_owed, screen.log_invalid = True, after, True, False
        if not self.log_on:
            self.log_on = True
            self.attribute(screen)
            self.up({"op": "log", "on": True, "after": self.ring[-1][0] if self.ring else 0})
        self._log_serve(screen)

    def _log_settle(self) -> None:
        if self.log_on and not any(screen.log for screen in self.bound()):
            self.log_on = False
            self.up({"op": "log", "on": False})  # The ring stays while the session lives.

    def _on_log(self, frame: Frame) -> None:
        events, boot = frame.get("events"), frame.get("bootId")
        if not isinstance(events, list) or not isinstance(boot, int):
            return
        screens = [screen for screen in self.bound() if screen.log]
        if frame.get("cursorInvalid") is True or (
            self.log_meta is not None and self.log_meta["bootId"] != boot
        ):
            self.ring.clear()
            self.ring_bytes = 0
            for screen in screens:
                screen.log_invalid = True
        missed = frame.get("missedEvents")
        if isinstance(missed, int) and missed > 0:
            for screen in screens:
                if not self.ring or screen.log_after == self.ring[-1][0]:
                    screen.log_missed += missed
        for event in events:
            sequence = event.get("sequence") if isinstance(event, dict) else None
            if not isinstance(sequence, int) or (
                self.ring and not _newer(sequence, self.ring[-1][0])
            ):
                continue
            size = len(dumps(event))
            self.ring.append((sequence, event, size))
            self.ring_bytes += size
        while len(self.ring) > LOG_EVENTS or self.ring_bytes > LOG_BYTES:
            self.ring_bytes -= self.ring.popleft()[2]
        self.log_meta = {
            name: frame.get(name) if isinstance(frame.get(name), int) else 0
            for name in ("bootId", "historyOverwritten", "serialDropped")
        }
        self.log_more = frame.get("hasMore") is True
        for screen in screens:
            self._log_serve(screen)

    def _log_serve(self, screen: Screen) -> None:
        """This screen's events after its cursor, in ≤ FRAME_BUDGET frames."""
        if self.log_meta is None:
            return
        ring, after, invalid = self.ring, screen.log_after, screen.log_invalid
        start = 0
        if ring and after and not invalid:
            oldest, newest = ring[0][0], ring[-1][0]
            if after == newest:
                start = len(ring)
            elif _newer(after, newest) or (_newer(oldest, after) and (oldest - after) & U32 > 1):
                # A cursor from the future, or older than the ring: refill from the oldest.
                invalid = True
            else:
                start = next(index for index, entry in enumerate(ring) if _newer(entry[0], after))
        if start == len(ring) and not (screen.log_owed or invalid or screen.log_missed):
            return
        chunks: list[list[object]]
        chunk: list[object]
        chunks, chunk, size = [], [], 0
        for index in range(start, len(ring)):
            _, event, event_size = ring[index]
            if chunk and size + event_size > FRAME_BUDGET - 512:
                chunks.append(chunk)
                chunk, size = [], 0
            chunk.append(event)
            size += event_size
        chunks.append(chunk)
        for number, events in enumerate(chunks):
            first = number == 0
            screen.send(
                dumps(
                    {
                        "v": 1,
                        "type": "log",
                        **self.log_meta,
                        "missedEvents": screen.log_missed if first else 0,
                        "cursorInvalid": invalid and first,
                        "events": events,
                        "hasMore": number < len(chunks) - 1 or self.log_more,
                    }
                )
            )
        if ring and start < len(ring):
            screen.log_after = ring[-1][0]
        elif invalid:
            screen.log_after = 0
        screen.log_owed = screen.log_invalid = False
        screen.log_missed = 0

    # --- Upstream frames ------------------------------------------------------------------
    def on_frame(self, frame: Frame, text: str) -> None:
        kind = frame.get("type")
        if kind == "home":
            self._on_home(frame, text)
        elif kind is None and "seq" in frame:
            self._on_card(frame, text)
        elif kind == "settings":
            self._on_settings(frame, text)
        elif kind == "diagnostic":
            self._on_diagnostic(frame, text)
        elif kind == "log":
            self._on_log(frame)
        elif kind in self.views:
            self.views[kind].on_frame(frame)
        elif kind != "alive":  # A newer controller's frame: every screen may know it.
            for screen in self.bound():
                screen.send(text)
        if self.alive_waiters:
            waiters, self.alive_waiters = self.alive_waiters, []
            for screen in waiters:
                screen.send('{"v":1,"type":"alive"}')
