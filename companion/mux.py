"""The multiplexer: every screen's views on the companion's one ui-stream session.

The controller keeps one claim and one stream session for all companion
screens. The companion builds every upstream op itself from validated screen
ops, keeps what a late screen needs (merged Home, Settings and Diagnostic
models, the shot card since its last snapshot, the log ring, the record
views' standing pages) and answers each screen from it, so the controller's
cost does not grow with the number of screens.
"""

import asyncio
import collections
import json

from . import log
from .upstream import Upstream, dumps

U32 = 0xFFFFFFFF
FRAME_BUDGET = 20 * 1024
SCREEN_BYTES = 1 << 20
CARD_FRAMES, CARD_BYTES = 512, 256 * 1024
RECORD_PAGES, RECORD_BYTES = 16, 512 * 1024
LOG_EVENTS, LOG_BYTES = 1024, 512 * 1024
BIND_S, IDLE_S, DIAGNOSTIC_LINGER_S = 5, 5, 5
FETCH_TIMEOUT_S, RECORDS_TIMEOUT_S = 120, 15
RESYNC_REPEAT_S, RESYNC_UPSTREAM_S = 30, 60
ATTRIBUTION_S = 1
HISTORY_TYPES = ("shot", "rinse", "other", "power_on", "no_scale_guard_aborted", "backflush")
STATS_RESULTS = ("on_recipe", "fast", "slow")
HISTORY_CAPACITY, HISTORY_PAGE_MAX, SHOT_LOG_CAPACITY = 1000, 120, 1000
STATS_WINDOWS, FILTER_MAX = (10, 50, 100), 8
FINAL = frozenset({"APPLIED", "PERSISTED", "FAILED", "CANCELED"})
DEFAULTS = {"history": {"offset": 0, "limit": 20, "dir": "desc", "types": ()},
            "stats": {"offset": 0, "limit": 10, "sort": "date", "dir": "desc", "filter": "{}", "window": 10}}


class Invalid(Exception):
    """An op the controller would reject: the screen is closed with 4003."""


def _now():
    return asyncio.get_running_loop().time()


def _newer(a, b):
    """a comes after b in uint32 sequence order."""
    return 0 < (a - b) & U32 < 0x80000000


def _reject(_):
    raise ValueError("not a JSON number")


# --- Op validation (the firmware's whitelists and ranges) -------------------------
def _fields(message, allowed):
    if not set(message) <= allowed:
        raise Invalid()


def _number(message, name, low, high):
    if name not in message:
        return None
    value = message[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != int(value) or \
            not low <= value <= high:
        raise Invalid()
    return int(value)


def _flag(message, name, required=False):
    if name not in message:
        if required:
            raise Invalid()
        return None
    if not isinstance(message[name], bool):
        raise Invalid()
    return message[name]


def _choice(message, name, choices):
    if name not in message:
        return None
    if message[name] not in choices:
        raise Invalid()
    return message[name]


def _list(value, limit):
    if not isinstance(value, list) or len(value) > limit:
        raise Invalid()
    return value


def _types(message):
    if "types" not in message:
        return None
    names = _list(message["types"], len(HISTORY_TYPES))
    if not all(isinstance(name, str) and name in HISTORY_TYPES for name in names):
        raise Invalid()
    return tuple(name for name in HISTORY_TYPES if name in names)


def _filter(message):
    """The Stats filter as canonical JSON (empty lists and bad:false dropped), or None when absent."""
    if "filter" not in message:
        return None
    value = message["filter"]
    if not isinstance(value, dict) or not set(value) <= {"result", "preset", "scale", "bad"}:
        raise Invalid()
    canonical = {}
    if _flag(value, "bad"):
        canonical["bad"] = True
    results = _list(value.get("result", []), FILTER_MAX)
    if not all(isinstance(name, str) and name in STATS_RESULTS for name in results):
        raise Invalid()
    if results:
        canonical["result"] = [name for name in STATS_RESULTS if name in results]
    for name, high in (("preset", 255), ("scale", U32)):
        items = _list(value.get(name, []), FILTER_MAX)
        numbers = sorted({_number({"v": item}, "v", 0, high) for item in items})
        if numbers:
            canonical[name] = numbers
    return dumps(dict(sorted(canonical.items())))


def parse(text):
    """A screen's op, validated; ValueError when it is not a JSON object."""
    message = json.loads(text, parse_constant=_reject)
    if not isinstance(message, dict) or not isinstance(message.get("op"), str):
        raise ValueError("not an op")
    return message


# --- Merged `changes` models (Home, Settings, Diagnostic) [D2] -----------------------
class Merged:
    """A flat `changes` map: a snapshot replaces it, an increment updates it in place.

    A key replaces its descendants ("a" drops "a.b"), so replaying the map in order
    rebuilds exactly the model the frames built, and keys keep their first position.
    """

    def __init__(self):
        self.boot, self.changes, self.ready = None, {}, False

    def apply(self, frame):
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
        return True

    def clear(self):
        self.boot, self.changes, self.ready = None, {}, False

    def frames(self, kind, extra=None, split=False):
        """The model as one synthesized snapshot, or split into ≤ FRAME_BUDGET frames."""
        head = {"v": 1, "type": kind, "boot": self.boot, "snapshot": True}
        if not split:
            return [dumps({**head, "changes": self.changes, **(extra or {})})]
        frames, part, size = [], {}, 0
        for key, value in self.changes.items():
            item = len(dumps({key: value}))
            if part and size + item > FRAME_BUDGET:
                frames.append(part)
                part, size = {}, 0
            part[key], size = value, size + item
        frames.append(part)
        return [dumps({**head, "changes": frames[0]})] + [
            dumps({"type": kind, "changes": changes}) for changes in frames[1:]]


# --- Screens ----------------------------------------------------------------------------
class Record:
    """One screen's History or Stats view: its parameters, group and request id."""

    def __init__(self, kind):
        self.params = dict(DEFAULTS[kind])
        self.group = None  # Parameter group while subscribed.
        self.request, self.synced = 0, False


class Screen:
    def __init__(self, mux, ws, addr):
        self.mux, self.ws, self.addr = mux, ws, addr
        self.id, self.bound, self.closed = None, False, False
        self.presets_tag = None
        self.home = self.card = False  # Holds a snapshot of each.
        self.settings = self.settings_synced = False
        self.diagnostic = self.diagnostic_synced = False
        self.log, self.log_after, self.log_owed, self.log_invalid, self.log_missed = False, 0, False, False, 0
        self.records = {"history": Record("history"), "stats": Record("stats")}
        self.stats_seq, self.stats_map = 0, {}
        self.until, self.hidden = 0.0, False
        self.active_at = self.resync_at = float("-inf")
        self.queue, self.queued = collections.deque(), 0
        self.wake = asyncio.Event()

    def send(self, text):
        if self.closed:
            return
        self.queue.append(text)
        self.queued += len(text)
        if self.queued > SCREEN_BYTES:  # A screen that cannot keep up reconnects quietly.
            log("a screen fell 1 MiB behind; closing it so it reconnects")
            self.close(4002)
            return
        self.wake.set()

    def close(self, code, reason=""):
        if not self.closed:
            self.closed = True
            self.wake.set()
            self.mux.companion.spawn(self.ws.close(code=code, message=reason.encode()))

    async def writer(self):
        while not self.closed:
            await self.wake.wait()
            self.wake.clear()
            while self.queue and not self.closed:
                text = self.queue.popleft()
                self.queued -= len(text)
                try:
                    await self.ws.send_str(text)
                except (ConnectionError, RuntimeError):
                    self.closed = True
                    return

    def seconds(self, now):
        return max(0, int(self.until - now + 0.999))


# --- History and Stats ---------------------------------------------------------------------
class Fetch:
    """One upstream fetch: a group's first page and/or screens' own windows, coalesced."""

    def __init__(self, key, group=None, target=None):
        self.key, self.group, self.targets = key, group, [target] if target else []
        self.id, self.timer, self.started = 0, None, False


class View:
    """History or Stats: one standing upstream window for the owner group, fetches for the others."""

    def __init__(self, mux, kind):
        self.mux, self.kind = mux, kind
        self.next_id = 0
        self.clear()

    def clear(self):
        if getattr(self, "inflight", None) and self.inflight.timer:
            self.inflight.timer.cancel()
        self.standing, self.request, self.epoch, self.awaiting = None, 0, None, False
        self.buffer, self.buffer_bytes, self.buffer_pages, self.buffer_state = [], 0, 0, "waiting"
        self.pages = {}  # Non-owner group -> (frames of its last page, complete)
        self.queue, self.inflight = [], None

    def _id(self):
        self.next_id = self.next_id % U32 + 1
        return self.next_id

    # Parameters and ops
    def key(self, params):
        if self.kind == "history":
            return (params["offset"], params["limit"], params["dir"], params["types"])
        return (params["offset"], params["limit"], params["sort"], params["dir"], params["filter"], params["window"])

    def op(self, key, request, fetch=False):
        op = {"op": self.kind, "on": True}
        if fetch:
            op["fetch"] = True
        if self.kind == "history":
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

    def members(self, group):
        return [screen for screen in self.mux.bound() if screen.records[self.kind].group == group]

    def _start(self, frame):
        return self.kind == "history" or frame.get("rowBase") == 0

    def deliver(self, screen, frame, request, snapshot=None):
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
    def on_op(self, screen, message):
        on = _flag(message, "on", required=True)
        request = _number(message, "request", 1, U32)
        tag = _number(message, "tag", 1, U32)
        offset = _number(message, "offset", 0, HISTORY_CAPACITY if self.kind == "history" else SHOT_LOG_CAPACITY)
        limit = _number(message, "limit", 1, HISTORY_PAGE_MAX if self.kind == "history" else SHOT_LOG_CAPACITY)
        direction = _choice(message, "dir", ("asc", "desc"))
        fetch = _flag(message, "fetch")
        record = screen.records[self.kind]
        if self.kind == "history":
            _fields(message, {"op", "on", "offset", "limit", "dir", "fetch", "request", "types", "tag"})
            values = {"offset": offset, "limit": limit, "dir": direction, "types": _types(message)}
            replaced = {"types": ()}
        else:
            _fields(message, {"op", "on", "offset", "limit", "sort", "dir", "fetch", "request", "filter", "window",
                              "tag"})
            window = _number(message, "window", 0, U32)
            if window is not None and window not in STATS_WINDOWS:
                raise Invalid()
            values = {"offset": offset, "limit": limit, "sort": _choice(message, "sort", ("date", "rating")),
                      "dir": direction, "filter": _filter(message), "window": window}
            replaced = {"filter": "{}", "window": 10}
        given = {name: value for name, value in values.items() if value is not None}
        if not on:
            if set(message) - {"op", "on"}:
                raise Invalid()
            self.unsubscribe(screen)
        elif fetch:
            if record.group is None or offset is None or tag is not None or (
                    self.kind == "stats" and "window" in given):
                raise Invalid()
            self.mux.attribute(screen)  # What it leaves out is its own window's, not the controller's.
            self._queue(self.key({**record.params, **given}), target=(screen, request or 0))
        elif self.kind == "stats" and record.group is not None and set(given) == {"window"} and \
                request is None and tag is None:
            self.subscribe(screen, record.request, {**record.params, "window": given["window"]}, window_only=True)
        else:
            self.subscribe(screen, request or 0, {**record.params, **replaced, **given})

    def subscribe(self, screen, request, params, window_only=False):
        record = screen.records[self.kind]
        old, group = record.group, self.key(params)
        # Nobody else holds the standing window: this screen may move it.
        alone = self.standing is not None and not any(s is not screen for s in self.members(self.standing))
        record.params, record.group, record.request = params, group, request
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

    def unsubscribe(self, screen, settle=True):
        record = screen.records[self.kind]
        record.group, record.synced = None, False
        for fetch in [self.inflight, *self.queue]:
            if fetch:
                fetch.targets = [target for target in fetch.targets if target[0] is not screen]
        if settle:
            self.settle()

    def resync(self, screen):
        record = screen.records[self.kind]
        if record.group is None:
            return
        record.synced = False
        if record.group == self.standing:
            self._replay(screen)
        else:
            self._join(screen, record.group)

    def settle(self):
        """After a screen left: promote another group, or end the upstream window."""
        screens = [screen for screen in self.mux.bound() if screen.records[self.kind].group is not None]
        if not screens:
            if self.standing is not None:
                self.mux.up({"op": self.kind, "on": False})
                self.clear()
            return
        if not any(screen.records[self.kind].group == self.standing for screen in screens):
            newest = max(screens, key=lambda screen: screen.active_at)
            self._subscribe_upstream(newest.records[self.kind].group)

    def _subscribe_upstream(self, group):
        self.standing, self.request, self.awaiting = group, self._id(), True
        self.buffer, self.buffer_bytes, self.buffer_pages, self.buffer_state = [], 0, 0, "waiting"
        self.pages.pop(group, None)
        for screen in self.members(group):
            screen.records[self.kind].synced = False
        self.dropped()
        self.mux.up(self.op(group, self.request))

    def dropped(self):
        """An upstream subscribe or resync drops the controller's fetch: ask again after its snapshot."""
        self.awaiting = True
        if self.inflight is not None:
            fetch, self.inflight = self.inflight, None
            if fetch.timer:
                fetch.timer.cancel()
            fetch.started = False
            self.queue.insert(0, fetch)

    def upstream_resync(self):
        self.buffer, self.buffer_bytes, self.buffer_pages, self.buffer_state = [], 0, 0, "waiting"
        for screen in self.members(self.standing):
            screen.records[self.kind].synced = False
        self.dropped()

    def _replay(self, screen):
        record = screen.records[self.kind]
        if self.buffer_state == "valid" and self.buffer:
            for frame in self.buffer:
                self.deliver(screen, frame, record.request)
            record.synced = True
        elif self.buffer_state == "over":
            self._subscribe_upstream(self.standing)  # Over the bound: one fresh snapshot, without a tag.

    def _join(self, screen, group):
        frames, complete = self.pages.get(group, ((), False))
        if complete:
            record = screen.records[self.kind]
            for frame in frames:
                self.deliver(screen, frame, record.request, snapshot=True)
            record.synced = True
        else:
            self._queue(group, group=group)

    # Fetch queue: one in flight, identical ones coalesced
    def _queue(self, key, group=None, target=None, behind_inflight=False):
        candidates = self.queue if behind_inflight else [*([self.inflight] if self.inflight else ()), *self.queue]
        for fetch in candidates:
            if fetch.key == key:
                fetch.group = fetch.group or group
                if target:
                    fetch.targets.append(target)
                return
        self.queue.append(Fetch(key, group, target))
        self.pump()

    def _wanted(self, fetch):
        return fetch.targets or (fetch.group is not None and fetch.group != self.standing and self.members(fetch.group))

    def pump(self):
        if self.inflight is not None or self.awaiting or self.mux.upstream.state != "open":
            return
        while self.queue:
            fetch = self.queue.pop(0)
            if self._wanted(fetch):
                fetch.id = self._id()
                fetch.timer = asyncio.get_running_loop().call_later(FETCH_TIMEOUT_S, self._expired, fetch)
                self.inflight = fetch
                self.mux.up(self.op(fetch.key, fetch.id, fetch=True))
                return

    def _expired(self, fetch):
        """Stats fetches wait silently while a shot's trace capture is open; never resent."""
        if self.inflight is fetch:
            self.inflight = None
            self.pump()

    # Upstream frames
    def on_frame(self, frame):
        request = frame.get("request")
        if not isinstance(request, int) or (self.kind == "stats" and not isinstance(frame.get("seq"), int)):
            return
        if self.standing is not None and request == self.request:
            self._standing(frame)
        elif self.inflight is not None and request == self.inflight.id:
            self._fetched(frame)

    def _standing(self, frame):
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
            self.epoch = epoch
        for screen in self.members(self.standing):
            record = screen.records[self.kind]
            if record.synced or (start and snapshot):
                self.deliver(screen, frame, record.request)
                record.synced = True
        self.pump()

    def _epoch_moved(self):
        """The store changed: every other group's page is out of date; one fetch per group."""
        self.pages.clear()
        groups = {screen.records[self.kind].group for screen in self.mux.bound()} - {None, self.standing}
        for group in sorted(groups, key=repr):
            self._queue(group, group=group, behind_inflight=True)

    def _fetched(self, frame):
        fetch, start = self.inflight, self._start(frame)
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
            self.pump()


# --- The multiplexer ---------------------------------------------------------------------------
class Mux:
    def __init__(self, companion, relay):
        self.companion, self.relay = companion, relay
        self.screens = set()
        self.claimed = set()  # Browser ids whose relayed claim (or sign-in) the controller accepted.
        self.upstream = Upstream(companion, relay, self)
        self.views = {"history": View(self, "history"), "stats": View(self, "stats")}
        self.home, self.settings, self.diagnostic = Merged(), Merged(), Merged()
        self.stores = {"shots": {"epoch": None, "rows": None, "at": None, "waiters": []},
                       "history": {"epoch": None, "rows": None, "at": None, "waiters": []}}
        self.idle = self.linger = None
        self.changed = asyncio.Event()
        self.attributed = collections.deque(maxlen=64)  # (time, screen) of ops sent upstream for a screen
        self._reset()

    def _reset(self):
        self.home.clear()
        self.settings.clear()
        self.diagnostic.clear()
        self.settings_tag, self.settings_on, self.diagnostic_on, self.log_on = None, False, False, False
        self.card, self.card_bytes, self.card_valid, self.card_live = [], 0, False, False
        self.card_resync_at = self.resync_at = float("-inf")
        self.ring, self.ring_bytes, self.log_meta, self.log_more = collections.deque(), 0, None, False
        self.alive_waiters = []
        for view in self.views.values():
            view.clear()
        for store in self.stores.values():
            store["at"], store["waiters"] = None, []

    def bound(self):
        return [screen for screen in self.screens if screen.bound and not screen.closed]

    def status(self):
        screens = self.bound()
        views = {"home": len(screens),
                 "settings": sum(screen.settings for screen in screens),
                 "diagnostic": sum(screen.diagnostic for screen in screens),
                 "log": sum(screen.log for screen in screens)}
        for kind in self.views:
            views[kind] = sum(screen.records[kind].group is not None for screen in screens)
        return {"screens": len(screens), "owner": bool(self.claimed), "views": views}

    # --- Upstream ops ----------------------------------------------------------------
    def up(self, op):
        return self.upstream.send(op)

    def attribute(self, screen):
        """Note that this screen's op led to upstream ops (a 4003 then names it)."""
        now = _now()
        screen.active_at = now
        self.attributed.append((now, screen))

    def bind_ops(self):
        screens = self.bound()
        ops = []
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
                ops.append(view.op(view.standing, view.request))
        return ops

    def upstream_opened(self):
        for view in self.views.values():
            view.pump()
        self._ask_records()
        if not self.bound() and not self.idle:
            self.idle = asyncio.get_running_loop().call_later(IDLE_S, self._idle)

    def upstream_closed(self, code, deliberate, heard=False):
        screens = list(self.screens)
        if code == 4001:  # The controller gave the Web UI to a direct browser, or forgot the claim (reboot).
            self.claimed.clear()
            log("the Web UI was opened directly on another device; every companion screen offers Reload")
            for screen in screens:
                screen.close(4001, "direct" if heard else "")
        elif code == 4003:  # An op failed the controller's validation: name the screens that sent one.
            log("the controller rejected an op on the shared live updates")
            recent = {screen for at, screen in self.attributed if _now() - at <= ATTRIBUTION_S}
            for screen in screens:
                screen.close(4003 if screen in recent else 4002)
        elif not deliberate:
            for screen in screens:
                screen.close(4002 if code == 4002 else 1001)
        self.attributed.clear()
        self._reset()

    def takeover(self):
        """A relayed call answered UI_TAKEN_OVER: a direct browser holds the Web UI."""
        self.claimed.clear()
        for screen in list(self.screens):
            screen.close(4001, "direct")
        self.upstream.close()

    # --- Screens ---------------------------------------------------------------------
    def connect(self, ws, addr):
        screen = Screen(self, ws, addr)
        self.screens.add(screen)
        if self.idle:
            self.idle.cancel()
            self.idle = None
        loop = asyncio.get_running_loop()
        loop.call_later(BIND_S, lambda: screen.bound or screen.close(1008))
        self.companion.spawn(screen.writer())
        return screen

    def disconnect(self, screen):
        screen.closed = True
        screen.wake.set()
        self.screens.discard(screen)
        if not screen.bound:
            return
        screen.bound = screen.log = screen.diagnostic = False
        remaining = bool(self.bound())  # The last screen leaving: the session closes soon, nothing to send.
        for view in self.views.values():
            view.unsubscribe(screen, settle=remaining)
        for store in self.stores.values():
            store["waiters"] = [waiter for waiter in store["waiters"] if waiter[0] is not screen]
        if remaining:
            self._settle()
            self.upstream.sync_activity()
        else:
            self.idle = asyncio.get_running_loop().call_later(IDLE_S, self._idle)

    def _settle(self):
        """Drop upstream subscriptions no screen holds any more."""
        for view in self.views.values():
            view.settle()
        self._log_settle()
        self._diagnostic_settle()

    def _idle(self):
        self.idle = None
        if not self.bound():
            self.upstream.close()  # The claim stays: the next screen binds a new session.

    def on_message(self, screen, text):
        try:
            message = parse(text)
        except ValueError:
            screen.close(1007)
            return
        op = message["op"]
        try:
            if not screen.bound:
                if op != "bind":
                    raise ValueError()
                self._bind(screen, message)
            else:
                self._op(screen, message)
        except ValueError:
            screen.close(1008)
        except Invalid:
            log(f"a screen's {op[:12]} op failed validation; closing it so it resets its list views")
            screen.close(4003)

    def _bind(self, screen, message):
        client = message.get("client")
        if not isinstance(client, str) or client not in self.claimed:
            screen.close(4001)
            return
        if self.upstream.state == "closing":  # Caught the idle close: reconnect quietly in a moment.
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
            raise Invalid()
        for op in ops:
            if not isinstance(op, dict) or not isinstance(op.get("op"), str) or op["op"] == "bind":
                raise Invalid()
            self._op(screen, op)
        self._settle()
        self.upstream.open()

    def _op(self, screen, message):
        op = message["op"]
        if op == "activity":
            _fields(message, {"op", "seconds", "hidden"})
            seconds, hidden = _number(message, "seconds", 0, 30), _flag(message, "hidden")
            if seconds is None:
                raise Invalid()
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
                raise Invalid()
            self._settings_subscribe(screen, tag)
        elif op == "diagnostic":
            _fields(message, {"op", "on"})
            self._diagnostic_subscribe(screen, _flag(message, "on", required=True))
        elif op == "log":
            _fields(message, {"op", "on", "after"})
            on, after = _flag(message, "on", required=True), _number(message, "after", 0, U32)
            if not on and after is not None:
                raise Invalid()
            self._log_subscribe(screen, on, after or 0)
        elif op in self.views:
            self.views[op].on_op(screen, message)
        elif op == "records":
            _fields(message, {"op", "shots", "history"})
            epochs = {store: _number(message, store, 0, U32) for store in ("shots", "history")}
            if all(epoch is None for epoch in epochs.values()):
                raise Invalid()
            self._records(screen, {store: epoch for store, epoch in epochs.items() if epoch is not None})
        else:
            raise Invalid()

    def aggregate(self):
        """(seconds, hidden) for the upstream: the most of the visible screens, hidden only when all are."""
        now, screens = _now(), self.bound()
        visible = [screen for screen in screens if not screen.hidden]
        return max((screen.seconds(now) for screen in visible), default=0), bool(screens) and not visible

    def _resync(self, screen):
        """Answered from what the companion holds; the same screen again within 30 s asks the controller."""
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

    def _resync_upstream(self):
        if not self.up({"op": "resync"}):
            return False
        self.resync_at = self.card_resync_at = _now()
        for view in self.views.values():
            view.upstream_resync()
        return True

    # --- Home, shot card --------------------------------------------------------------
    def _send_home(self, screen, presets=False):
        if not self.home.ready:
            screen.home = False
            return
        changes = self.home.changes
        if presets and screen.presets_tag is not None and changes.get("presetsTag") == screen.presets_tag:
            changes = {key: value for key, value in changes.items() if key != "presets"}
        screen.send(dumps({"v": 1, "type": "home", "boot": self.home.boot, "snapshot": True, "changes": changes}))
        screen.home = True

    def _send_card(self, screen):
        if self.card_valid:
            for text in self.card:
                screen.send(text)
            screen.card = True
        else:
            self._card_recover()

    def _card_recover(self):
        """Over its bound the card cannot serve a new screen: one upstream resync, at most once a minute."""
        if not self.card_live and _now() - self.card_resync_at >= RESYNC_UPSTREAM_S and self.upstream.heard:
            self._resync_upstream()

    def _on_home(self, frame, text):
        if not self.home.apply(frame):
            return
        snapshot = frame.get("snapshot") is True
        for screen in self.bound():
            if screen.home or snapshot:
                screen.send(text)
                screen.home = True
        self.changed.set()
        self.changed = asyncio.Event()

    def _on_card(self, frame, text):
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

    async def command_done(self, request_id, timeout):
        """Wait until Home's lastCommand settles this request (or a newer one), or the timeout."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while self.upstream.state == "open":
            current = self.home.changes.get("lastCommand.requestId")
            if isinstance(current, int) and (_newer(current, request_id) or (
                    current == request_id and self.home.changes.get("lastCommand.state") in FINAL)):
                return True
            remaining = deadline - loop.time()
            if remaining <= 0:
                return False
            try:
                await asyncio.wait_for(self.changed.wait(), remaining)
            except asyncio.TimeoutError:
                return False
        return False

    # --- Settings, Diagnostic --------------------------------------------------------------
    def _settings_subscribe(self, screen, tag):
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

    def _on_settings(self, frame, text):
        if not self.settings.apply(frame):
            return
        if "tag" in frame:
            self.settings_tag = frame["tag"]
        snapshot = frame.get("snapshot") is True
        for screen in self.bound():
            if screen.settings and (screen.settings_synced or snapshot):
                screen.send(text)
                screen.settings_synced = True

    def _diagnostic_subscribe(self, screen, on):
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

    def _send_diagnostic(self, screen):
        if self.diagnostic.ready:
            for text in self.diagnostic.frames("diagnostic", split=True):
                screen.send(text)
            screen.diagnostic_synced = True
        else:
            screen.diagnostic_synced = False

    def _diagnostic_settle(self):
        if self.diagnostic_on and not any(screen.diagnostic for screen in self.bound()) and not self.linger:
            self.linger = asyncio.get_running_loop().call_later(DIAGNOSTIC_LINGER_S, self._diagnostic_off)

    def _diagnostic_off(self):
        self.linger = None
        if self.diagnostic_on and not any(screen.diagnostic for screen in self.bound()):
            self.diagnostic_on = False
            self.diagnostic.clear()
            self.up({"op": "diagnostic", "on": False})

    def _on_diagnostic(self, frame, text):
        if not self.diagnostic_on or not self.diagnostic.apply(frame):
            return
        snapshot = frame.get("snapshot") is True
        for screen in self.bound():
            if screen.diagnostic and (screen.diagnostic_synced or snapshot):
                screen.send(text)
                screen.diagnostic_synced = True

    # --- Log ---------------------------------------------------------------------------
    def _log_subscribe(self, screen, on, after):
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

    def _log_settle(self):
        if self.log_on and not any(screen.log for screen in self.bound()):
            self.log_on = False
            self.up({"op": "log", "on": False})  # The ring stays while the session lives.

    def _on_log(self, frame):
        events, boot = frame.get("events"), frame.get("bootId")
        if not isinstance(events, list) or not isinstance(boot, int):
            return
        screens = [screen for screen in self.bound() if screen.log]
        if frame.get("cursorInvalid") is True or (self.log_meta is not None and self.log_meta["bootId"] != boot):
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
            if not isinstance(sequence, int) or (self.ring and not _newer(sequence, self.ring[-1][0])):
                continue
            size = len(dumps(event))
            self.ring.append((sequence, event, size))
            self.ring_bytes += size
        while len(self.ring) > LOG_EVENTS or self.ring_bytes > LOG_BYTES:
            self.ring_bytes -= self.ring.popleft()[2]
        self.log_meta = {name: frame.get(name) if isinstance(frame.get(name), int) else 0
                         for name in ("bootId", "historyOverwritten", "serialDropped")}
        self.log_more = frame.get("hasMore") is True
        for screen in screens:
            self._log_serve(screen)

    def _log_serve(self, screen):
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
                invalid = True  # A cursor from the future, or older than the ring: refill from the oldest.
            else:
                start = next(index for index, entry in enumerate(ring) if _newer(entry[0], after))
        if start == len(ring) and not (screen.log_owed or invalid or screen.log_missed):
            return
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
            screen.send(dumps({"v": 1, "type": "log", **self.log_meta,
                               "missedEvents": screen.log_missed if first else 0,
                               "cursorInvalid": invalid and first, "events": events,
                               "hasMore": number < len(chunks) - 1 or self.log_more}))
        if ring and start < len(ring):
            screen.log_after = ring[-1][0]
        elif invalid:
            screen.log_after = 0
        screen.log_owed = screen.log_invalid = False
        screen.log_missed = 0

    # --- Offline-copy index ---------------------------------------------------------------
    def _records(self, screen, epochs):
        for store, epoch in epochs.items():
            self.stores[store]["waiters"].append((screen, epoch))
        self.attribute(screen)
        self._ask_records()

    def _ask_records(self):
        """One upstream ask per store with the cached epoch, shared by every screen waiting."""
        now, ask = _now(), {}
        for name, store in self.stores.items():
            if store["waiters"] and (store["at"] is None or now - store["at"] > RECORDS_TIMEOUT_S):
                ask[name] = store["epoch"] or 0
        if ask and self.up({"op": "records", **ask}):
            for name in ask:
                self.stores[name]["at"] = now

    def _on_records(self, frame):
        name, epoch = frame.get("store"), frame.get("epoch")
        if name not in self.stores or not isinstance(epoch, int):
            return
        store = self.stores[name]
        if isinstance(frame.get("rows"), list):
            store["rows"] = frame["rows"]
        elif store["epoch"] != epoch or store["rows"] is None:
            store["rows"] = []
        store["epoch"], store["at"] = epoch, None
        waiters, store["waiters"] = store["waiters"], []
        for screen, held in waiters:
            answer = {"v": 1, "type": "records", "boot": frame.get("boot"), "store": name, "epoch": epoch}
            if held != epoch:
                answer["rows"] = store["rows"]
            screen.send(dumps(answer))

    # --- Upstream frames ------------------------------------------------------------------
    def on_frame(self, frame, text):
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
        elif kind == "records":
            self._on_records(frame)
        elif kind != "alive":  # A newer controller's frame: every screen may know it.
            for screen in self.bound():
                screen.send(text)
        if self.alive_waiters:
            waiters, self.alive_waiters = self.alive_waiters, []
            for screen in waiters:
                screen.send('{"v":1,"type":"alive"}')
