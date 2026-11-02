"""The companion service: pairing, the Web UI relay, the controller link, the La Marzocco route and its pages.

It runs on its own thread and event loop inside the gateway supervisor, which
tells it the controller's address on start and on every mDNS announcement.
nginx serves its pages under /__companion/, and the Web UI's API and live
updates, through a Unix socket.
"""

import asyncio
import hashlib
import html
import json
import re
import sqlite3
import threading
import time
import traceback
from pathlib import Path

import aiohttp
from aiohttp import web
from cryptography.exceptions import InvalidTag

from . import VERSION, crypto, dashboard, log
from . import stats
from .archive import FETCH_MAX, Archive, Unavailable
from .lamarzocco import LaMarzocco
from .link import Erased, LinkClosed, open_link
from .logstore import EXPORT_VERSION, FIRST_PAGE, FORMAT, LogStore
from .pairing import Pairing
from .relay import CLIENT_ID, Relay, address
from .screens import Screens
from .store import Store, offload

HERE = Path(__file__).resolve().parent
BACKOFF_S = (0, 5, 15, 60, 300)  # The first reopen is immediate; then it backs off.
RETRY_LATER_S = 15  # The controller is busy with its scale: a steady short retry, never a longer one.
FROM_CONTROLLER = frozenset({"cfg", "creds", "route", "hold", "cmd", "dev", "log", "rs", "rec", "trc"})
RETENTION_DAYS_DEFAULT, RETENTION_MB_DEFAULT = 30, 50
RETENTION_S = 24 * 3600
LOG_LEVELS = {"c": 0, "e": 1, "w": 2, "i": 3, "d": 4}
LOG_CATEGORY_MAX, LOG_MESSAGE_MAX = 24, 1024
LOG_ACCESS_RECHECK_S = 300  # How often a session's right to read the history is asked of the controller.
LOG_UNREACHABLE_S = 30  # ...and how long a controller that could not answer is left alone.
PING_S = {"companion": 15, "direct": 120}
STATS_WINDOWS = frozenset({10, 50, 100, 500, 1000})
# A sleep that comes back this late means the loop stood still; 20 s is where
# the controller's 30 s ping contract starts to break.
STALL_WARN_S = 5
WATCHDOG_S = 10
STALL_BREACH_S = 20
CONFIRM_S = 5
FULL_RETRY_S = (1, 2, 5, 10, 30)
HTTP_TIMEOUT_S = 10
# The controller's list filters (docs/INTEGRATION_API.md): at most eight values each.
FILTER_MAX = 8
RESULTS = frozenset({"on_recipe", "fast", "slow"})
HISTORY_TYPES = frozenset({"shot", "rinse", "backflush", "power_on", "other", "no_scale_guard_aborted"})
SERIAL_FORBIDDEN = set("\r\n:\\/")


class Companion:
    def __init__(self, name, data, http, upstream):
        self.name, self.http = name, http
        self.store = Store(data)
        self.id, self.key = self.store.identity()
        self.public = crypto.public_point(self.key)
        self.controller = None  # (name, (ip, port)) from the supervisor
        self.device_name = None  # The controller's own name, from its `dev` frame.
        self.device_id = None  # Its stable id (the webhook's deviceId), the log store's key, kept there.
        self.tasks = set()
        self.wake = asyncio.Event()
        self.pairing = Pairing(self)
        self.link, self.link_reason, self.failures = "down", "", 0
        self.ws = self.outbox = None
        self.route, self.hold, self.held = "direct", False, []
        self.ping_now = asyncio.Event()
        self.heard_at = 0.0  # time.monotonic() of the last controller frame.
        self.unknown_frames, self.unknown_kinds = 0, set()
        self.cfg = {"lm": False, "conn": "ws", "observe": True}
        self.logs = LogStore(data)
        self.log_on, self.log_subscribed, self.log_identified, self.configured = False, False, False, False
        self.log_error, self.log_dropped = None, 0  # Why the store is closed; frames that could not be keyed.
        self.log_grants = {}  # sha256 of a Web UI session -> when the controller last accepted it.
        self.log_denials = {}  # ...and when it last refused one, so a refused page does not keep asking.
        self.log_unreachable = 0.0  # When the controller last could not answer that question.
        self.retention = (RETENTION_DAYS_DEFAULT, RETENTION_MB_DEFAULT)
        self.archive = Archive(self)  # The shot and activation archive, in the same store.
        # Sync requests waiting for the end of a sync hold, and the hold the controller's `hold` frames
        # name: True during a shot (nothing crosses the link), None until the session's first one.
        self.sync_due, self.sync_hold = {}, None
        self.creds_gen = None  # Generation whose sign-in result the controller still waits for.
        self.full_ep, self.full_task = None, None
        self.expect, self.confirm_timer = None, None
        self.command_lock = asyncio.Lock()
        self.reported = None
        self.lm = upstream(self.store, self)
        self.relay = Relay(self)
        self.screens = Screens(self, self.relay)

    def spawn(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self._done)
        return task

    def _done(self, task):
        self.tasks.discard(task)
        if not task.cancelled() and task.exception():
            log("task failed:\n" + "".join(traceback.format_exception(task.exception())))

    # --- Controller ----------------------------------------------------------
    def base_url(self, scheme="http"):
        ip, port = self.controller[1]
        return f"{scheme}://{ip}" + ("" if port == 80 else f":{port}")

    def set_controller(self, target):
        """The controller in use, on start and on each of its mDNS announcements."""
        if target is None:
            return
        moved = self.controller is not None and target[1] != self.controller[1]
        self.controller = target
        if moved and self.ws is not None:
            log("the controller has a new address; reopening the link")
            self.spawn(self.ws.close())
        elif self.ws is not None:
            self.poke()  # It announced itself: a socket that died with a restart is found now.
        if self.ws is None:
            self.wake.set()  # Reconnect now instead of waiting out the backoff.
        self.pairing.start()
        self.spawn(self.relay.handshake())  # Also how a forgotten companion learns it.

    async def controller_request(self, method, url, body=None):
        """(status, JSON object) from the controller, or (None, {}) when it did not answer."""
        try:
            async with self.http.request(method, url, json=body,
                                         timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_S)) as reply:
                try:
                    data = await reply.json(content_type=None)
                except ValueError:
                    data = None
                return reply.status, data if isinstance(data, dict) else {}
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            return None, {}

    async def paired(self, secret):
        await offload(self.store.erase_pairing)
        self.lm.erase()
        await offload(self.store.save_pairing, secret, self.controller[0])
        log(f"paired with {self.controller[0]}")
        if self.ws is not None:
            self.spawn(self.ws.close())
        self.wake.set()
        self.spawn(self.relay.handshake())

    async def erase(self, why, history=True):
        """Delete the pairing, the La Marzocco account and its installation key and, unless `history` is
        false, the log history and the archive (Forget, D2). The page's erase of a pairing the controller
        no longer recognizes keeps both: pairing that controller again reattaches to them (S4)."""
        await offload(self.store.erase_pairing)
        self.lm.erase()
        self.creds_gen = None
        self.device_name = None  # It named the pairing, not this controller.
        self.pairing.state, self.pairing.auto = "unpaired", False
        self.relay.reset()
        self.archive.stop()
        self.screens.mux.unpark()
        if history:
            await self.erase_log()
            log(f"{why}; its pairing, La Marzocco account, installation key, log history and archive are erased")
        else:
            log(f"{why}; its pairing, La Marzocco account and installation key are erased, the log history and "
                "the archive are kept")
        self.wake.set()

    def not_recognized(self):
        """The controller does not know this companion, unsigned: stop using the account, keep every secret."""
        if self.pairing.state == "paired":
            self.pairing.state = "not_recognized"
            self.lm.configure(None, self.cfg["conn"], self.cfg["observe"])
            log("the controller does not recognize this companion; La Marzocco is stopped")

    async def recognized(self):
        """A relay session proved the pairing: a controller that did not know us does again."""
        if self.pairing.state == "not_recognized":
            self.pairing.state = "paired"
            await self._apply_account()

    def link_wanted(self, wanted):
        """The relay learned whether a feature needs the link [D4]; with no relay it always opens."""
        if wanted is False and self.ws is not None:
            log("the controller needs no link now; closing it")
            self.spawn(self.ws.close())
        self.wake.set()

    def poke(self):
        """Fresh evidence the controller answered (an announcement, a relay handshake):
        ping at once, so a link whose socket died with its restart — a reboot sends no
        FIN or RST — is found now, not at the next ping cadence. Never during a shot."""
        if self.ws is not None and not self.sync_hold:
            self.post({"t": "ping", "up": self.lm.up})

    # --- Link ----------------------------------------------------------------
    async def run_link(self):
        while True:
            try:
                reason = await self._link()
            except Exception:  # A bug or a disk error ends this attempt, never the gateway.
                log("the link failed unexpectedly:\n" + traceback.format_exc())
                reason = "ERROR"
            if reason is None:
                continue
            if reason == "RETRY_LATER":
                delay = RETRY_LATER_S
            else:
                delay = BACKOFF_S[min(self.failures, len(BACKOFF_S) - 1)]
                self.failures += 1
            self.link, self.link_reason = "retry", reason
            age = f"; last controller frame {time.monotonic() - self.heard_at:.0f} s ago" if self.heard_at else ""
            log(f"link closed ({reason}){age}; reopening in {delay} s, "
                "or as soon as the controller announces itself")
            try:
                await asyncio.wait_for(self.wake.wait(), delay)
            except asyncio.TimeoutError:
                pass

    async def _link(self):
        """One link attempt and its session: why it ended, or None to look again at once."""
        pairing = await offload(self.store.pairing)
        if self.controller is not None and pairing is not None and self.relay.link is None:
            # Nobody answered the relay handshake yet (the controller was off when this companion
            # started): ask again on the link's backoff, since a manual address hears no announcement.
            await self.relay.handshake()
            if self.relay.link is None:
                log("the controller did not answer the relay handshake")
                return "UNREACHABLE"
        if self.controller is None or pairing is None or self.relay.link is not True:
            self.link, self.link_reason = "down", ""
            self.wake.clear()
            await self.wake.wait()
            return None
        self.wake.clear()
        self.link = "connecting"
        hello = {"id": self.id, "name": self.name, "version": VERSION}
        try:
            ws, codec = await open_link(self.http, self.base_url("ws") + "/api/v1/companion/link",
                                        hello, pairing["secret"])
        except Erased:
            self.failures = 0
            await self.erase("the controller forgot this companion")
            return None
        except LinkClosed as error:
            if error.code == "NOT_PAIRED":  # Unsigned, so it could be forged.
                self.not_recognized()
            elif error.detail:
                log(f"the link did not open: {error}")  # run_link names the code; this is the why.
            return error.code
        self.failures = 0
        self.pairing.state = "paired"
        return await self._session(ws, codec)

    async def _session(self, ws, codec):
        self.ws, self.outbox = ws, asyncio.Queue()
        self.link, self.link_reason = "open", ""
        self.hold, self.held, self.full_ep, self.reported = False, [], None, None
        # This session's cfg and dev re-arm the logsub; the last session's cfg says nothing about this one.
        self.log_subscribed = self.log_identified = self.configured = False
        self.sync_due, self.sync_hold = {}, None
        self.unknown_frames = 0
        self.unknown_kinds.clear()
        self.heard_at = 0.0
        log(f"link open to {self.controller[0]}")
        writer = self.spawn(self._writer(ws, codec, self.outbox))
        pinger = self.spawn(self._pinger())
        try:
            async for message in ws:
                if message.type is not aiohttp.WSMsgType.TEXT:
                    return self._socket_reason(message, ws)
                await self._on_frame(codec.decode(message.data))
            # A close frame carries the peer's code; an ended loop without one is a dead transport.
            return f"CLOSED_{ws.close_code}" if ws.close_code else "SOCKET_RESET"
        except LinkClosed as error:
            log(f"closing the link: {error}")
            return error.code
        except (aiohttp.ClientError, ConnectionError) as error:
            # Deliberately narrow: a local error (a disk OSError, a bug) must
            # bubble to run_link as ERROR instead of posing as a dead socket.
            return f"SOCKET_{type(error).__name__}"
        finally:
            writer.cancel()
            pinger.cancel()
            self.archive.stop()
            self.screens.mux.unpark()
            self.ws = self.outbox = None
            self._set_route("direct")
            self.hold, self.held = False, []
            await ws.close()

    @staticmethod
    def _socket_reason(message, ws):
        """Why the socket ended. aiohttp converts a transport death into a CLOSED
        or ERROR message instead of raising, with a code it chose itself."""
        if message.type is aiohttp.WSMsgType.ERROR:
            return f"SOCKET_{type(message.data).__name__}"
        if message.type is aiohttp.WSMsgType.CLOSED:
            # 1006 marks a reset and 1000 an EOF: aiohttp synthesized the code.
            return "SOCKET_RESET" if ws.close_code in (None, 1006) else "SOCKET_EOF"
        return "PROTOCOL"

    def post(self, frame):
        if self.outbox is None:
            return False
        self.outbox.put_nowait(frame)
        return True

    def post_sync(self, frame, key):
        """A sync request (S17): sent at once outside a sync hold, so none crosses Wi-Fi during a shot;
        otherwise it waits (one per `key`, the newest) for the hold's end."""
        if self.outbox is None:
            return False
        if self.sync_hold is False:
            return self.post(frame)
        self.sync_due[key] = frame
        return True

    def sync_blocked(self):
        """Sync cannot flow now: the link is down, a hold is on (or not known yet), or a request waits."""
        return self.outbox is None or self.sync_hold is not False or bool(self.sync_due)

    def _hold_state(self, frame):
        """The controller sends `hold` whenever a sync hold starts or ends, on every build: during one
        nothing crosses the link either way (no ping, no sync request) and both sides trust it; at its
        end the waiting requests go and a ping checks the link at once. A ping's answer carries the
        store epochs, the replica's heartbeat."""
        if frame.get("t") != "hold":
            return
        was, self.sync_hold = self.sync_hold, frame.get("sync") is True
        if not self.sync_hold:
            due, self.sync_due = self.sync_due, {}
            for request in due.values():
                self.post(request)
        if was is not None and was != self.sync_hold:
            self.ping_now.set()  # The pinger stops for the hold, or pings now that it ended.
        if "sh" in frame or "hi" in frame:
            self.archive.on_heartbeat(frame)

    async def _writer(self, ws, codec, outbox):
        while True:
            frame = await outbox.get()
            try:
                text = codec.encode(frame)
            except ValueError as error:
                log(f"dropped a frame: {error}")
                continue
            try:
                await ws.send_str(text)
            except (aiohttp.ClientError, ConnectionError, RuntimeError):
                await ws.close()
                return

    async def _pinger(self):
        """A ping when the session opens, whenever `up` changes or the route turns to the companion,
        and then every PING_S of the route; none during a sync hold, and one the moment it ends (only a
        missing answer to that one finds a link lost during the shot)."""
        loop = asyncio.get_running_loop()
        while True:
            while self.sync_hold:
                self.ping_now.clear()
                await self.ping_now.wait()
            up, route = self.lm.up, self.route
            self.post({"t": "ping", "up": up})
            deadline = loop.time() + PING_S[route]
            while True:
                self.ping_now.clear()
                try:
                    await asyncio.wait_for(self.ping_now.wait(), max(0.0, deadline - loop.time()))
                except asyncio.TimeoutError:
                    self._stalled(loop.time() - deadline)
                    break
                if self.sync_hold:
                    break
                if self.lm.up != up or self.route != route == "direct":
                    self._stalled(loop.time() - deadline)
                    break
                if self.route != route:  # Back to direct: the slow interval, counted from now.
                    route, deadline = self.route, loop.time() + PING_S[self.route]

    @staticmethod
    def _stalled(late):
        if late >= STALL_WARN_S:
            log(f"the event loop stood still {late:.0f} s before a ping")

    async def _on_frame(self, frame):
        self.heard_at = time.monotonic()
        self._hold_state(frame)
        kind = frame.get("t")
        if not isinstance(kind, str) or kind not in FROM_CONTROLLER:  # A newer controller's: counted, shown.
            self.unknown_frames += 1
            if len(self.unknown_kinds) < 8 and str(kind)[:32] not in self.unknown_kinds:
                self.unknown_kinds.add(str(kind)[:32])
                log(f"ignored a frame this version does not know ({str(kind)[:32]!r}); update the companion")
        elif kind == "cfg":
            self.cfg = {"lm": frame.get("lm") is True, "conn": "api" if frame.get("conn") == "api" else "ws",
                        "observe": frame.get("observe") is not False}
            await self._apply_account()
            self.log_on, self.configured = frame.get("log") is True, True
            self.archive.configure(frame)  # First: it says whether this firmware holds sync during a shot.
            if self._log_usable():  # Kept, so a restart with the controller off still reads the archive.
                try:
                    await self.logs.set_meta("archive", json.dumps(frame.get("archive")))
                except sqlite3.Error as error:
                    log(f"the log store could not keep the archive switch ({error})")
            await self._log_subscribe()
            self._report(force=True)
        elif kind == "creds":
            await self._on_credentials(frame)
        elif kind == "route":
            self._set_route("companion" if frame.get("to") == "companion" else "direct")
        elif kind == "hold":
            self._set_hold(frame.get("on") is True)
        elif kind == "dev":
            self._device_name(frame.get("name"))
            await self._device_id(frame.get("id"))
        elif kind == "log":
            await self._on_log(frame)
        elif kind == "rs":
            self.archive.on_rs(frame)
            self.screens.mux.unpark(frame)
        elif kind == "rec":
            self.archive.on_rec(frame)
        elif kind == "trc":
            self.archive.on_trc(frame)
        else:  # cmd
            command_id, op, value = frame.get("id"), frame.get("op"), frame.get("v")
            if type(command_id) is not int or command_id < 1:
                raise LinkClosed("PROTOCOL", "command without an id")
            if op not in ("temp", "standby", "on", "refresh") or (
                    op == "temp" and (type(value) is not int or not 0 < value < 2000)):
                self.post({"t": "res", "id": command_id, "r": "failed", "http": 0})
            else:
                self.spawn(self._command(command_id, op, value))

    def _set_route(self, route):
        if route == self.route:
            return
        self.route = route
        self.ping_now.set()
        log(f"La Marzocco route: {route}")
        if route == "companion":
            self.full_ep = None
            self._start_full()
        else:
            self.held = []  # Nothing forwards on the direct route.

    def _set_hold(self, on):
        self.hold = on
        if not on and self.held:
            held, self.held = self.held, []
            for frame in held:  # In the order each was last observed.
                if frame["ep"] == self.lm.ep:  # An older subscription says nothing new.
                    self.post(frame)

    def _device_name(self, name):
        """The controller names itself when the link opens and again after a rename."""
        # isprintable() first: it is False for lone surrogates, whose encode() would raise.
        if isinstance(name, str) and name.isprintable() and 0 < len(name.encode()) <= 32:
            if name != self.device_name:
                log(f"the controller is named '{name}'")
                self.device_name = name

    async def _device_id(self, value):
        """The controller's stable id (its MAC text): the log store's key, kept across restarts."""
        if not isinstance(value, str) or not value.isprintable() or not 0 < len(value) <= 24:
            return
        if value != self.device_id:
            self.device_id = value
            if self._log_usable():
                try:
                    await self.logs.set_meta("device", value)
                except sqlite3.Error as error:
                    log(f"the log store could not keep the controller's id ({error})")
        self.log_identified = True
        await self._log_subscribe()
        self.archive.start()

    # --- Diagnostic log ---------------------------------------------------------
    def _log_usable(self):
        """A store that opened: a companion whose log store failed keeps every
        other feature (the relay, La Marzocco) and simply stores no history."""
        return self.logs.connection is not None

    async def open_log(self):
        """The log store and what it remembers: the controller's id, its archive switch and the sessions
        it accepted."""
        try:
            await self.logs.open()
            self.device_id = await self.logs.meta("device")
            switch = await self.logs.meta("archive")
            self.archive.available, self.archive.on = switch in ("true", "false"), switch == "true"
            self.log_grants = await self.logs.grants()
        except (sqlite3.Error, OSError) as error:
            # A store that cannot open disables only the log history: the
            # relay, the screens and La Marzocco keep working.
            await self.logs.close()
            self.log_error = str(error)
            log(f"the log store could not open ({error}); the log history is disabled")

    async def erase_log(self):
        if self._log_usable():
            try:
                await self.logs.erase()
            except sqlite3.Error as error:
                log(f"the log history could not be erased ({error})")
        self.device_id, self.log_grants, self.log_denials = None, {}, {}

    async def _log_subscribe(self, resync=False):
        """`logsub` with the stored cursor, once per session after cfg turned the
        stream on and `dev` named the controller (so the cursor is that
        controller's); `resync` asks again from it after a frame was lost.
        Either leaves right after a frame that shows no hold (S17)."""
        if not self.log_on or not self.configured or not self.log_identified or self.outbox is None or \
                not self._log_usable() or (
                self.log_subscribed and not resync):
            return
        self.log_subscribed = True
        try:
            boot, after = await self.logs.cursor(self.device_id) or (0, 0)
        except sqlite3.Error as error:
            log(f"the log store could not read its cursor ({error}); the log stream waits for the next link")
            return
        self.post_sync({"t": "logsub", "on": True, "boot": boot, "after": after}, "logsub")

    async def _on_log(self, frame):
        """One page of the controller's log, stored with the hole it names.

        A log frame never closes the link: text out of bounds is cut, a frame
        whose events cannot be keyed is dropped and counted, and a frame the
        store could not write is asked for again from the stored cursor, so
        it leaves no hole behind.
        """
        if not self._log_usable() or self.device_id is None:
            return  # A closed store logged why once; no id means no subscription either.
        rows = _log_rows(frame)
        if rows is None:
            self.log_dropped += len(frame["e"]) if isinstance(frame.get("e"), list) else 1
            log("dropped a log frame whose events have no usable boot or sequence")
            return
        try:
            await self.logs.apply(self.device_id, {"b": frame["b"], "e": rows, "miss": frame.get("miss", 0),
                                                   "reset": frame.get("reset") is True})
        except sqlite3.Error as error:
            log(f"the log store failed ({error}); asking the controller again from the stored cursor")
            await self._log_subscribe(resync=True)

    async def ui_access(self, headers, live=False):
        """Whether this browser may read the stored log and archive: exactly when
        the controller lets it open the Web UI (`GET /api/v1/auth` through the
        relay). Each session's answer is kept for LOG_ACCESS_RECHECK_S, and an
        accepted one is remembered on disk, so it keeps reading while the
        controller is off; a controller that did not answer is not asked again
        for LOG_UNREACHABLE_S, so a page never waits on it twice in a row.
        `live` (changing the archive or the log) needs the controller's answer
        now: (signed in, Admin unlocked for this screen), or None when it
        cannot give one."""
        session = hashlib.sha256(headers.get("X-WebUI-Session", "").encode()).hexdigest()
        now = time.time()
        for answers, verdict in ((self.log_grants, True), (self.log_denials, False)):
            if not live and session in answers and now - answers[session] < LOG_ACCESS_RECHECK_S:
                return verdict
        answer = None
        if live or now - self.log_unreachable >= LOG_UNREACHABLE_S:
            answer = await self._web_ui_allows(headers)
            if answer is None:
                self.log_unreachable = now
        allowed = None if answer is None else answer[0]
        if allowed is None:
            if live:
                return None
            if session in self.log_grants:
                self.log_grants[session] = now  # What the controller said last stands until it can answer.
            return session in self.log_grants
        answers, other = (self.log_grants, self.log_denials) if allowed else (self.log_denials, self.log_grants)
        other.pop(session, None)
        answers[session] = now
        if not allowed:  # Kept in memory only, and only while it counts.
            self.log_denials = {key: at for key, at in self.log_denials.items() if now - at < LOG_ACCESS_RECHECK_S}
        try:
            await self.logs.grant(session, allowed)
        except sqlite3.Error as error:
            log(f"the log store could not keep a Web UI session's access ({error})")
        return answer if live else allowed

    async def _web_ui_allows(self, headers):
        """The controller's answer for this browser: (signed in, Admin unlocked for this screen), or None
        when it cannot answer. It asks through the relay as the screen itself (its own X-WebUI-Client,
        signed), so the unlock it reads is that screen's, never the companion's shared client's; without
        a relay session, or without the screen's id, nothing counts as unlocked."""
        if self.controller is None:
            return None
        client = headers.get("X-WebUI-Client", "")
        screen = client if CLIENT_ID.fullmatch(client) else None
        try:
            reply = None
            if self.relay.mode != "disabled":
                reply = await self.relay.request("GET", "/api/v1/auth", headers, b"",
                                                 address(headers.get("X-Real-IP")), screen or self.relay.client_id,
                                                 False)
            relayed = reply is not None
            if reply is None:  # No relay session: the session would cross the LAN in clear, so ask as nobody.
                reply = await self.relay.passthrough("GET", "/api/v1/auth", {}, b"")
            try:
                answer = json.loads(reply.data) if reply.status == 200 and reply.data else None
            finally:
                reply.release()
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
            return None
        if not isinstance(answer, dict):
            return None
        return (answer.get("loginRequired") is False or answer.get("signedIn") is True,
                relayed and screen is not None and answer.get("adminUnlocked") is True)

    # --- La Marzocco account ---------------------------------------------------
    async def _apply_account(self):
        account = await offload(self.store.credentials) if self.cfg["lm"] else None
        self.lm.configure(account, self.cfg["conn"], self.cfg["observe"])

    async def _on_credentials(self, frame):
        generation = frame.get("gen")
        if type(generation) is not int or generation < 0:
            raise LinkClosed("PROTOCOL", "credentials without a generation")
        if frame.get("erase") is True:
            await offload(self.store.erase_account)
            self.creds_gen = None
            await self._apply_account()
            log("the controller erased the La Marzocco account")
            return
        try:
            plain = crypto.decrypt_credentials((await offload(self.store.pairing))["secret"],
                                               generation,
                                               crypto.unb64(frame.get("iv"), 12), crypto.unb64(frame.get("ct")))
            decoded = json.loads(plain)
            account = {key: decoded[key] for key in ("email", "password", "serial")}
            if not all(isinstance(value, str) and value for value in account.values()) or \
                    SERIAL_FORBIDDEN.intersection(account["serial"]):
                raise ValueError()
        except (ValueError, KeyError, TypeError, InvalidTag):
            raise LinkClosed("PROTOCOL", "credentials did not decrypt") from None
        await offload(self.store.save_credentials, generation, account)
        self.creds_gen = generation
        log(f"received the La Marzocco account (generation {generation})")
        if self.lm.rejected_for(account):
            self.account(False)
        elif self.lm.signed_in_for(account):
            self.account(True)
        else:
            await self._apply_account()

    # --- Events from the La Marzocco client ------------------------------------
    def account(self, ok):
        """A sign-in (also one a read or command needed) or a refusal: report it with the new token's life."""
        if self.creds_gen is not None and self.post({"t": "creds", "gen": self.creds_gen, "ok": ok}):
            self.creds_gen = None
        self._report(force=True)

    def upstream(self):
        self.ping_now.set()
        self._report()

    def subscribed(self):
        self._start_full()

    def pushed(self, data, ac):
        if self.expect and dashboard.confirms(data, *self.expect):
            self.expect = None
            if self.confirm_timer:
                self.confirm_timer.cancel()
                self.confirm_timer = None
        self._forward("push", data, ac)

    def polled(self, data, ac, first):
        if first and self._forward("full", data, ac):
            self.full_ep = self.lm.ep
        elif not first:
            self._forward("read", data, ac)

    def renewed(self):
        self._report(force=True)
        if self.route == "companion":
            self.spawn(self._read_and_forward())

    def _report(self, force=False):
        state = (self.lm.sub, self.lm.ep, self.lm.refused)
        frame = {"t": "lm", "sub": self.lm.sub, "ep": self.lm.ep, "tok": self.lm.tok}
        if self.lm.refused:
            frame["err"] = "auth"  # The subscription lives, but reads and commands answer 401/403.
        if (force or state != self.reported) and self.post(frame):
            self.reported = state

    # --- Machine state -----------------------------------------------------------
    def _forward(self, kind, data, ac, ep=None):
        """Send one observation while the route is the companion's; a hold keeps
        the latest push and read back until it ends."""
        if self.route != "companion" or self.outbox is None:
            return False
        reduced = dashboard.reduce(data, push=kind == "push")
        if reduced is None:
            return False
        frame = {"t": "st", "k": kind, "ep": self.lm.ep if ep is None else ep, "d": reduced}
        if kind != "push":  # Pushes take their order from when the controller receives them.
            frame["ac"] = ac
        if kind != "full" and self.hold:  # The latest of each kind, in observation order.
            self.held = [held for held in self.held if held["k"] != kind] + [frame]
            return True
        return self.post(frame)

    def _start_full(self):
        if self.route == "companion" and (self.full_task is None or self.full_task.done()):
            self.full_task = self.spawn(self._full())

    async def _full(self):
        """The read after a new subscription, sent as `full` once per route start and epoch."""
        for index in range(len(FULL_RETRY_S)):
            if self.route != "companion" or self.outbox is None or not self.lm.sub or self.full_ep == self.lm.ep:
                return
            ep = self.lm.ep
            _, data, ac = await self.lm.read()
            if data is not None and ep == self.lm.ep != self.full_ep and self._forward("full", data, ac, ep):
                self.full_ep = ep
                return
            if index + 1 < len(FULL_RETRY_S):
                await asyncio.sleep(FULL_RETRY_S[index])  # Bounded: a route restart or epoch re-arms it.

    async def _read_and_forward(self):
        status, data, ac = await self.lm.read()
        if data is not None:
            self._forward("read", data, ac)
        return status, data

    async def _command(self, command_id, op, value):
        async with self.command_lock:
            if op == "refresh":
                status, data = await self._read_and_forward()
                accepted = data is not None
            else:
                expected = (op, value)
                self.expect = expected  # A push may confirm it before La Marzocco answers the request.
                status = await self.lm.command(command_id, op, value)
                accepted = 200 <= status < 300
                if self.expect == expected:
                    if self.confirm_timer:
                        self.confirm_timer.cancel()
                    self.expect = expected if accepted else None
                    self.confirm_timer = asyncio.get_running_loop().call_later(
                        CONFIRM_S, self._unconfirmed) if accepted else None
            log(f"command {command_id} ({op}): " + ("accepted" if accepted else f"failed, HTTP {status}"))
            self.post({"t": "res", "id": command_id, "r": "accepted"} if accepted else
                      {"t": "res", "id": command_id, "r": "failed", "http": status})

    def _unconfirmed(self):
        """No push showed the command's outcome in time: read the machine once instead."""
        self.expect = self.confirm_timer = None
        self.spawn(self._read_and_forward())

    # --- Pages -----------------------------------------------------------------
    async def status(self):
        pairing = await offload(self.store.pairing)
        credentials = await offload(self.store.credentials)
        log_facts = {"enabled": self.log_on, "days": self.retention[0], "mb": self.retention[1],
                     "dropped": self.log_dropped}
        try:
            log_facts.update(await self.logs.stats(self.device_id) if self._log_usable()
                             else {"error": self.log_error or "not open"})
        except sqlite3.Error as error:
            log_facts["error"] = str(error)
        try:
            archive_facts = await self.archive.facts()
        except sqlite3.Error as error:
            archive_facts = {"on": self.archive.on, "available": self.archive.available, "error": str(error)}
        return {
            "name": self.name, "version": VERSION, "id": self.id,
            "paired": pairing is not None,
            "pairedWith": (self.device_name or pairing.get("controller")) if pairing else None,
            "controller": {"name": self.device_name or self.controller[0],
                           "address": self.base_url().removeprefix("http://")}
            if self.controller else None,
            "pairing": self.pairing.status(),
            "link": self.link, "linkReason": self.link_reason or None,
            "route": self.route, "unknownFrames": self.unknown_frames,
            "laMarzocco": {"enabled": self.cfg["lm"], "account": credentials is not None,
                           "connection": self.cfg["conn"], "subscribed": self.lm.sub, "up": self.lm.up,
                           "refused": self.lm.refused},
            "log": log_facts, "archive": archive_facts,
            "relay": self.relay.mode, **self.screens.mux.status(),
        }


def _log_rows(frame):
    """A `log` frame's events made storable, or None when one cannot be keyed
    (no boot, no positive sequence): an unknown level reads as info and text
    past its bounds is cut, so the content never costs an event."""
    boot, events, miss = frame.get("b"), frame.get("e"), frame.get("miss", 0)
    if not _uint32(boot) or not isinstance(events, list) or not events or not _uint32(miss):
        return None
    rows = []
    for entry in events:
        if not isinstance(entry, list) or len(entry) != 6 or not _uint32(entry[0]) or entry[0] == 0:
            return None
        sequence, at_ms, wall_sec, level, category, message = entry
        rows.append([sequence, at_ms if _uint32(at_ms) else 0, wall_sec if _uint32(wall_sec) else 0,
                     level if level in LOG_LEVELS else "i", str(category)[:LOG_CATEGORY_MAX],
                     str(message)[:LOG_MESSAGE_MAX]])
    return rows


def _uint32(value):
    return type(value) is int and 0 <= value < 2 ** 32


def render_page(name="page.html"):
    """A companion page, styled like the setup page it sits beside."""
    setup = (HERE.parent / "gateway" / "setup.html").read_text()
    style = setup[setup.index("<style>") + 7:setup.index("</style>")]
    return (HERE / name).read_text().replace("@STYLE@", style)


def web_app(companion):
    page = render_page()
    notice = render_page("ui-off.html").replace("@VERSION@", html.escape(VERSION)).replace(
        "@NAME@", html.escape(companion.name))
    no_store = {"Cache-Control": "no-store"}

    async def show(request):
        return web.Response(text=page, content_type="text/html", headers=no_store)

    async def gate(request):
        """nginx asks before each Web UI page: 403 shows the notice while the Web UI opens directly."""
        page = request.headers.get("X-Original-URI", "").partition("?")[0]
        allowed = companion.relay.mode != "disabled" or page == "/sw.js"
        return web.Response(status=204 if allowed else 403)

    async def ui_off(request):
        address = html.escape(companion.base_url()) if companion.controller else ""
        return web.Response(text=notice.replace("@ADDRESS@", address), content_type="text/html",
                            headers=no_store)

    async def status(request):
        return web.json_response(await companion.status(), headers=no_store)

    async def pair(request):
        if request.content_type != "application/json":  # A web page elsewhere cannot send this without asking.
            return web.json_response({"error": "UNSUPPORTED_MEDIA_TYPE"}, status=415)
        if companion.controller is None:
            return web.json_response({"error": "NO_CONTROLLER", "message": "No controller found yet"}, status=409)
        companion.pairing.start(manual=True)
        return web.json_response(companion.pairing.status(), status=202, headers=no_store)

    async def erase(request):
        if request.content_type != "application/json":
            return web.json_response({"error": "UNSUPPORTED_MEDIA_TYPE"}, status=415)
        if await offload(companion.store.pairing) is None or companion.ws is not None or companion.pairing.state in (
                "paired", "requesting", "pending"):
            return web.json_response({"error": "IN_USE", "message": "Only a pairing the controller no longer "
                                      "recognizes can be erased here; use Forget in Admin"}, status=409)
        await companion.erase("erased on the companion's page", history=False)
        return web.json_response(await companion.status(), headers=no_store)

    def _wall(value):
        """Wall seconds in uint32 range, or None when absent; ValueError otherwise."""
        if value is None:
            return None
        value = int(value)
        if not 0 <= value < 2 ** 32:
            raise ValueError()
        return value

    def _log_query(request):
        """The page's keyset cursor (boot, before; the newest first when absent), its size, and the
        optional filters: `level` (the levels kept, from "cewid"), `category` and `at` (wall seconds:
        start at the newest event at or before it)."""
        query = request.query
        try:
            boot = int(query.get("boot", FIRST_PAGE))
            before = int(query.get("before", FIRST_PAGE))
            limit = min(max(int(query.get("limit", 100)), 1), 500)
            at = _wall(query.get("at"))
        except ValueError:
            return None
        levels, category = query.get("level"), query.get("category")
        if boot < 0 or before < 0 or (levels is not None and not (levels and set(levels) <= set(LOG_LEVELS))) \
                or (category is not None and not re.fullmatch(r"[a-z_]{1,24}", category)):
            return None
        return boot, before, limit, levels and tuple(sorted(set(levels))), category, at

    async def _log_refusal(request, live=False, admin=False):
        """The history answers with the controller down, but only to a browser it would let in;
        changing the archive (`live`) needs the controller's answer now, and deleting (`admin`) also
        needs Admin unlocked on the screen asking."""
        if not companion._log_usable():
            return web.json_response({"error": "STORE", "message": companion.log_error or "not open"}, status=503)
        answer = await companion.ui_access(request.headers, live or admin)
        if answer is None:
            return web.json_response({"error": "CONTROLLER_UNREACHABLE", "message": "The controller must be on "
                                      "to confirm your sign-in"}, status=503)
        if not (answer[0] if live or admin else answer):
            return web.json_response({"error": "AUTH_REQUIRED", "message": "Sign in to the Web UI through "
                                      "the companion while the controller is on"}, status=401)
        if admin and not answer[1]:
            log(f"refused {request.path}: Admin is not unlocked on the screen that asked")
            return web.json_response({"error": "ADMIN_LOCKED", "message": "Unlock Admin in the Web UI opened "
                                      "through the companion, then try again"}, status=401)
        return None

    async def log_page(request):
        query = _log_query(request)
        if query is None:
            return web.json_response({"error": "INVALID_REQUEST"}, status=400)
        refusal = await _log_refusal(request)
        if refusal is not None:
            return refusal
        try:
            entries, following, has_more = await companion.logs.page(companion.device_id, *query)
        except sqlite3.Error as error:
            return web.json_response({"error": "STORE", "message": str(error)}, status=500)
        return web.json_response({
            "device": companion.device_id, "entries": entries,
            "next": {"boot": following[0], "before": following[1]} if following else None,
            "hasMore": has_more}, headers=no_store)

    async def log_export(request):
        """The whole history, or the events between wall times `from` and `to` (either may be absent)."""
        try:
            since, until = _wall(request.query.get("from")), _wall(request.query.get("to"))
        except ValueError:
            return web.json_response({"error": "INVALID_REQUEST"}, status=400)
        refusal = await _log_refusal(request)
        if refusal is not None:
            return refusal
        device = companion.device_id
        try:
            span = await companion.logs.bounds(device, since, until)
        except sqlite3.Error as error:
            return web.json_response({"error": "STORE", "message": str(error)}, status=500)
        name = "obbw-log" + ("-" + re.sub(r"[^A-Za-z0-9]", "-", device) if device else "")
        answer = web.StreamResponse(headers={"Content-Type": "application/json",
                                             "Content-Disposition": f'attachment; filename="{name}.json"',
                                             "Cache-Control": "no-store"})
        await answer.prepare(request)
        head = {"format": FORMAT, "version": EXPORT_VERSION, "device": device}
        await answer.write(json.dumps(head)[:-1].encode() + b',"entries":[')
        cursor, first = span[0] if span else None, True
        try:
            while cursor is not None:
                entries, cursor = await companion.logs.chunk(device, *cursor, through=span[1])
                for entry in entries:
                    await answer.write((("" if first else ",") + json.dumps(entry)).encode())
                    first = False
        except sqlite3.Error as error:
            await answer.write((("" if first else ",") + json.dumps({"error": str(error)})).encode())
        await answer.write(b"]}")
        await answer.write_eof()
        return answer

    async def log_delete(request):
        if request.content_type != "application/json":
            return web.json_response({"error": "UNSUPPORTED_MEDIA_TYPE"}, status=415)
        refusal = await _log_refusal(request, admin=True)
        if refusal is not None:
            return refusal
        try:
            await companion.logs.erase(history_only=True)
        except sqlite3.Error as error:
            return web.json_response({"error": "STORE", "message": str(error)}, status=500)
        log("the log history was deleted from the Web UI's Diagnostic")
        return web.json_response({"deleted": True}, headers=no_store)

    # --- The archive ---------------------------------------------------------
    def _numbers(source, *names, optional=()):
        """Whole numbers in uint32 range, a `generation` also below zero (records set aside); a name in
        `optional` may be absent (None)."""
        try:
            values = [None if name in optional and source.get(name) is None else int(source[name])
                      for name in names]
        except (KeyError, TypeError, ValueError):
            return None
        return values if all(value is None or (-2 ** 31 if name == "generation" else 0) <= value < 2 ** 32
                             for name, value in zip(names, values)) else None

    def _invalid():
        return web.json_response({"error": "INVALID_REQUEST"}, status=400)

    async def _archive_body(request, admin=False):
        """(body, refusal): a JSON object from a browser the controller accepts right now (and, for
        `admin`, from a screen with Admin unlocked)."""
        if request.content_type != "application/json":
            return None, web.json_response({"error": "UNSUPPORTED_MEDIA_TYPE"}, status=415)
        try:
            body = await request.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return None, _invalid()
        return body, await _log_refusal(request, live=True, admin=admin)

    def _archive_query(store, query):
        """The tail's sort, direction, cursor and filters with the controller's whitelists, or None."""
        def listed(name, allowed=None):
            values = [value for value in query.get(name, "").split(",") if value]
            if allowed is None:
                values = [int(value) for value in values]
                if not all(0 <= value < 2 ** 32 for value in values):
                    raise ValueError()
            elif not set(values) <= allowed:
                raise ValueError()
            if len(values) > FILTER_MAX:
                raise ValueError()
            return values
        try:
            parsed = {"sort": query.get("sort", "date"), "dir": query.get("dir", "desc"), "bad": query.get("bad") == "1",
                      "all": query.get("all") == "1",
                      "result": listed("result", RESULTS) if store == "shots" else [],
                      "preset": listed("preset") if store == "shots" else [],
                      "scale": listed("scale") if store == "shots" else [],
                      "types": listed("types", HISTORY_TYPES) if store == "history" else [],
                      "cursor": tuple(int(part) for part in query["cursor"].split(":")) if "cursor" in query else None}
            limit = int(query.get("limit", 20))
        except ValueError:
            return None
        sorts = ("date", "rating") if store == "shots" else ("date",)
        if parsed["sort"] not in sorts or parsed["dir"] not in ("desc", "asc") or not 1 <= limit <= FETCH_MAX[store] \
                or (parsed["cursor"] is not None and len(parsed["cursor"]) != (4 if parsed["sort"] == "rating" else 2)):
            return None
        return parsed, limit

    async def archive_rows(request):
        store = request.match_info["store"]
        query = _archive_query(store, request.query)
        if query is None:
            return _invalid()
        refusal = await _log_refusal(request)
        if refusal is not None:
            return refusal
        if query[0]["all"] and not companion.archive.on:  # The controller-off view follows the switch.
            return web.json_response({"error": "ARCHIVE_OFF"}, status=409)
        rows, following, holes, generations, presets = await companion.archive.store.tail(
            companion.device_id, store, *query)
        answer = {"device": companion.device_id, "rows": rows, "next": following, "holes": holes,
                  "generations": generations}
        if presets is not None:
            answer["presets"] = presets
        return web.json_response(answer, headers=no_store)

    async def archive_stats(request):
        """The Stats header over the whole history (S13), or 503 STATS_UNAVAILABLE: the browser then
        shows the controller's own header, labelled as covering only its shots, and asks again."""
        query = request.query
        try:
            window, active, epoch = int(query["window"]), int(query.get("active", 0)), int(query["epoch"])
            filters = _archive_query("shots", {key: query[key] for key in ("result", "preset", "scale") if key in query})
        except (KeyError, ValueError):
            filters = None
        if filters is None or window not in STATS_WINDOWS or not 0 <= active < 256 or not 0 <= epoch < 2 ** 32:
            return _invalid()
        refusal = await _log_refusal(request)
        if refusal is not None:
            return refusal
        parsed = filters[0]
        chosen = (tuple(stats.VERDICTS[name] for name in parsed["result"]), tuple(parsed["preset"]),
                  tuple(parsed["scale"]))
        try:
            header, good, synced = await companion.archive.header(window, active, epoch, chosen)
        except (Unavailable, sqlite3.Error) as error:
            companion.archive.note_unavailable(error)
            return web.json_response({"error": "STATS_UNAVAILABLE"}, status=503)
        return web.json_response({"stats": header, "good": good, "epoch": synced}, headers=no_store)

    async def archive_trace(request):
        identity = _numbers(request.query, "id", "boot", "end")
        if identity is None:
            return _invalid()
        refusal = await _log_refusal(request)
        if refusal is not None:
            return refusal
        data = await companion.archive.store.trace(companion.device_id, *identity)
        if data is None:
            return web.json_response({"error": "NO_SHOT_TRACE"}, status=404)
        return web.Response(body=data, content_type="application/octet-stream", headers=no_store)

    def _found(done):
        return web.json_response({"ok": True}, headers=no_store) if done else \
            web.json_response({"error": "NOT_FOUND"}, status=404)

    async def archive_rate(request):
        body, refusal = await _archive_body(request)
        if refusal is not None:
            return refusal
        values = _numbers(body, "generation", "id", "rating", optional=("generation",))
        if values is None or values[2] > 5:
            return _invalid()
        return _found(await companion.archive.store.rate(companion.device_id, *values))

    async def archive_delete(request):
        """One record only the archive holds (rotated out of the controller, or from an earlier history),
        from a screen with Admin unlocked; the controller deletes its own records itself, and the
        archive follows on its next sync."""
        body, refusal = await _archive_body(request, admin=True)
        if refusal is not None:
            return refusal
        values = _numbers(body, "generation", "id", optional=("generation",))
        if values is None or body.get("store") not in FETCH_MAX:
            return _invalid()
        return _found(await companion.archive.store.remove(companion.device_id, body["store"], *values))

    async def archive_export(request):
        refusal = await _log_refusal(request)
        if refusal is not None:
            return refusal
        device, store = companion.device_id, companion.archive.store
        name = "obbw-archive" + ("-" + re.sub(r"[^A-Za-z0-9]", "-", device) if device else "")
        answer = web.StreamResponse(headers={"Content-Type": "application/json",
                                             "Content-Disposition": f'attachment; filename="{name}.json"',
                                             "Cache-Control": "no-store"})
        await answer.prepare(request)
        head = {"format": "openbrewbyweight-companion-archive", "version": 1, "device": device}
        await answer.write(json.dumps(head)[:-1].encode())
        for key, read in (("shots", lambda after: store.chunk(device, "shots", after)),
                          ("history", lambda after: store.chunk(device, "history", after)),
                          ("traces", lambda after: store.trace_chunk(device, after))):
            await answer.write(f',"{key}":['.encode())
            after, first = (-2 ** 63, 0), True  # Records set aside sit below generation 1.
            while after is not None:
                items, after = await read(after)
                for item in items:
                    await answer.write((("" if first else ",") + json.dumps(item)).encode())
                    first = False
            await answer.write(b"]")
        await answer.write(f',"holes":{json.dumps(await store.holes(device))}}}'.encode())
        await answer.write_eof()
        return answer

    app = web.Application(client_max_size=2 << 20)  # An OTA chunk is 64 KiB; nginx allows 1 MiB.
    app.router.add_get("/__companion/", show)
    app.router.add_get("/__companion/ui-gate", gate)
    app.router.add_get("/__companion/ui-off", ui_off)
    app.router.add_routes(companion.screens.routes())
    app.router.add_get("/__companion/pair", show)
    app.router.add_get("/__companion/status", status)
    app.router.add_get("/__companion/log", log_page)
    app.router.add_get("/__companion/log/export", log_export)
    app.router.add_post("/__companion/log/delete", log_delete)
    app.router.add_get("/__companion/archive/{store:shots|history}", archive_rows)
    app.router.add_get("/__companion/archive/trace", archive_trace)
    app.router.add_get("/__companion/archive/stats", archive_stats)
    app.router.add_get("/__companion/archive/export", archive_export)
    app.router.add_post("/__companion/archive/rate", archive_rate)
    app.router.add_post("/__companion/archive/delete", archive_delete)
    app.router.add_post("/__companion/pair", pair)
    app.router.add_post("/__companion/erase", erase)
    return app


class Handle:
    """What the supervisor's thread may call; each call runs on the companion's loop."""

    loop = companion = stopping = None

    def controller(self, target):
        if self.loop:
            self.loop.call_soon_threadsafe(self.companion.set_controller, target)

    def stop(self):
        if self.loop:
            self.loop.call_soon_threadsafe(self.stopping.set)


async def _retention(companion):
    """On start and daily: prune the log store by age, then to the size budget,
    and refresh its consistent copy for backups of the data folder."""
    while True:
        if companion._log_usable():
            try:
                days, megabytes = companion.retention
                deleted = await companion.logs.prune(days, megabytes, companion.device_id)
                if deleted:
                    log(f"log retention pruned {deleted} event(s)")
                await companion.logs.backup()
            except (sqlite3.Error, OSError) as error:
                log(f"log retention failed ({error})")
        await asyncio.sleep(RETENTION_S)


async def _serve(cfg, data, socket_path, handle, ready):
    # One connection per request: the controller has few sockets.
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as controller, \
            aiohttp.ClientSession() as cloud:
        companion = Companion(cfg["name"], data, controller,
                              lambda store, events: LaMarzocco(store, cloud, events))
        companion.retention = (cfg.get("log_retention_days", RETENTION_DAYS_DEFAULT),
                               cfg.get("log_retention_mb", RETENTION_MB_DEFAULT))
        await companion.open_log()
        runner = web.AppRunner(web_app(companion), access_log=None)
        await runner.setup()
        socket_path.unlink(missing_ok=True)
        await web.UnixSite(runner, str(socket_path)).start()
        socket_path.chmod(0o666)  # nginx workers run as the nginx user.
        handle.loop, handle.companion, handle.stopping = asyncio.get_running_loop(), companion, asyncio.Event()
        ready.set()
        log(f"'{cfg['name']}' version {VERSION} is running")
        link = companion.spawn(companion.run_link())
        companion.spawn(_loop_watchdog())
        companion.spawn(_retention(companion))
        stopping = companion.spawn(handle.stopping.wait())
        try:
            await asyncio.wait({link, stopping}, return_when=asyncio.FIRST_COMPLETED)
            if not stopping.done():
                raise RuntimeError("the link loop ended")
        finally:
            companion.lm.stop()
            await runner.cleanup()
            await companion.relay.close()
            await companion.logs.close()


async def _loop_watchdog():
    """Measure the loop's own sleep overshoot: whatever blocks the loop shows up here."""
    loop = asyncio.get_running_loop()
    while True:
        before = loop.time()
        await asyncio.sleep(WATCHDOG_S)
        late = loop.time() - before - WATCHDOG_S
        if late >= STALL_BREACH_S:
            log(f"the event loop stood still {late:.0f} s: long enough for the controller to miss its pings")
        elif late >= STALL_WARN_S:
            log(f"the event loop stood still {late:.0f} s")


def start(cfg, data, run, on_exit):
    """Run the companion on its own thread; on_exit runs if it ever stops."""
    handle, ready = Handle(), threading.Event()

    def main():
        try:
            asyncio.run(_serve(cfg, data, run / "companion.sock", handle, ready))
        except Exception:
            log("stopped after an error:\n" + traceback.format_exc())
        finally:
            ready.set()
            on_exit()

    threading.Thread(target=main, name="companion", daemon=True).start()
    ready.wait(30)
    return handle
