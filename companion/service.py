"""The companion service: pairing, the Web UI relay, the controller link, the La Marzocco route and its pages.

It runs on its own thread and event loop inside the gateway supervisor, which
tells it the controller's address on start and on every mDNS announcement.
nginx serves its pages under /__companion/, and the Web UI's API and live
updates, through a Unix socket.
"""

import asyncio
import html
import json
import threading
import time
import traceback
from pathlib import Path

import aiohttp
from aiohttp import web
from cryptography.exceptions import InvalidTag

from . import VERSION, crypto, dashboard, log
from .lamarzocco import LaMarzocco
from .link import Erased, LinkClosed, open_link
from .pairing import Pairing
from .relay import Relay
from .screens import Screens
from .store import Store, offload

HERE = Path(__file__).resolve().parent
BACKOFF_S = (0, 5, 15, 60, 300)  # The first reopen is immediate; then it backs off.
RETRY_LATER_S = 15  # The controller is busy with its scale: a steady short retry, never a longer one.
FROM_CONTROLLER = frozenset({"cfg", "creds", "route", "hold", "cmd", "dev"})
PING_S = {"companion": 15, "direct": 120}
# A sleep that comes back this late means the loop stood still; 20 s is where
# the controller's 30 s ping contract starts to break.
STALL_WARN_S = 5
WATCHDOG_S = 10
STALL_BREACH_S = 20
CONFIRM_S = 5
FULL_RETRY_S = (1, 2, 5, 10, 30)
HTTP_TIMEOUT_S = 10
SERIAL_FORBIDDEN = set("\r\n:\\/")


class Companion:
    def __init__(self, name, data, http, upstream):
        self.name, self.http = name, http
        self.store = Store(data)
        self.id, self.key = self.store.identity()
        self.public = crypto.public_point(self.key)
        self.controller = None  # (name, (ip, port)) from the supervisor
        self.device_name = None  # The controller's own name, from its `dev` frame.
        self.tasks = set()
        self.wake = asyncio.Event()
        self.pairing = Pairing(self)
        self.link, self.link_reason, self.failures = "down", "", 0
        self.ws = self.outbox = None
        self.route, self.hold, self.held = "direct", False, None
        self.ping_now = asyncio.Event()
        self.heard_at = 0.0  # time.monotonic() of the last controller frame.
        self.unknown_frames, self.unknown_kinds = 0, set()
        self.cfg = {"lm": False, "conn": "ws", "observe": True}
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

    async def erase(self, why):
        """Delete the pairing, the La Marzocco account and its installation key."""
        await offload(self.store.erase_pairing)
        self.lm.erase()
        self.creds_gen = None
        self.device_name = None  # It named the pairing, not this controller.
        self.pairing.state, self.pairing.auto = "unpaired", False
        self.relay.reset()
        log(f"{why}; its pairing, La Marzocco account and installation key are erased")
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
        FIN or RST — is found now, not at the next ping cadence."""
        if self.ws is not None:
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
        self.hold, self.held, self.full_ep, self.reported = False, None, None, None
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
            self.ws = self.outbox = None
            self._set_route("direct")
            self.hold, self.held = False, None
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
        and then every PING_S of the route."""
        loop = asyncio.get_running_loop()
        while True:
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
            self._report(force=True)
        elif kind == "creds":
            await self._on_credentials(frame)
        elif kind == "route":
            self._set_route("companion" if frame.get("to") == "companion" else "direct")
        elif kind == "hold":
            self._set_hold(frame.get("on") is True)
        elif kind == "dev":
            self._device_name(frame.get("name"))
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

    def _set_hold(self, on):
        self.hold = on
        if not on and self.held:
            held, self.held = self.held, None
            if held["ep"] == self.lm.ep:  # A read from an older subscription says nothing new.
                self.post(held)

    def _device_name(self, name):
        """The controller names itself when the link opens and again after a rename."""
        # isprintable() first: it is False for lone surrogates, whose encode() would raise.
        if isinstance(name, str) and name.isprintable() and 0 < len(name.encode()) <= 32:
            if name != self.device_name:
                log(f"the controller is named '{name}'")
                self.device_name = name

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
        """Send one observation while the route is the companion's; reads wait out a hold."""
        if self.route != "companion" or self.outbox is None:
            return False
        reduced = dashboard.reduce(data, push=kind == "push")
        if reduced is None:
            return False
        frame = {"t": "st", "k": kind, "ep": self.lm.ep if ep is None else ep, "d": reduced}
        if kind != "push":  # Pushes take their order from when the controller receives them.
            frame["ac"] = ac
        if kind == "read" and self.hold:
            self.held = frame
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
            "relay": self.relay.mode, **self.screens.mux.status(),
        }


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
        await companion.erase("erased on the companion's page")
        return web.json_response(await companion.status(), headers=no_store)

    app = web.Application(client_max_size=2 << 20)  # An OTA chunk is 64 KiB; nginx allows 1 MiB.
    app.router.add_get("/__companion/", show)
    app.router.add_get("/__companion/ui-gate", gate)
    app.router.add_get("/__companion/ui-off", ui_off)
    app.router.add_routes(companion.screens.routes())
    app.router.add_get("/__companion/pair", show)
    app.router.add_get("/__companion/status", status)
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


async def _serve(cfg, data, socket_path, handle, ready):
    # One connection per request: the controller has few sockets.
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as controller, \
            aiohttp.ClientSession() as cloud:
        companion = Companion(cfg["name"], data, controller,
                              lambda store, events: LaMarzocco(store, cloud, events))
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
        stopping = companion.spawn(handle.stopping.wait())
        try:
            await asyncio.wait({link, stopping}, return_when=asyncio.FIRST_COMPLETED)
            if not stopping.done():
                raise RuntimeError("the link loop ended")
        finally:
            companion.lm.stop()
            await runner.cleanup()
            await companion.relay.close()


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
