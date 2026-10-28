"""The companion service: pairing, the controller link, the La Marzocco route and its pages.

It runs on its own thread and event loop inside the gateway supervisor, which
tells it the controller's address on start and on every mDNS announcement.
nginx serves its pages under /__companion/ through a Unix socket.
"""

import asyncio
import itertools
import json
import threading
import traceback
from pathlib import Path

import aiohttp
from aiohttp import web
from cryptography.exceptions import InvalidTag

from . import VERSION, crypto, dashboard, log
from .lamarzocco import LaMarzocco
from .link import Erased, LinkClosed, open_link
from .pairing import Pairing
from .store import Store

HERE = Path(__file__).resolve().parent
BACKOFF_S = (5, 15, 60, 300)
PING_S = {"companion": 15, "direct": 120}
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
        self.tasks = set()
        self.wake = asyncio.Event()
        self.pairing = Pairing(self)
        self.link, self.link_reason = "down", ""
        self.ws = self.outbox = None
        self.route, self.hold, self.held = "direct", False, None
        self.route_changed = asyncio.Event()
        self.cfg = {"lm": False, "conn": "ws", "observe": True}
        self.creds_gen = None  # Generation whose sign-in result the controller still waits for.
        self.full_ep, self.full_task = None, None
        self.expect, self.confirm_timer = None, None
        self.command_lock = asyncio.Lock()
        self.reported = None
        self.lm = upstream(self.store, self)

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
        if self.ws is None:
            self.wake.set()  # Reconnect now instead of waiting out the backoff.
        self.pairing.start()

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

    def paired(self, secret):
        self.store.erase_account()
        self.lm.erase()
        self.store.save_pairing(secret, self.controller[0])
        log(f"paired with {self.controller[0]}")
        if self.ws is not None:
            self.spawn(self.ws.close())
        self.wake.set()

    def _erased(self):
        self.store.erase_pairing()
        self.lm.erase()
        self.creds_gen = None
        self.pairing.state, self.pairing.auto = "unpaired", False
        log("the controller forgot this companion; its pairing and La Marzocco account are erased")

    # --- Link ----------------------------------------------------------------
    async def run_link(self):
        failures = 0
        while True:
            pairing = self.store.pairing()
            if self.controller is None or pairing is None:
                self.link, self.link_reason = "down", ""
                self.wake.clear()
                await self.wake.wait()
                continue
            self.wake.clear()
            self.link = "connecting"
            hello = {"id": self.id, "name": self.name, "version": VERSION}
            try:
                ws, codec = await open_link(self.http, self.base_url("ws") + "/api/v1/companion/link",
                                            hello, pairing["secret"])
            except Erased:
                self._erased()
                failures = 0
                continue
            except LinkClosed as error:
                reason = error.code
                if reason == "NOT_PAIRED":
                    self.pairing.state = "not_recognized"
            else:
                failures = 0
                self.pairing.state = "paired"
                reason = await self._session(ws, codec)
            delay = BACKOFF_S[min(failures, len(BACKOFF_S) - 1)]
            failures += 1
            self.link, self.link_reason = "retry", reason
            log(f"link closed ({reason}); reopening in {delay} s, or as soon as the controller announces itself")
            try:
                await asyncio.wait_for(self.wake.wait(), delay)
            except asyncio.TimeoutError:
                pass

    async def _session(self, ws, codec):
        self.ws, self.outbox = ws, asyncio.Queue()
        self.link, self.link_reason = "open", ""
        self.hold, self.held, self.full_ep, self.reported = False, None, None, None
        log(f"link open to {self.controller[0]}")
        writer = self.spawn(self._writer(ws, codec, self.outbox))
        pinger = self.spawn(self._pinger())
        try:
            async for message in ws:
                if message.type is not aiohttp.WSMsgType.TEXT:
                    return "CLOSED" if message.type is aiohttp.WSMsgType.ERROR else "PROTOCOL"
                await self._on_frame(codec.decode(message.data))
            return "CLOSED"
        except LinkClosed as error:
            log(f"closing the link: {error}")
            return error.code
        except (aiohttp.ClientError, ConnectionError):
            return "CLOSED"
        finally:
            writer.cancel()
            pinger.cancel()
            self.ws = self.outbox = None
            self._set_route("direct")
            self.hold, self.held = False, None
            await ws.close()

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
        while True:
            self.route_changed.clear()
            try:
                await asyncio.wait_for(self.route_changed.wait(), PING_S[self.route])
                if self.route != "companion":
                    continue  # Back to the slow interval, counted from now.
            except asyncio.TimeoutError:
                pass
            self.post({"t": "ping", "up": self.lm.up})

    async def _on_frame(self, frame):
        kind = frame["t"]
        if kind == "cfg":
            self.cfg = {"lm": frame.get("lm") is True, "conn": "api" if frame.get("conn") == "api" else "ws",
                        "observe": frame.get("observe") is not False}
            self._apply_account()
            self._report(force=True)
        elif kind == "creds":
            self._on_credentials(frame)
        elif kind == "route":
            self._set_route("companion" if frame.get("to") == "companion" else "direct")
        elif kind == "hold":
            self._set_hold(frame.get("on") is True)
        else:
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
        self.route_changed.set()
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

    # --- La Marzocco account ---------------------------------------------------
    def _apply_account(self):
        account = self.store.credentials() if self.cfg["lm"] else None
        self.lm.configure(account, self.cfg["conn"], self.cfg["observe"])

    def _on_credentials(self, frame):
        generation = frame.get("gen")
        if type(generation) is not int or generation < 0:
            raise LinkClosed("PROTOCOL", "credentials without a generation")
        if frame.get("erase") is True:
            self.store.erase_account()
            self.lm.erase()
            self.creds_gen = None
            log("the controller erased the La Marzocco account")
            return
        try:
            plain = crypto.decrypt_credentials(self.store.pairing()["secret"], generation,
                                               crypto.unb64(frame.get("iv"), 12), crypto.unb64(frame.get("ct")))
            decoded = json.loads(plain)
            account = {key: decoded[key] for key in ("email", "password", "serial")}
            if not all(isinstance(value, str) and value for value in account.values()) or \
                    SERIAL_FORBIDDEN.intersection(account["serial"]):
                raise ValueError()
        except (ValueError, KeyError, TypeError, InvalidTag):
            raise LinkClosed("PROTOCOL", "credentials did not decrypt") from None
        self.store.save_credentials(generation, account)
        self.creds_gen = generation
        log(f"received the La Marzocco account (generation {generation})")
        if self.lm.rejected_for(account):
            self.account(False)
        elif self.lm.signed_in_for(account):
            self.account(True)
        else:
            self._apply_account()

    # --- Events from the La Marzocco client ------------------------------------
    def account(self, ok):
        if self.creds_gen is not None and self.post(
                {"t": "creds", "gen": self.creds_gen, "ok": True} if ok else
                {"t": "creds", "gen": self.creds_gen, "ok": False, "code": "AUTH"}):
            self.creds_gen = None
        self._report()

    def upstream(self):
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
        state = (self.lm.sub, self.lm.ep)
        if (force or state != self.reported) and self.post(
                {"t": "lm", "sub": self.lm.sub, "ep": self.lm.ep, "tok": self.lm.tok}):
            self.reported = state

    # --- Machine state -----------------------------------------------------------
    def _forward(self, kind, data, ac, ep=None):
        """Send one observation while the route is the companion's; reads wait out a hold."""
        if self.route != "companion" or self.outbox is None:
            return False
        reduced = dashboard.reduce(data, push=kind == "push")
        if reduced is None:
            return False
        frame = {"t": "st", "k": kind, "ep": self.lm.ep if ep is None else ep, "ac": ac, "d": reduced}
        if kind == "read" and self.hold:
            self.held = frame
            return True
        return self.post(frame)

    def _start_full(self):
        if self.route == "companion" and (self.full_task is None or self.full_task.done()):
            self.full_task = self.spawn(self._full())

    async def _full(self):
        """The read after a new subscription, sent as `full` once per route start and epoch."""
        for delay in itertools.chain(FULL_RETRY_S, itertools.repeat(FULL_RETRY_S[-1])):
            if self.route != "companion" or self.outbox is None or not self.lm.sub or self.full_ep == self.lm.ep:
                return
            ep = self.lm.ep
            _, data, ac = await self.lm.read()
            if data is not None and ep == self.lm.ep != self.full_ep and self._forward("full", data, ac, ep):
                self.full_ep = ep
            else:
                await asyncio.sleep(delay)

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
    def status(self):
        pairing = self.store.pairing()
        return {
            "name": self.name, "version": VERSION, "id": self.id,
            "paired": pairing is not None,
            "pairedWith": pairing.get("controller") if pairing else None,
            "controller": {"name": self.controller[0], "address": self.base_url().removeprefix("http://")}
            if self.controller else None,
            "pairing": self.pairing.status(),
            "link": self.link, "linkReason": self.link_reason or None,
            "route": self.route,
            "laMarzocco": {"enabled": self.cfg["lm"], "account": self.store.credentials() is not None,
                           "connection": self.cfg["conn"], "subscribed": self.lm.sub, "up": self.lm.up},
        }


def render_page():
    """The status and pairing page, styled like the setup page it sits beside."""
    setup = (HERE.parent / "gateway" / "setup.html").read_text()
    style = setup[setup.index("<style>") + 7:setup.index("</style>")]
    return (HERE / "page.html").read_text().replace("@STYLE@", style)


def web_app(companion):
    page = render_page()
    no_store = {"Cache-Control": "no-store"}

    async def show(request):
        return web.Response(text=page, content_type="text/html", headers=no_store)

    async def status(request):
        return web.json_response(companion.status(), headers=no_store)

    async def pair(request):
        if request.content_type != "application/json":  # A web page elsewhere cannot send this without asking.
            return web.json_response({"error": "UNSUPPORTED_MEDIA_TYPE"}, status=415)
        if companion.controller is None:
            return web.json_response({"error": "NO_CONTROLLER", "message": "No controller found yet"}, status=409)
        companion.pairing.start(manual=True)
        return web.json_response(companion.pairing.status(), status=202, headers=no_store)

    app = web.Application()
    app.router.add_get("/__companion/", show)
    app.router.add_get("/__companion/pair", show)
    app.router.add_get("/__companion/status", status)
    app.router.add_post("/__companion/pair", pair)
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
        stopping = companion.spawn(handle.stopping.wait())
        try:
            await asyncio.wait({link, stopping}, return_when=asyncio.FIRST_COMPLETED)
            if not stopping.done():
                raise RuntimeError("the link loop ended")
        finally:
            companion.lm.stop()
            await runner.cleanup()


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
