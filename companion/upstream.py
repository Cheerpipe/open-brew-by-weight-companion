"""The companion's one ui-stream session with the controller, shared by every screen.

It opens signed as relayed, binds with the relay's client id and the union of
the screens' subscriptions, and hands each frame to the multiplexer. It also
owns the session's liveness: one `activity` op aggregated over the screens.
"""

import asyncio
import collections
import json

import aiohttp

from . import log

PATH = "/api/v1/ui/ui-stream"
REQUEST_BYTES = 640  # The controller's request frame (kUiStreamRequestBytes).
MAX_FRAME = 64 * 1024
ACTIVITY_S, KEEPALIVE_S, ALIVE_S = 19, 120, 25
TICK_S = 1


def dumps(value):
    return json.dumps(value, separators=(",", ":"))


class Upstream:
    def __init__(self, companion, relay, mux):
        self.companion, self.relay, self.mux = companion, relay, mux
        self.state = "closed"  # closed, opening, open or closing
        self.ws = self.outbox = None
        self.heard = False  # A frame arrived since the bind: the controller accepted it.
        self.heard_at = self.sent_at = 0.0
        self.activity = (0, False)  # The last aggregate sent: (seconds, hidden).
        self.activity_at = 0.0
        self.probing = False
        self.ops = 0  # Ops sent on this companion's lifetime (the bind counts as one).
        self.recent = collections.deque(maxlen=64)  # The last ops, for tests and the 4003 attribution.

    def open(self):
        if self.state == "closed":
            self.state = "opening"
            self.companion.spawn(self._run())

    def close(self):
        if self.state == "open":
            self.state = "closing"
            self.companion.spawn(self.ws.close())

    def alive(self):
        """True while the session is bound and the controller was heard recently."""
        loop = asyncio.get_running_loop()
        return self.state == "open" and self.heard and loop.time() - self.heard_at < ALIVE_S

    def send(self, op):
        if self.state != "open":
            return False
        self.outbox.put_nowait(dumps(op))
        self.ops += 1
        self.recent.append(op)
        self.sent_at = asyncio.get_running_loop().time()
        return True

    async def _connect(self):
        companion, relay = self.companion, self.relay
        host = companion.base_url().removeprefix("http://")
        for attempt in (0, 1):
            value = await relay.signed("GET", PATH, "0.0.0.0", relay.client_id)
            if value is None:
                return None
            try:
                return await relay.session().ws_connect(
                    companion.base_url("ws") + PATH, headers={"Origin": f"http://{host}", "X-OBBW-Relay": value},
                    autoping=True, max_msg_size=MAX_FRAME, timeout=aiohttp.ClientWSTimeout(ws_close=5))
            except aiohttp.WSServerHandshakeError as error:
                if error.status != 401 or attempt:
                    log(f"the controller refused the live updates: HTTP {error.status}")
                    return None
                relay.key = None  # RELAY_STALE: a new relay session, then once more.
        return None

    async def _run(self):
        try:
            ws = await self._connect()
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as error:
            log(f"could not open the live updates: {type(error).__name__}")
            ws = None
        if ws is None:
            self.state = "closed"
            self.mux.upstream_closed(None, False)
            return
        loop = asyncio.get_running_loop()
        self.ws, self.outbox, self.heard = ws, asyncio.Queue(), False
        self.heard_at = self.sent_at = self.activity_at = loop.time()
        self.activity, self.probing = (0, False), False
        # The bind and the state it carries are taken in one step: later changes go as ops.
        self.state = "open"
        bind, rest = {"op": "bind", "client": self.relay.client_id}, []
        for op in self.mux.bind_ops():
            if len(dumps({**bind, "ops": [*bind.get("ops", ()), op]})) <= REQUEST_BYTES:
                bind.setdefault("ops", []).append(op)
            else:
                rest.append(op)
        for op in (bind, *rest):
            self.send(op)
        writer = self.companion.spawn(self._writer(ws, self.outbox))
        ticker = self.companion.spawn(self._ticker())
        self.mux.upstream_opened()
        try:
            async for message in ws:
                if message.type is not aiohttp.WSMsgType.TEXT:
                    break
                try:
                    frame = json.loads(message.data)
                except ValueError:
                    continue
                if isinstance(frame, dict):
                    self.heard, self.heard_at, self.probing = True, loop.time(), False
                    self.mux.on_frame(frame, message.data)
        except (aiohttp.ClientError, ConnectionError, asyncio.TimeoutError):
            pass
        finally:
            writer.cancel()
            ticker.cancel()
            await ws.close()
            deliberate = self.state == "closing"
            self.state, self.ws, self.outbox = "closed", None, None
            self.mux.upstream_closed(ws.close_code, deliberate, self.heard)

    async def _writer(self, ws, outbox):
        while True:
            text = await outbox.get()
            try:
                await ws.send_str(text)
            except (aiohttp.ClientError, ConnectionError, RuntimeError):
                await ws.close()
                return

    # --- Liveness ----------------------------------------------------------------
    def sync_activity(self, probe=False):
        """Send the screens' aggregate when it is due: at once when it rises from 0 or
        hidden changes, every ACTIVITY_S while it is above 0, every KEEPALIVE_S anyway,
        and when a screen waits for `alive` from a controller not heard lately."""
        if self.state != "open":
            return
        now = asyncio.get_running_loop().time()
        seconds, hidden = self.mux.aggregate()
        last_seconds, last_hidden = self.activity
        due = (hidden != last_hidden or (seconds and not last_seconds) or
               (seconds and now - self.activity_at >= ACTIVITY_S) or now - self.sent_at >= KEEPALIVE_S or
               (probe and not self.probing and now - self.heard_at >= ALIVE_S))
        if due:
            self.activity, self.activity_at = (seconds, hidden), now
            self.probing = self.probing or probe
            self.send({"op": "activity", "seconds": seconds, "hidden": hidden})

    async def _ticker(self):
        while True:
            await asyncio.sleep(TICK_S)
            self.sync_activity()
