"""A fake controller for the relay and screen tests: the relay routes, relay admission, the claim and
a ui-stream that answers ops the way the firmware does, written from the phase 3 design's formulas
(not from the companion's code), so the two are checked against each other.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re

from aiohttp import web

CLIENT = re.compile(r"[0-9a-f]{16,24}")


def b64(data):
    return base64.b64encode(data).decode()


def mac(key, *parts):
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()


def relay_key(secret, rb, nc):
    """HKDF-SHA256(ikm=S, salt=rb‖nc, info="obbw-relay-v1", L=32), written out (RFC 5869)."""
    prk = hmac.new(rb + nc, secret, hashlib.sha256).digest()
    return hmac.new(prk, b"obbw-relay-v1\x01", hashlib.sha256).digest()


def relay_tag(key, method, uri, q, addr, screen, session):
    canonical = "\n".join(["obbw-relay-v1", method, uri, str(q), addr, screen, session]) + "\n"
    return hmac.new(key, canonical.encode(), hashlib.sha256).digest()[:16].hex()


def dumps(value):
    return json.dumps(value, separators=(",", ":"))


class Controller:
    def __init__(self, secret, companion_id):
        self.secret, self.companion_id = secret, companion_id
        self.mode = "ok"  # ok, none (phase-1 firmware), forgotten, bad_erase, unknown, bad_proof
        self.ui, self.link = True, False
        self.rb, self.kr, self.high, self.mask = os.urandom(16), None, 0, 0
        self.handshakes, self.stale_next = 0, False
        self.active = None  # activeWebUiClientId_
        self.requests = []  # (method, uri, headers, body, identity)
        self.request_id = 100
        self.streams = []  # Open ui-stream sessions
        self.sessions = asyncio.Queue()
        self.require_relay_stream = True
        self.epoch = 5  # The record stores' epoch in the answers below.
        self.handler = None  # Optional override per test: async (session, op) -> handled?

    # --- Relay routes -------------------------------------------------------------
    async def relay_get(self, request):
        if self.mode == "none":
            return web.Response(status=404, text="404: Not Found")
        if self.mode in ("forgotten", "bad_erase", "unknown"):
            return web.json_response({"error": "COMPANION_NOT_PAIRED"}, status=404)
        return web.json_response({"challenge": b64(self.rb), "protocol": 1})

    async def relay_post(self, request):
        if self.mode == "none":
            return web.Response(status=404, text="404: Not Found")
        if request.content_type != "application/json":
            return web.json_response({"error": "UNSUPPORTED_MEDIA_TYPE"}, status=415)
        body = await request.json()
        nc = base64.b64decode(body["nonce"])
        if self.mode in ("forgotten", "bad_erase"):
            key = self.secret if self.mode == "forgotten" else bytes(32)
            return web.json_response({"error": "COMPANION_NOT_PAIRED", "erase": b64(mac(key, b"E", nc))}, status=404)
        if self.mode == "unknown" or body["id"] != self.companion_id:
            return web.json_response({"error": "COMPANION_NOT_PAIRED"}, status=404)
        if not hmac.compare_digest(base64.b64decode(body["mac"]), mac(self.secret, b"R", self.rb, nc)):
            return web.json_response({"error": "COMPANION_AUTH"}, status=401)
        self.handshakes += 1
        self.kr, self.high, self.mask = relay_key(self.secret, self.rb, nc), 0, 0
        proof = mac(self.secret if self.mode != "bad_proof" else bytes(32), b"Q", self.rb, nc)
        answer = {"mac": b64(proof), "ui": self.ui, "link": self.link}
        self.rb = os.urandom(16)
        return web.json_response(answer)

    def admit(self, request):
        """(identity or None, refusal or None) as relay admission defines them."""
        value = request.headers.get("X-OBBW-Relay")
        if value is None:
            return None, None
        parts = value.split(" ")
        if len(parts) != 5 or parts[0] != "1" or not parts[1].isdigit() or not CLIENT.fullmatch(parts[3]) or \
                not re.fullmatch(r"[0-9a-f]{32}", parts[4]) or len(parts[2]) > 45:
            return None, web.json_response({"error": "RELAY_INVALID"}, status=400)
        q, addr, screen, tag = int(parts[1]), parts[2], parts[3], parts[4]
        session = request.headers.get("X-WebUI-Session", "")
        if self.stale_next or self.kr is None or tag != relay_tag(self.kr, request.method, request.raw_path, q, addr,
                                                                  screen, session):
            self.stale_next = False
            return None, web.json_response({"error": "RELAY_STALE"}, status=401)
        if q > self.high:
            shift = q - self.high
            self.mask = ((self.mask << shift) | 1) & (2 ** 64 - 1) if shift < 64 else 1
            self.high = q
        elif self.high - q < 64 and not self.mask >> (self.high - q) & 1:
            self.mask |= 1 << (self.high - q)
        else:
            return None, web.json_response({"error": "RELAY_REPLAY"}, status=401)
        if not self.ui:
            return None, web.json_response({"error": "RELAY_DISABLED"}, status=403)
        return {"q": q, "addr": addr, "screen": screen, "session": session}, None

    # --- REST -------------------------------------------------------------------------
    async def api(self, request):
        identity, refusal = self.admit(request)
        if refusal is not None:
            return refusal
        body = await request.read()
        self.requests.append((request.method, request.raw_path, dict(request.headers), body, identity))
        client, path = request.headers.get("X-WebUI-Client", ""), request.path
        if path == "/api/v1/ui/claim":
            if not CLIENT.fullmatch(client):
                return web.json_response({"error": "UI_CLIENT_INVALID"}, status=400)
            if self.active != client:
                self.active = client
                for session in list(self.streams):  # A new owner closes the previous one's stream.
                    await session.ws.close(code=4001)
            return web.json_response({"active": True, "compatibilityMode": False})
        if path == "/api/v1/auth/login":
            self.active = client
            return web.json_response({"token": "t", "remember": False, "active": True})
        if path == "/api/v1/ota" and request.method == "PATCH":
            return web.json_response({"received": len(body)})
        if path == "/api/v1/debug/export":
            response = web.StreamResponse(headers={
                "Content-Type": "application/octet-stream", "Content-Encoding": "gzip",
                "Content-Disposition": 'attachment; filename="export.gz"'})
            await response.prepare(request)
            for _ in range(4):
                await response.write(b"\x1f\x8b" + bytes(32 * 1024))
            await response.write_eof()
            return response
        if path == "/api/v1/companion/admin":
            return web.json_response({"ok": True})
        if path == "/api/v1/auth":
            return web.json_response({"login": False})
        if client != self.active:
            return web.json_response({"error": "UI_TAKEN_OVER", "message": "Another window took over"}, status=409)
        if request.method == "GET":
            return web.json_response({"ok": True, "uri": request.raw_path})
        self.request_id += 1
        return web.json_response({"accepted": True, "requestId": self.request_id}, status=202)

    # --- ui-stream ----------------------------------------------------------------------
    async def stream(self, request):
        host = request.headers.get("Host", "")
        if request.headers.get("Origin") not in (f"http://{host}", f"http://{host}:80"):
            return web.Response(status=403)
        identity, refusal = self.admit(request)
        if refusal is not None:
            return refusal
        if identity is None and self.require_relay_stream:
            return web.Response(status=400, text="relay header expected")
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        session = Session(self, ws, identity)
        self.streams.append(session)
        await self.sessions.put(session)
        try:
            async for message in ws:
                await session.on_text(message.data)
        finally:
            self.streams.remove(session)
            if not session.closed.done():
                session.closed.set_result(ws.close_code)
        return ws

    def app(self):
        app = web.Application()
        app.router.add_get("/api/v1/companion/relay", self.relay_get)
        app.router.add_post("/api/v1/companion/relay", self.relay_post)
        app.router.add_get("/api/v1/ui/ui-stream", self.stream)
        app.router.add_route("*", "/api/{tail:.*}", self.api)
        return app


class Session:
    """One controller-side ui-stream session with the firmware's answers to each op."""

    def __init__(self, controller, ws, identity):
        self.controller, self.ws, self.identity = controller, ws, identity
        self.ops = []
        self.bound = False
        self.closed = asyncio.get_running_loop().create_future()
        self.history = self.stats = None
        self.seq = 0

    async def send(self, frame):
        await self.ws.send_str(dumps(frame))

    async def on_text(self, text):
        op = json.loads(text)
        self.ops.append(op)
        handler = self.controller.handler
        if handler and await handler(self, op):
            return
        await self.answer(op)

    async def answer(self, op):
        name = op["op"]
        if name == "bind":
            if op.get("client") != self.controller.active:
                await self.ws.close(code=4001)
                return
            self.bound = True
            await self.send(home_snapshot())
            await self.send(card_snapshot())
            for item in op.get("ops", []):
                await self.answer(item)
        elif name == "activity":
            await self.send({"v": 1, "type": "alive"})
        elif name == "settings":
            await self.send({"v": 1, "type": "settings", "boot": 7, "snapshot": True, "tag": 55,
                             "changes": {"config.dripDelayMs": 0, "scale.history": []}})
        elif name == "diagnostic" and op["on"]:
            await self.send(diagnostic_snapshot())
            await self.send({"type": "diagnostic", "changes": {"tasks": {"big": "x" * 30000}}})
        elif name == "log" and op["on"]:
            after = op.get("after", 0)
            await self.send(log_frame([event(n) for n in range(1, 6) if n > after]))
        elif name == "history" and op["on"]:
            await self.send(history_frame(op, snapshot=not op.get("fetch"), epoch=self.controller.epoch))
        elif name == "stats" and op["on"] and set(op) != {"op", "on", "window"}:
            for frame in stats_page(self, op, snapshot=not op.get("fetch"), epoch=self.controller.epoch):
                await self.send(frame)
        elif name == "records":
            for store in ("shots", "history"):
                if store in op:
                    frame = {"v": 1, "type": "records", "boot": 7, "store": store, "epoch": 40}
                    if op[store] != 40:
                        frame["rows"] = [3, 111, 2, 222]
                    await self.send(frame)
        elif name == "resync":
            await self.send(home_snapshot())
            await self.send(card_snapshot())


def home_snapshot(**extra):
    changes = {"bootId": 7, "configMutable": True, "adminUnlocked": False, "config.soundAlertsEnabled": True,
               "presetsTag": 9, "presets": [{"id": 1, "name": "Espresso"}], "lastCommand.requestId": 0,
               "lastCommand.state": "NONE", "machineState": "idle", **extra}
    return {"v": 1, "type": "home", "boot": 7, "snapshot": True, "changes": changes}


def card_snapshot(seq=1):
    return {"v": 1, "boot": 7, "seq": seq, "snapshot": True, "cycle": 3, "cursor": 0, "stale": False,
            "phase": "idle", "card": {"valid": True}, "curve": {}}


def diagnostic_snapshot():
    return {"v": 1, "type": "diagnostic", "boot": 7, "snapshot": True,
            "changes": {"relayClosed": False, "controlSource": "none", "safety.fault": "none",
                        "scale.controlState": "idle", "heap": {"free": 1}}}


def event(sequence):
    return {"sequence": sequence, "atMs": sequence * 10, "wallSec": 0, "localSec": 0, "level": "info",
            "category": "system", "message": f"event {sequence}"}


def log_frame(events, **extra):
    frame = {"v": 1, "type": "log", "bootId": 7, "historyOverwritten": 0, "missedEvents": 0, "serialDropped": 0,
             "cursorInvalid": False, "events": events, "hasMore": False}
    frame.update(extra)
    return frame


def history_frame(op, snapshot, epoch=5, request=None):
    limit, direction = op.get("limit", 20), op.get("dir", "desc")
    ids = list(range(1, 4)) if direction == "desc" else list(range(3, 0, -1))
    return {"v": 1, "type": "history", "boot": 7, "snapshot": snapshot, "epoch": epoch,
            "request": request if request is not None else op.get("request", 0), "tag": 77, "total": 3,
            "offset": op.get("offset", 0), "limit": limit, "hasMore": False,
            "records": [{"id": n, "type": (op.get("types") or ["shot"])[0], "durationS": 1.0, "hasWallTime": False,
                         "endedAtUnixSec": 0, "endedAtLocalSec": 0} for n in ids]}


def stats_page(session, op, snapshot, epoch=5, request=None):
    """Two frames: a header frame and a continuation."""
    session.seq += 1
    common = {"v": 1, "type": "stats", "boot": 7, "epoch": epoch, "seq": session.seq,
              "request": request if request is not None else op.get("request", 0), "total": 2,
              "offset": op.get("offset", 0), "limit": op.get("limit", 10), "hasMore": False}
    header = {"window": op.get("window", 10)}
    return [{**common, "snapshot": snapshot, "stats": header, "cols": "id", "tag": 88, "rows": [[1, {}]],
             "rowBase": 0, "more": True},
            {**common, "snapshot": False, "rows": [[2, {}]], "rowBase": 1, "more": False}]
