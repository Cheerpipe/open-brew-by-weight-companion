"""A fake controller for the relay and screen tests: the relay routes, relay admission, the claim
and a ui-stream that answers ops the way the firmware does, written from the design's formulas
(not from the companion's code), so the two are checked against each other. Relay protocol 2:
requests arrive signed and sealed, JSON answers leave sealed under the response counter.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import struct
import zlib
from typing import TYPE_CHECKING, Any, TypedDict

from aiohttp import web
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

CLIENT = re.compile(r"[0-9a-f]{16,24}")
CTX_SESSION, CTX_PASSWORD, CTX_BODY = 0, 1, 2

# An op as the companion sent it: JSON, read as the firmware reads it.
type Op = dict[str, Any]
# A frame this fake sends.
type Frame = dict[str, object]


class Identity(TypedDict):
    """A relayed request as admission identifies it, its sealed values opened."""

    q: int
    addr: str
    screen: str
    session: str
    password: str


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def mac(key: bytes, *parts: bytes) -> bytes:
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()


def relay_key(secret: bytes, rb: bytes, nc: bytes) -> bytes:
    """HKDF-SHA256(ikm=S, salt=rb‖nc, info="obbw-relay-v1", L=32), written out (RFC 5869)."""
    prk = hmac.new(rb + nc, secret, hashlib.sha256).digest()
    return hmac.new(prk, b"obbw-relay-v1\x01", hashlib.sha256).digest()


def body_key(key: bytes) -> bytes:
    """Kb = HKDF-SHA256(ikm=Kr, salt="", info="obbw-relay-body-v2", L=32), written out."""
    prk = hmac.new(bytes(32), key, hashlib.sha256).digest()
    return hmac.new(prk, b"obbw-relay-body-v2\x01", hashlib.sha256).digest()


def nonce(direction: bytes, context: int, counter: int) -> bytes:
    return direction + bytes((context, 0, 0)) + counter.to_bytes(8, "little")


def seal(key: bytes, context: int, counter: int, plaintext: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce(b"c", context, counter), plaintext, None)


def open_(key: bytes, direction: bytes, context: int, counter: int, sealed: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce(direction, context, counter), sealed, None)


def relay_tag(
    key: bytes, method: str, uri: str, q: int, addr: str, screen: str, session: str
) -> str:
    canonical = "\n".join(["obbw-relay-v2", method, uri, str(q), addr, screen, session]) + "\n"
    return hmac.new(key, canonical.encode(), hashlib.sha256).digest()[:16].hex()


def dumps(value: object) -> str:
    return json.dumps(value, separators=(",", ":"))


def index_answer(
    baselines: dict[str, tuple[int, list[int]]],
    store: str,
    held: object,
    delta: object,
    epoch: int,
    rows: list[int],
) -> dict[str, object]:
    """A firmware with deltas: the fields a link index answer adds to `epoch` for the flat
    newest-first `rows`, asked from `held`. Listed, it carries `sum` and becomes the session's
    baseline (in `baselines`); asked with the delta flag from the baseline's epoch, it lists only
    the difference when that is smaller."""
    if held == epoch:
        return {}
    fields: dict[str, object] = {"rows": rows}
    base = baselines.get(store)
    if delta and base and base[0] == held:
        old = dict(zip(base[1][0::2], base[1][1::2], strict=True))
        now = dict(zip(rows[0::2], rows[1::2], strict=True))
        up = [value for rid, rev in now.items() if old.get(rid) != rev for value in (rid, rev)]
        gone = [rid for rid in old if rid not in now]
        if len(up) + len(gone) < len(rows):
            fields = {"base": held, "up": up, "del": gone}
    baselines[store] = (epoch, rows)
    fields["sum"] = zlib.crc32(struct.pack(f"<{len(rows)}I", *rows))
    return fields


class Controller:
    def __init__(self, secret: bytes, companion_id: str) -> None:
        self.secret, self.companion_id = secret, companion_id
        self.mode = (
            "ok"  # ok, none (no relay route answers), forgotten, bad_erase, unknown, bad_proof
        )
        self.ui, self.link = True, False
        self.rb = os.urandom(16)
        self.kr: bytes | None = None
        self.kb: bytes | None = None
        self.high, self.mask = 0, 0
        self.responses = 0
        self.handshakes, self.stale_next = 0, False
        self.relay_gets, self.auth_required = 0, False
        self.corrupt_body, self.corrupt_reply = False, False  # A man in the middle, for tests.
        self.active: str | None = None  # activeWebUiClientId_
        # Each request's method, URI, headers, body and identity.
        self.requests: list[tuple[str, str, dict[str, str], bytes, Identity | None]] = []
        # The sealed bytes as they arrived: (session header, password header, body).
        self.wire: list[tuple[str, str, bytes]] = []
        self.request_id = 100
        self.streams: list[Session] = []  # Open ui-stream sessions
        self.sessions: asyncio.Queue[Session] = asyncio.Queue()
        self.require_relay_stream = True
        self.epoch, self.boot = 5, 7  # The record stores' epoch and the boot in the answers below.
        # Optional override per test: async (session, op) -> handled?
        self.handler: Callable[[Session, Op], Awaitable[bool]] | None = None

    # --- Relay routes -------------------------------------------------------------
    async def relay_get(self, _request: web.Request) -> web.Response:
        self.relay_gets += 1
        if self.mode == "none":
            return web.Response(status=404, text="404: Not Found")
        if self.mode in ("forgotten", "bad_erase", "unknown"):
            return web.json_response({"error": "COMPANION_NOT_PAIRED"}, status=404)
        return web.json_response({"challenge": b64(self.rb), "protocol": 1})

    async def relay_post(self, request: web.Request) -> web.Response:
        if self.mode == "none":
            return web.Response(status=404, text="404: Not Found")
        if request.content_type != "application/json":
            return web.json_response({"error": "UNSUPPORTED_MEDIA_TYPE"}, status=415)
        body = await request.json()
        nc = base64.b64decode(body["nonce"])
        if self.mode in ("forgotten", "bad_erase"):
            key = self.secret if self.mode == "forgotten" else bytes(32)
            return web.json_response(
                {"error": "COMPANION_NOT_PAIRED", "erase": b64(mac(key, b"E", nc))}, status=404
            )
        if self.mode == "unknown" or body["id"] != self.companion_id:
            return web.json_response({"error": "COMPANION_NOT_PAIRED"}, status=404)
        if not hmac.compare_digest(
            base64.b64decode(body["mac"]), mac(self.secret, b"R", self.rb, nc)
        ):
            return web.json_response({"error": "COMPANION_AUTH"}, status=401)
        self.handshakes += 1
        self.kr = relay_key(self.secret, self.rb, nc)
        self.kb, self.high, self.mask = body_key(self.kr), 0, 0  # responses never reset: nonces.
        proof = mac(self.secret if self.mode != "bad_proof" else bytes(32), b"Q", self.rb, nc)
        answer = {"mac": b64(proof), "ui": self.ui, "link": self.link}
        self.rb = os.urandom(16)
        return web.json_response(answer)

    def admit(self, request: web.Request) -> tuple[Identity | None, web.Response | None]:
        """(identity or None, refusal or None) as relay admission defines them; the sealed
        session and password values open here, so a recorded request names the plaintext."""
        value = request.headers.get("X-OBBW-Relay")
        if value is None:
            return None, None
        parts = value.split(" ")
        if (
            len(parts) != 5
            or parts[0] != "2"
            or not parts[1].isdigit()
            or not CLIENT.fullmatch(parts[3])
            or not re.fullmatch(r"[0-9a-f]{32}", parts[4])
            or len(parts[2]) > 45
        ):
            return None, web.json_response({"error": "RELAY_INVALID"}, status=400)
        q, addr, screen, tag = int(parts[1]), parts[2], parts[3], parts[4]
        raw_session = request.headers.get("X-WebUI-Session", "")
        raw_password = request.headers.get("X-Device-Password", "")
        if (
            self.stale_next
            or self.kr is None
            or self.kb is None
            or tag
            != relay_tag(self.kr, request.method, request.raw_path, q, addr, screen, raw_session)
        ):
            self.stale_next = False
            return None, web.json_response({"error": "RELAY_STALE"}, status=401)
        session = password = ""
        try:
            if raw_session:
                session = open_(
                    self.kb, b"c", CTX_SESSION, q, base64.b64decode(raw_session)
                ).decode()
            if raw_password:
                password = open_(
                    self.kb, b"c", CTX_PASSWORD, q, base64.b64decode(raw_password)
                ).decode()
        except InvalidTag, ValueError, UnicodeDecodeError:
            return None, web.json_response({"error": "RELAY_INVALID"}, status=400)
        if q > self.high:
            shift = q - self.high
            self.mask = ((self.mask << shift) | 1) & (2**64 - 1) if shift < 64 else 1
            self.high = q
        elif self.high - q < 64 and not self.mask >> (self.high - q) & 1:
            self.mask |= 1 << (self.high - q)
        else:
            return None, web.json_response({"error": "RELAY_REPLAY"}, status=401)
        if not self.ui:
            return None, web.json_response({"error": "RELAY_DISABLED"}, status=403)
        return {
            "q": q,
            "addr": addr,
            "screen": screen,
            "session": session,
            "password": password,
        }, None

    def answer(self, identity: Identity | None, payload: object, status: int = 200) -> web.Response:
        """A JSON answer: sealed (X-OBBW-Enc names its counter) to a relayed request."""
        if identity is None or self.kb is None:  # A relayed request found the session's keys.
            return web.json_response(payload, status=status, dumps=dumps)
        self.responses += 1
        sealed = AESGCM(self.kb).encrypt(
            nonce(b"f", 3, self.responses), dumps(payload).encode(), None
        )
        if self.corrupt_reply:
            sealed = sealed[:-1] + bytes((sealed[-1] ^ 1,))
        return web.Response(
            status=status,
            content_type="application/json",
            headers={"Cache-Control": "no-store", "X-OBBW-Enc": str(self.responses)},
            body=sealed,
        )

    # --- REST -------------------------------------------------------------------------
    async def api(self, request: web.Request) -> web.StreamResponse:
        identity, refusal = self.admit(request)
        if refusal is not None:
            return refusal
        raw = await request.read()
        if self.corrupt_body and raw:  # Flip one sealed byte, as a listener on the wire could.
            raw = raw[:-1] + bytes((raw[-1] ^ 1,))
        body = raw
        # Firmware update ranges travel as they are; every other relayed body
        # arrived sealed under its request's q.
        sealed_body = (
            identity is not None
            and raw
            and not (request.method == "PATCH" and request.path == "/api/v1/ota")
        )
        if sealed_body and identity is not None and self.kb is not None:
            try:
                body = open_(self.kb, b"c", CTX_BODY, identity["q"], raw)
            except InvalidTag:
                return web.json_response({"error": "RELAY_INVALID"}, status=400)
        headers = dict(request.headers)
        if identity is not None:
            if identity["session"]:
                headers["X-WebUI-Session"] = identity["session"]
            if identity["password"]:
                headers["X-Device-Password"] = identity["password"]
        self.requests.append((request.method, request.raw_path, headers, body, identity))
        self.wire.append(
            (
                request.headers.get("X-WebUI-Session", ""),
                request.headers.get("X-Device-Password", ""),
                raw,
            )
        )
        client, path = request.headers.get("X-WebUI-Client", ""), request.path
        if path == "/api/v1/ui/claim":
            if not CLIENT.fullmatch(client):
                return self.answer(identity, {"error": "UI_CLIENT_INVALID"}, status=400)
            if self.active != client:
                self.active = client
                for session in list(self.streams):  # A new owner closes the previous one's stream.
                    await session.ws.close(code=4001)
            return self.answer(identity, {"active": True, "compatibilityMode": False})
        if path == "/api/v1/auth/login":
            self.active = client
            return self.answer(identity, {"token": "t", "remember": False, "active": True})
        if path == "/api/v1/ota" and request.method == "PATCH":
            return self.answer(identity, {"received": len(body)})
        if path == "/api/v1/debug/export":
            response = web.StreamResponse(
                headers={
                    "Content-Type": "application/octet-stream",
                    "Content-Encoding": "gzip",
                    "Content-Disposition": 'attachment; filename="export.gz"',
                }
            )
            await response.prepare(request)
            for _ in range(4):
                await response.write(b"\x1f\x8b" + bytes(32 * 1024))
            await response.write_eof()
            return response
        if path == "/api/v1/companion/admin":
            return self.answer(identity, {"ok": True})
        if path == "/api/v1/auth":
            return self.answer(identity, {"login": False})
        if path == "/api/v1/auth/logout":
            return self.answer(identity, {"ok": True})
        if self.auth_required:
            return self.answer(identity, {"error": "AUTH_REQUIRED"}, status=401)
        if client != self.active:
            return self.answer(
                identity,
                {"error": "UI_TAKEN_OVER", "message": "Another window took over"},
                status=409,
            )
        if request.method == "GET":
            return self.answer(identity, {"ok": True, "uri": request.raw_path})
        self.request_id += 1
        return self.answer(identity, {"accepted": True, "requestId": self.request_id}, status=202)

    # --- ui-stream ----------------------------------------------------------------------
    async def stream(self, request: web.Request) -> web.StreamResponse:
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

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/api/v1/companion/relay", self.relay_get)
        app.router.add_post("/api/v1/companion/relay", self.relay_post)
        app.router.add_get("/api/v1/ui/ui-stream", self.stream)
        app.router.add_route("*", "/api/{tail:.*}", self.api)
        return app


class Session:
    """One controller-side ui-stream session with the firmware's answers to each op."""

    def __init__(
        self, controller: Controller, ws: web.WebSocketResponse, identity: Identity | None
    ) -> None:
        self.controller, self.ws, self.identity = controller, ws, identity
        self.ops: list[Op] = []
        self.bound = False
        self.closed: asyncio.Future[int | None] = asyncio.get_running_loop().create_future()
        self.history = self.stats = None
        self.seq = 0
        self.sent: list[str] = []  # Every frame this session sent, as text.

    async def send(self, frame: Frame) -> None:
        self.sent.append(dumps(frame))
        await self.ws.send_str(self.sent[-1])

    async def on_text(self, text: str) -> None:
        op = json.loads(text)
        self.ops.append(op)
        handler = self.controller.handler
        if handler and await handler(self, op):
            return
        await self.answer(op)

    async def answer(self, op: Op) -> None:
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
            await self.send(
                {
                    "v": 1,
                    "type": "settings",
                    "boot": 7,
                    "snapshot": True,
                    "tag": 55,
                    "changes": {"config.dripDelayMs": 0, "scale.history": []},
                }
            )
        elif name == "diagnostic" and op["on"]:
            await self.send(diagnostic_snapshot())
            await self.send({"type": "diagnostic", "changes": {"tasks": {"big": "x" * 30000}}})
        elif name == "log" and op["on"]:
            after = op.get("after", 0)
            await self.send(log_frame([event(n) for n in range(1, 6) if n > after]))
        elif name == "history" and op["on"]:
            await self.send(
                history_frame(
                    op,
                    snapshot=not op.get("fetch"),
                    epoch=self.controller.epoch,
                    boot=self.controller.boot,
                )
            )
        elif name == "stats" and op["on"] and set(op) != {"op", "on", "window"}:
            for frame in stats_page(
                self,
                op,
                snapshot=not op.get("fetch"),
                epoch=self.controller.epoch,
                boot=self.controller.boot,
            ):
                await self.send(frame)
        elif name == "resync":
            await self.send(home_snapshot())
            await self.send(card_snapshot())


def home_snapshot(**extra: object) -> Frame:
    changes = {
        "bootId": 7,
        "configMutable": True,
        "adminUnlocked": False,
        "config.soundAlertsEnabled": True,
        "presetsTag": 9,
        "presets": [{"id": 1, "name": "Espresso"}],
        "lastCommand.requestId": 0,
        "lastCommand.state": "NONE",
        "machineState": "idle",
        "timeUtcSec": 1800000000,
        **extra,
    }
    return {"v": 1, "type": "home", "boot": 7, "snapshot": True, "changes": changes}


def card_snapshot(seq: int = 1) -> Frame:
    return {
        "v": 1,
        "boot": 7,
        "seq": seq,
        "snapshot": True,
        "cycle": 3,
        "cursor": 0,
        "stale": False,
        "phase": "idle",
        "card": {"valid": True},
        "curve": {},
    }


def diagnostic_snapshot() -> Frame:
    return {
        "v": 1,
        "type": "diagnostic",
        "boot": 7,
        "snapshot": True,
        "changes": {
            "relayClosed": False,
            "controlSource": "none",
            "safety.fault": "none",
            "scale.controlState": "idle",
            "heap": {"free": 1},
        },
    }


def event(sequence: int) -> Frame:
    return {
        "sequence": sequence,
        "atMs": sequence * 10,
        "wallSec": 0,
        "localSec": 0,
        "level": "info",
        "category": "system",
        "message": f"event {sequence}",
    }


def log_frame(events: list[Frame], **extra: object) -> Frame:
    frame: Frame = {
        "v": 1,
        "type": "log",
        "bootId": 7,
        "historyOverwritten": 0,
        "missedEvents": 0,
        "serialDropped": 0,
        "cursorInvalid": False,
        "events": events,
        "hasMore": False,
    }
    frame.update(extra)
    return frame


def fingerprint(*parts: object) -> int:
    """The standing page's tag: its epoch, window and content; a subscribe naming it gets bare
    ids."""
    return zlib.crc32(dumps(parts).encode()) or 1


def history_frame(
    op: Op, snapshot: bool, epoch: int = 5, request: int | None = None, boot: int = 7
) -> Frame:
    limit, direction = op.get("limit", 20), op.get("dir", "desc")
    ids = list(range(1, 4)) if direction == "desc" else list(range(3, 0, -1))
    records = [
        {
            "id": n,
            "type": (op.get("types") or ["shot"])[0],
            "durationS": 1.0,
            "hasWallTime": False,
            "endedAtUnixSec": 0,
            "endedAtLocalSec": 0,
        }
        for n in ids
    ]
    tag = fingerprint(epoch, op.get("offset", 0), limit, direction, op.get("types"), records)
    kept = snapshot and op.get("tag") == tag
    return {
        "v": 1,
        "type": "history",
        "boot": boot,
        "snapshot": snapshot,
        "epoch": epoch,
        "request": request if request is not None else op.get("request", 0),
        "tag": tag,
        "total": 3,
        "offset": op.get("offset", 0),
        "limit": limit,
        "hasMore": False,
        "records": [record["id"] for record in records] if kept else records,
    }


def stats_page(
    session: Session,
    op: Op,
    snapshot: bool,
    epoch: int = 5,
    request: int | None = None,
    boot: int = 7,
) -> list[Frame]:
    """Two frames, a header frame and a continuation; a kept page's bare ids fit the first."""
    session.seq += 1
    common: Frame = {
        "v": 1,
        "type": "stats",
        "boot": boot,
        "epoch": epoch,
        "seq": session.seq,
        "request": request if request is not None else op.get("request", 0),
        "total": 2,
        "offset": op.get("offset", 0),
        "limit": op.get("limit", 10),
        "hasMore": False,
    }
    header: Frame = {"window": op.get("window", 10)}
    rows: list[list[object]] = [[1, {"wCg": [10]}], [2, {"wCg": [20]}]]
    tag = fingerprint(
        epoch,
        *(op.get(name) for name in ("offset", "limit", "sort", "dir", "filter")),
        header,
        rows,
    )
    first: Frame = {
        **common,
        "snapshot": snapshot,
        "stats": header,
        "cols": "id",
        "tag": tag,
        "rowBase": 0,
    }
    if snapshot and op.get("tag") == tag:
        return [{**first, "rows": [1, 2], "more": False}]
    return [
        {**first, "rows": rows[:1], "more": True},
        {**common, "snapshot": False, "rows": rows[1:], "rowBase": 1, "more": False},
    ]
