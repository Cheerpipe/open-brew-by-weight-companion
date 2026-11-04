"""Web Push delivery: keys, subscriptions, encryption and sending, and nothing else.

The controller decides which events exist and when they fire (`ev` link frames) and the firmware's
service worker renders them from the firmware's own text, so an event's `d` is passed on unread and
this module holds no wording and no shot logic. VAPID (RFC 8292) and aes128gcm (RFC 8291) need no
account with any push service. An endpoint is a capability: it is stored 0600 and never logged.
"""

import asyncio
import base64
import hashlib
import json
import os
import time
from typing import TYPE_CHECKING, TypedDict, cast
from urllib.parse import urlsplit

import aiohttp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import clip, crypto, log
from .store import offload

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Mapping

    from .store import Store

NAME, ACTIVITY = "push", "push-activity"
VERSION = 1
PUSH_HOSTS = (
    "fcm.googleapis.com",
    ".push.apple.com",
    ".push.services.mozilla.com",
    ".notify.windows.com",
)
MAX_DEVICES = 16
MAX_PENDING = 64
MAX_EVENT_BYTES = 1024
MAX_TOPICS = 8
MAX_TOPIC, MAX_KEY, MAX_LABEL = 32, 64, 48
MAX_TTL_S = 24 * 3600
DEFAULT_TTL_S = 3600
ACTIVITY_LENGTH = 50
RECORD_BYTES = 4096
TIMEOUT_S = 15
RETRY_S = (5, 30, 120)
JWT_LIFE_S = 12 * 3600
JWT_REUSE_S = 3600  # Apple asks for no more than one new token an hour.
TEST_INTERVAL_S = 2.0
MAX_TEST_DELAY_S = 60
# Apple refuses a VAPID subject that is not a real URL or address.
SUBJECT = "https://github.com/Cheerpipe/open-brew-by-weight-companion"
GONE, KEY_PROBLEM, OUR_BUG = {404, 410}, {401, 403}, {400, 413}


class Subscription(TypedDict):
    endpoint: str
    p256dh: str
    auth: str
    topics: list[str]
    label: str
    addedAt: int
    lastOkAt: int
    lastError: str


class Saved(TypedDict):
    subscriptions: dict[str, Subscription]


class Activity(TypedDict, total=False):
    at: int
    kind: str
    device: str
    topic: str
    key: str
    status: int
    detail: str


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def device_id(endpoint: str) -> str:
    return hashlib.sha256(endpoint.encode()).hexdigest()[:16]


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def vapid_key(identity: ec.EllipticCurvePrivateKey) -> ec.EllipticCurvePrivateKey:
    """Derived from the companion's identity: it stores nothing until a device subscribes, and
    every subscription outlives a restart and a re-pairing's erase of its devices."""
    return crypto.load_key(_hkdf(crypto.scalar(identity), b"", b"obbw-push-vapid-v1", 32))


def encrypt(
    message: bytes,
    p256dh: bytes,
    auth: bytes,
    key: ec.EllipticCurvePrivateKey | None = None,
    salt: bytes | None = None,
) -> bytes:
    """One aes128gcm record for this subscription (RFC 8291); key and salt are fresh per message."""
    key = key or crypto.new_key()
    salt = salt or os.urandom(16)
    ours = crypto.public_point(key)
    secret = key.exchange(ec.ECDH(), crypto.load_point(p256dh))
    ikm = _hkdf(secret, auth, b"WebPush: info\0" + p256dh + ours, 32)
    cek = _hkdf(ikm, salt, b"Content-Encoding: aes128gcm\0", 16)
    nonce = _hkdf(ikm, salt, b"Content-Encoding: nonce\0", 12)
    sealed = AESGCM(cek).encrypt(nonce, message + b"\x02", None)
    return salt + RECORD_BYTES.to_bytes(4, "big") + bytes([len(ours)]) + ours + sealed


def vapid_token(key: ec.EllipticCurvePrivateKey, audience: str, now: float) -> str:
    """The signed JWT for one push service's origin (RFC 8292)."""
    head = {"typ": "JWT", "alg": "ES256"}
    claims = {"aud": audience, "exp": int(now) + JWT_LIFE_S, "sub": SUBJECT}
    signed = ".".join(b64url(json.dumps(part).encode()) for part in (head, claims))
    r, s = decode_dss_signature(key.sign(signed.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{signed}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def allowed_endpoint(endpoint: str) -> bool:
    """Only the browsers' push services: a page cannot aim the companion at any other host."""
    url = urlsplit(endpoint)
    host = url.hostname or ""
    return url.scheme == "https" and any(
        host.endswith(name) if name.startswith(".") else host == name for name in PUSH_HOSTS
    )


def parse_subscription(body: object) -> tuple[str, str, str] | None:
    """PushSubscription.toJSON() checked: (endpoint, p256dh, auth), or None."""
    if not isinstance(body, dict):
        return None
    fields = cast("dict[str, object]", body)
    endpoint, keys = fields.get("endpoint"), fields.get("keys")
    if (
        not isinstance(endpoint, str)
        or not allowed_endpoint(endpoint)
        or not isinstance(keys, dict)
    ):
        return None
    named = cast("dict[str, object]", keys)
    p256dh, auth = named.get("p256dh"), named.get("auth")
    if not isinstance(p256dh, str) or not isinstance(auth, str):
        return None
    try:
        crypto.load_point(unb64url(p256dh))
        if len(unb64url(auth)) != 16:
            return None
    except ValueError:
        return None
    return endpoint, p256dh, auth


def parse_topics(value: object) -> list[str] | None:
    """Opaque names the Web UI chose, only bounded here."""
    if not isinstance(value, list) or len(value) > MAX_TOPICS:
        return None
    named = cast("list[object]", value)
    topics = [topic for topic in named if isinstance(topic, str) and 0 < len(topic) <= MAX_TOPIC]
    return topics if len(topics) == len(named) else None


class Push:
    def __init__(
        self,
        store: Store,
        identity: ec.EllipticCurvePrivateKey,
        http: aiohttp.ClientSession,
        spawn: Callable[[Coroutine[object, None, None]], asyncio.Task[None]],
        post_sync: Callable[[dict[str, object], str], bool],
    ) -> None:
        self.store, self.http, self.spawn, self.post_sync = store, http, spawn, post_sync
        self.post = self._post
        self.saved = cast("Saved | None", store.read(NAME)) or Saved(subscriptions={})
        self.key = vapid_key(identity)
        self.public = b64url(crypto.public_point(self.key))
        self.activity = cast("list[Activity]", store.read(ACTIVITY) or [])
        self.tokens: dict[str, tuple[str, float]] = {}
        self.pending = 0
        self.counters = {"events": 0, "sent": 0, "accepted": 0, "failed": 0, "removed": 0}
        self.last_event: dict[str, object] | None = None
        self.last_error = ""
        self.tests: dict[str, float] = {}

    # --- State ---------------------------------------------------------------------
    def status_facts(self) -> dict[str, object]:
        """Public facts for /__companion/status, which answers without a session."""
        return {"version": VERSION, "available": True, "publicKey": self.public}

    def _fingerprint(self) -> str:
        return hashlib.sha256(unb64url(self.public)).hexdigest()[:12]

    def status(self) -> dict[str, object]:
        return {
            "version": VERSION,
            "publicKey": self.public,
            "fingerprint": self._fingerprint(),
            "pending": self.pending,
            "counters": self.counters,
            "lastError": self.last_error,
            "lastEvent": self.last_event,
            "devices": [
                {
                    "id": ident,
                    "label": device["label"],
                    "service": urlsplit(device["endpoint"]).hostname,
                    "topics": device["topics"],
                    "addedAt": device["addedAt"],
                    "lastOkAt": device["lastOkAt"],
                    "lastError": device["lastError"],
                }
                for ident, device in self.saved["subscriptions"].items()
            ],
            "activity": self.activity[::-1],
        }

    async def _save(self) -> None:
        await offload(self.store.write, NAME, cast("Mapping[str, object]", self.saved))

    async def _note(self, kind: str, **fields: object) -> None:
        entry = cast("Activity", {"at": int(time.time()), "kind": kind, **fields})
        self.activity = [*self.activity, entry][-ACTIVITY_LENGTH:]
        await offload(self.store.write, ACTIVITY, cast("list[object]", list(self.activity)))

    def announce(self) -> None:
        """Tell the controller whether any device wants events: it sends none otherwise."""
        self.post_sync({"t": "ps", "on": bool(self.saved["subscriptions"])}, "push")

    def knows(self, endpoint: object) -> bool:
        return isinstance(endpoint, str) and device_id(endpoint) in self.saved["subscriptions"]

    # --- Subscriptions ---------------------------------------------------------------
    async def subscribe(
        self, parsed: tuple[str, str, str], topics: list[str], label: str, old: object = None
    ) -> str | None:
        """Add or refresh a device; None when the list is full. `old` is the endpoint a browser
        replaced on its own: that device's record moves to the new one."""
        endpoint, p256dh, auth = parsed
        ident = device_id(endpoint)
        known = self.saved["subscriptions"]
        replaced = known.pop(device_id(old), None) if isinstance(old, str) else None
        previous = known.get(ident) or replaced
        if previous is None and len(known) >= MAX_DEVICES:
            return None
        known[ident] = {
            "endpoint": endpoint,
            "p256dh": p256dh,
            "auth": auth,
            "topics": topics,
            "label": "".join(c for c in label if c.isprintable())[:MAX_LABEL]
            or (previous["label"] if previous else ""),
            "addedAt": previous["addedAt"] if previous else int(time.time()),
            "lastOkAt": previous["lastOkAt"] if previous else 0,
            "lastError": previous["lastError"] if previous else "",
        }
        await self._save()
        if previous is None:
            log(f"push: device {ident} added at {urlsplit(endpoint).hostname}")
            await self._note("subscribed", device=ident)
            if len(known) == 1:
                self.announce()
        return ident

    async def remove(self, ident: str, why: str = "unsubscribed") -> bool:
        if self.saved["subscriptions"].pop(ident, None) is None:
            return False
        await self._save()
        log(f"push: device {ident} removed ({why})")
        await self._note(why, device=ident)
        if not self.saved["subscriptions"]:
            self.announce()
        return True

    async def erase(self) -> None:
        """Forget: a later controller never reaches this one's devices."""
        self.saved["subscriptions"] = {}
        self.activity, self.last_event, self.last_error = [], None, ""
        await offload(self.store.delete, NAME, ACTIVITY)

    # --- Events ----------------------------------------------------------------------
    def on_event(self, frame: Mapping[str, object]) -> bool:
        """An `ev` frame, passed on unread; False when it is malformed."""
        topic, key, data, ttl = (
            frame.get("topic"),
            frame.get("key"),
            frame.get("d"),
            frame.get("ttl"),
        )
        if (
            not isinstance(topic, str)
            or not 0 < len(topic) <= MAX_TOPIC
            or not isinstance(key, str)
            or not 0 < len(key) <= MAX_KEY
            or not isinstance(data, dict)
            or not (ttl is None or (type(ttl) is int and ttl > 0))
            or len(json.dumps(data).encode()) > MAX_EVENT_BYTES
        ):
            return False
        wanted = [
            ident
            for ident, device in self.saved["subscriptions"].items()
            if topic in device["topics"]
        ]
        self.counters["events"] += 1
        self.last_event = {
            "topic": topic,
            "key": key,
            "receivedAt": int(time.time()),
            "devices": len(wanted),
            "answers": {},
            "receivedOn": {},
        }
        lifetime = min(ttl or DEFAULT_TTL_S, MAX_TTL_S)
        for ident in wanted:
            self._queue(ident, topic, key, cast("dict[str, object]", data), lifetime)
        log(f"push: event {key} ({topic}) for {len(wanted)} device(s)")
        return True

    async def test(self, endpoint: str, topic: str, data: dict[str, object], delay: int) -> str:
        """A sample for this one device, shaped like an event; '' or why it was refused."""
        ident = device_id(endpoint)
        now = time.monotonic()
        if now - self.tests.get(ident, float("-inf")) < TEST_INTERVAL_S:
            return "TOO_SOON"
        self.tests[ident] = now
        await self._note("test", device=ident, topic=topic)
        self._queue(ident, topic, f"test-{int(time.time())}", data, MAX_TEST_DELAY_S * 2, delay)
        return ""

    def _queue(
        self, ident: str, topic: str, key: str, data: dict[str, object], ttl: int, delay: int = 0
    ) -> None:
        if self.pending >= MAX_PENDING:
            self.counters["failed"] += 1
            self.last_error = "the send queue is full"
            log(f"push: the send queue is full; {key} is not sent to {ident}")
            return
        self.pending += 1
        mid = os.urandom(8).hex()
        message = json.dumps({"topic": topic, "key": key, "mid": mid, "d": data}).encode()
        _ = self.spawn(self._deliver(ident, topic, key, message, ttl, delay))

    def _token(self, endpoint: str, now: float) -> str:
        url = urlsplit(endpoint)
        audience = f"{url.scheme}://{url.netloc}"
        token, made = self.tokens.get(audience, ("", float("-inf")))
        if now - made >= JWT_REUSE_S:
            token, made = vapid_token(self.key, audience, now), now
            self.tokens[audience] = (token, made)
        return token

    async def _send(self, device: Subscription, message: bytes, ttl: int) -> tuple[int, str, float]:
        """The push service's status, its answer and its Retry-After; status 0 when unreachable."""
        now = time.time()
        headers = {
            "Authorization": f"vapid t={self._token(device['endpoint'], now)}, k={self.public}",
            "Content-Encoding": "aes128gcm",
            "Content-Type": "application/octet-stream",
            "TTL": str(ttl),
            "Urgency": "high",
        }
        body = encrypt(message, unb64url(device["p256dh"]), unb64url(device["auth"]))
        return await self.post(device["endpoint"], headers, body)

    async def _post(
        self, endpoint: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, str, float]:
        """Checked again here: a stored subscription is never trusted to name a host."""
        if not allowed_endpoint(endpoint):
            return 0, "not a known push service", 0.0
        try:
            async with self.http.post(
                endpoint,
                headers=headers,
                data=body,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT_S),
            ) as answer:
                text = (await answer.content.read(300)).decode(errors="replace")
                wait = answer.headers.get("Retry-After", "")
                return answer.status, clip(text), float(wait) if wait.isdigit() else 0.0
        except (aiohttp.ClientError, TimeoutError, OSError) as failure:
            return 0, type(failure).__name__, 0.0

    async def _deliver(
        self, ident: str, topic: str, key: str, message: bytes, ttl: int, delay: int
    ) -> None:
        """One message to one device, retried within its TTL. Nothing here reaches the link."""
        try:
            await asyncio.sleep(delay)
            started = time.monotonic()
            for attempt in (*RETRY_S, None):
                device = self.saved["subscriptions"].get(ident)
                if device is None:
                    return
                self.counters["sent"] += 1
                status, detail, wait = await self._send(device, message, ttl)
                self._answer(ident, key, status)
                if 200 <= status < 300:
                    self.counters["accepted"] += 1
                    device["lastOkAt"], device["lastError"] = int(time.time()), ""
                    await self._save()
                    await self._note("accepted", device=ident, topic=topic, key=key, status=status)
                    return
                if status in GONE:
                    self.counters["removed"] += 1
                    await self.remove(ident, "rejected")
                    return
                reason = f"{status} {detail}" if detail else str(status)
                device["lastError"] = self.last_error = reason
                log(f"push: {key} to {ident} failed: {reason}")
                pause = max(attempt or 0, wait)
                give_up = (
                    status in KEY_PROBLEM
                    or status in OUR_BUG
                    or attempt is None
                    or time.monotonic() - started + pause >= ttl
                )
                await self._note(
                    "failed" if give_up else "retry",
                    device=ident,
                    topic=topic,
                    key=key,
                    status=status,
                    detail=detail,
                )
                if give_up:
                    self.counters["failed"] += 1
                    await self._save()
                    return
                await asyncio.sleep(pause)
        finally:
            self.pending -= 1

    def _answer(self, ident: str, key: str, status: int) -> None:
        event = self.last_event
        if event is not None and event["key"] == key:
            cast("dict[str, int]", event["answers"])[ident] = status
            event["sentAt"] = int(time.time())

    async def ack(self, mid: str, key: str, ident: str) -> None:
        """The worker's receipt: this device got the message and showed it."""
        event = self.last_event
        if event is not None and event["key"] == key:
            cast("dict[str, int]", event["receivedOn"])[ident] = int(time.time())
        await self._note("received", device=ident, key=key, detail=mid[:16])
