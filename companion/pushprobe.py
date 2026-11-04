"""A probe on a spike branch: does Web Push reach a device through the companion's private CA?

Its own page, manifest and service worker under /__companion/push-probe/, so nothing touches the
Web UI's service worker or the firmware. VAPID (RFC 8292) and aes128gcm (RFC 8291) need no account
with any push service. Never logs an endpoint: whoever holds one can address that device.
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
from aiohttp import web
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import crypto, log
from .store import offload

if TYPE_CHECKING:
    from pathlib import Path

    from .store import Store

BASE = "/__companion/push-probe/"
NAME = "push-probe"
PUSH_HOSTS = ("fcm.googleapis.com", ".push.apple.com", ".push.services.mozilla.com")
RECORD_BYTES = 4096
MAX_DELAY_S = 300
TTL_S = MAX_DELAY_S
TIMEOUT_S = 15
JWT_LIFE_S = 12 * 3600
# Apple refuses a VAPID subject that is not a real URL or address.
SUBJECT = "https://github.com/Cheerpipe/open-brew-by-weight-companion"
NO_STORE = {"Cache-Control": "no-store"}
MANIFEST = {
    "name": "Push probe",
    "start_url": BASE,
    "scope": BASE,
    "display": "standalone",
}
SERVICE_WORKER = """\
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("push", (event) => {
  const message = event.data.json();
  event.waitUntil(self.registration.showNotification(message.title, { body: message.body }));
});
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(self.clients.openWindow(new URL("./", self.location)));
});
"""


class Subscription(TypedDict):
    endpoint: str
    p256dh: str
    auth: str


class Saved(TypedDict):
    key: str  # The VAPID P-256 scalar, hex.
    subscriptions: dict[str, Subscription]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


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


def vapid_header(key: ec.EllipticCurvePrivateKey, endpoint: str, now: float) -> str:
    """The Authorization header for this endpoint's push service (RFC 8292)."""
    url = urlsplit(endpoint)
    head = {"typ": "JWT", "alg": "ES256"}
    claims = {
        "aud": f"{url.scheme}://{url.netloc}",
        "exp": int(now) + JWT_LIFE_S,
        "sub": SUBJECT,
    }
    signed = ".".join(b64url(json.dumps(part).encode()) for part in (head, claims))
    r, s = decode_dss_signature(key.sign(signed.encode(), ec.ECDSA(hashes.SHA256())))
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"vapid t={signed}.{b64url(signature)}, k={b64url(crypto.public_point(key))}"


def allowed_endpoint(endpoint: str) -> bool:
    """Only the browsers' push services: a page cannot aim the companion at any other host."""
    url = urlsplit(endpoint)
    host = url.hostname or ""
    return url.scheme == "https" and any(
        host.endswith(name) if name.startswith(".") else host == name for name in PUSH_HOSTS
    )


def parse_subscription(body: object) -> Subscription | None:
    """PushSubscription.toJSON() checked, or None."""
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
    p256dh, auth = cast("dict[str, object]", keys).get("p256dh"), keys.get("auth")
    if not isinstance(p256dh, str) or not isinstance(auth, str):
        return None
    try:
        crypto.load_point(unb64url(p256dh))
        if len(unb64url(auth)) != 16:
            return None
    except ValueError:
        return None
    return {"endpoint": endpoint, "p256dh": p256dh, "auth": auth}


def load(store: Store) -> Saved:
    saved = cast("Saved | None", store.read(NAME))
    if not saved:
        saved = {"key": crypto.scalar(crypto.new_key()).hex(), "subscriptions": {}}
        store.write(NAME, saved)
    return saved


async def post(endpoint: str, headers: dict[str, str], body: bytes) -> tuple[int, str]:
    """The push service's status and answer; status 0 when it could not be reached."""
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_S)
    try:
        async with (
            aiohttp.ClientSession(timeout=timeout) as session,
            session.post(endpoint, headers=headers, data=body) as answer,
        ):
            return answer.status, (await answer.text())[:300]
    except (aiohttp.ClientError, TimeoutError) as failure:
        return 0, type(failure).__name__


def routes(store: Store, page: Path) -> list[web.RouteDef]:
    results: dict[str, dict[str, object]] = {}
    pending: set[asyncio.Task[None]] = set()

    async def show(_request: web.Request) -> web.Response:
        saved = await offload(load, store)
        key = b64url(crypto.public_point(crypto.load_key(bytes.fromhex(saved["key"]))))
        text = (await offload(page.read_text)).replace("@VAPID_KEY@", key)
        return web.Response(text=text, content_type="text/html", headers=NO_STORE)

    async def manifest(_request: web.Request) -> web.Response:
        return web.json_response(MANIFEST, content_type="application/manifest+json")

    async def worker(_request: web.Request) -> web.Response:
        return web.Response(
            text=SERVICE_WORKER, content_type="application/javascript", headers=NO_STORE
        )

    def refused(request: web.Request) -> web.Response | None:
        # Only nginx's HTTPS server names the browser, and push needs a secure page anyway.
        if "X-Real-IP" not in request.headers:
            return web.json_response({"error": "HTTPS_REQUIRED"}, status=403)
        if request.content_type != "application/json":
            return web.json_response({"error": "UNSUPPORTED_MEDIA_TYPE"}, status=415)
        return None

    async def subscribe(request: web.Request) -> web.Response:
        if answer := refused(request):
            return answer
        subscription = parse_subscription(await request.json())
        if subscription is None:
            return web.json_response({"error": "BAD_SUBSCRIPTION"}, status=400)
        ident = hashlib.sha256(subscription["endpoint"].encode()).hexdigest()[:16]

        def remember() -> None:
            saved = load(store)
            saved["subscriptions"][ident] = subscription
            store.write(NAME, saved)

        await offload(remember)
        log(f"push probe: {ident} subscribed at {urlsplit(subscription['endpoint']).hostname}")
        return web.json_response({"id": ident}, headers=NO_STORE)

    async def deliver(ident: str, delay: int) -> None:
        await asyncio.sleep(delay)
        saved = await offload(load, store)
        subscription = saved["subscriptions"][ident]
        now = time.time()
        message = {"title": "Open Brew by Weight", "body": f"Push probe, asked {delay} s earlier"}
        status, detail = await post(
            subscription["endpoint"],
            {
                "Authorization": vapid_header(
                    crypto.load_key(bytes.fromhex(saved["key"])), subscription["endpoint"], now
                ),
                "Content-Encoding": "aes128gcm",
                "Content-Type": "application/octet-stream",
                "TTL": str(TTL_S),
                "Urgency": "high",
            },
            encrypt(
                json.dumps(message).encode(),
                unb64url(subscription["p256dh"]),
                unb64url(subscription["auth"]),
            ),
        )
        results[ident] = {"status": status, "detail": detail, "at": int(now)}
        log(f"push probe: {ident} answered {status} {detail}")

    async def send(request: web.Request) -> web.Response:
        if answer := refused(request):
            return answer
        body = await request.json()
        if not isinstance(body, dict):
            return web.json_response({"error": "BAD_REQUEST"}, status=400)
        ident, delay = body.get("id"), body.get("delayS", 0)
        if not isinstance(delay, int) or not 0 <= delay <= MAX_DELAY_S:
            return web.json_response({"error": "BAD_DELAY"}, status=400)
        saved = await offload(load, store)
        if ident not in saved["subscriptions"]:
            return web.json_response({"error": "UNKNOWN_SUBSCRIPTION"}, status=404)
        task = asyncio.create_task(deliver(ident, delay))
        pending.add(task)
        task.add_done_callback(pending.discard)
        return web.json_response({"delayS": delay}, status=202, headers=NO_STORE)

    async def result(request: web.Request) -> web.Response:
        found = results.get(request.query.get("id", ""))
        return web.json_response(found, headers=NO_STORE)

    return [
        web.get(BASE, show),
        web.get(BASE + "manifest.webmanifest", manifest),
        web.get(BASE + "sw.js", worker),
        web.post(BASE + "subscribe", subscribe),
        web.post(BASE + "send", send),
        web.get(BASE + "result", result),
    ]
