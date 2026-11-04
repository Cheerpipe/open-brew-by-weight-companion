"""Web Push delivery: RFC 8291's vector, the VAPID token, each answer's action and the routes.

Offline, inside the image: every send is a fake. Nothing here knows what an event means.
"""

import asyncio
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from companion import crypto, push
from companion.link import LinkClosedError
from companion.push import Push, allowed_endpoint, b64url, device_id, parse_subscription, unb64url
from companion.service import Companion, web_app
from companion.store import Store

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

ENDPOINT = "https://web.push.apple.com/abc"
AUTH = b"\x01" * 16
IDENTITY = crypto.new_key()


def fresh_subscription() -> tuple[ec.EllipticCurvePrivateKey, tuple[str, str, str]]:
    device = crypto.new_key()
    return device, (ENDPOINT, b64url(crypto.public_point(device)), b64url(AUTH))


def open_record(body: bytes, key: ec.EllipticCurvePrivateKey, auth: bytes) -> bytes:
    salt, length = body[:16], body[20]
    theirs = body[21 : 21 + length]
    secret = key.exchange(ec.ECDH(), crypto.load_point(theirs))

    def derive(ikm: bytes, use_salt: bytes, info: bytes, size: int) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=size, salt=use_salt, info=info).derive(ikm)

    ikm = derive(secret, auth, b"WebPush: info\0" + crypto.public_point(key) + theirs, 32)
    cek = derive(ikm, salt, b"Content-Encoding: aes128gcm\0", 16)
    nonce = derive(ikm, salt, b"Content-Encoding: nonce\0", 12)
    return AESGCM(cek).decrypt(nonce, body[21 + length :], None)[:-1]


def test_encrypt_matches_rfc8291_vector() -> None:
    body = push.encrypt(
        b"When I grow up, I want to be a watermelon",
        unb64url(
            "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
        ),
        unb64url("BTBZMqHH6r4Tts7J_aSIgg"),
        crypto.load_key(unb64url("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")),
        unb64url("DGv6ra1nlYgDCS1FRnbzlw"),
    )
    assert b64url(body) == (
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmY"
        "WAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexS"
        "gSxsj_Qulcy4a-fN"
    )


def test_vapid_token_verifies_with_its_key() -> None:
    key = crypto.new_key()
    head, claims, signature = push.vapid_token(key, "https://web.push.apple.com", 1000.0).split(".")
    parsed = json.loads(unb64url(claims))
    assert parsed["aud"] == "https://web.push.apple.com"
    assert parsed["exp"] == 1000 + push.JWT_LIFE_S
    assert parsed["sub"].startswith("https://")
    raw = unb64url(signature)
    der = encode_dss_signature(int.from_bytes(raw[:32]), int.from_bytes(raw[32:]))
    key.public_key().verify(der, f"{head}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize(
    ("endpoint", "allowed"),
    [
        ("https://fcm.googleapis.com/fcm/send/x", True),
        ("https://web.push.apple.com/x", True),
        ("https://updates.push.services.mozilla.com/x", True),
        ("https://wns2-par02p.notify.windows.com/x", True),
        ("http://web.push.apple.com/x", False),
        ("https://evilpush.apple.com/x", False),
        ("https://fcm.googleapis.com.evil.test/x", False),
        ("https://192.168.1.1/x", False),
    ],
)
def test_only_push_services_are_allowed(endpoint: str, allowed: bool) -> None:
    assert allowed_endpoint(endpoint) is allowed


@pytest.mark.parametrize(
    "body",
    [
        [],
        {"endpoint": "https://evil.test/x", "keys": {"p256dh": "a", "auth": "b"}},
        {"endpoint": ENDPOINT},
        {"endpoint": ENDPOINT, "keys": {"p256dh": 1, "auth": "b"}},
        {"endpoint": ENDPOINT, "keys": {"p256dh": "AAAA", "auth": "AAAA"}},
    ],
)
def test_bad_subscriptions_are_refused(body: object) -> None:
    assert parse_subscription(body) is None


@pytest.mark.parametrize("topics", ["x", [1], [""], ["x" * 33], ["t"] * 9])
def test_bad_topics_are_refused(topics: object) -> None:
    assert push.parse_topics(topics) is None


class Harness:
    """A Push with a fake sender, its posted frames and its spawned tasks."""

    def __init__(self, data: Path, http: aiohttp.ClientSession) -> None:
        self.frames: list[dict[str, object]] = []
        self.tasks: list[asyncio.Task[None]] = []
        self.sends: list[tuple[str, dict[str, str], bytes]] = []
        self.answers: list[tuple[int, str, float]] = []
        self.push = Push(Store(data), IDENTITY, http, self.spawn, self.post_sync)

        async def fake_post(
            endpoint: str, headers: dict[str, str], body: bytes
        ) -> tuple[int, str, float]:
            self.sends.append((endpoint, headers, body))
            return self.answers.pop(0) if self.answers else (201, "", 0.0)

        self.push.post = fake_post

    def spawn(self, coroutine: Any) -> asyncio.Task[None]:
        task = asyncio.create_task(coroutine)
        self.tasks.append(task)
        return task

    def post_sync(self, frame: dict[str, object], _key: str) -> bool:
        self.frames.append(frame)
        return True

    async def settle(self) -> None:
        await asyncio.gather(*self.tasks)


def with_harness(work: Callable[[Harness], Awaitable[None]]) -> None:
    async def run(data: Path) -> None:
        async with aiohttp.ClientSession() as http:
            await work(Harness(data, http))

    with tempfile.TemporaryDirectory() as data:
        asyncio.run(run(Path(data)))


EVENT = {"t": "ev", "topic": "shot_result", "key": "42-7", "d": {"v": 1, "unread": [1, "two"]}}


def test_an_event_reaches_only_devices_that_want_its_topic_with_d_unread() -> None:
    async def work(h: Harness) -> None:
        device, parsed = fresh_subscription()
        ident = await h.push.subscribe(parsed, ["shot_result"], "iPhone · Safari")
        assert ident == device_id(ENDPOINT)
        assert h.frames == [{"t": "ps", "on": True}], "the first device asks for events"
        other, parsed_other = fresh_subscription()
        await h.push.subscribe(
            ("https://fcm.googleapis.com/x", parsed_other[1], parsed_other[2]), ["other"], "Other"
        )
        assert len(h.frames) == 1

        assert h.push.on_event(EVENT)
        await h.settle()

        assert len(h.sends) == 1
        endpoint, headers, record = h.sends[0]
        assert endpoint == ENDPOINT
        assert headers["Content-Encoding"] == "aes128gcm"
        assert headers["TTL"] == str(push.DEFAULT_TTL_S)
        assert headers["Authorization"].endswith(f", k={h.push.public}")
        message = json.loads(open_record(record, device, AUTH))
        assert message["d"] == EVENT["d"], "the event's data passes unread"
        assert message["topic"] == "shot_result"
        assert message["key"] == "42-7"
        status = cast("dict[str, Any]", h.push.status())
        assert status["counters"]["accepted"] == 1
        assert status["lastEvent"]["answers"] == {ident: 201}
        assert "endpoint" not in json.dumps(status), "a status never names an endpoint"
        assert ENDPOINT not in json.dumps(status)
        del other

    with_harness(work)


@pytest.mark.parametrize(
    "frame",
    [
        {"topic": "", "key": "k", "d": {}},
        {"topic": "t", "key": "", "d": {}},
        {"topic": "t", "key": "k", "d": []},
        {"topic": "t", "key": "k", "d": {}, "ttl": 0},
        {"topic": "t", "key": "k", "d": {"big": "x" * 1100}},
    ],
)
def test_malformed_events_are_refused(frame: dict[str, object]) -> None:
    async def work(h: Harness) -> None:
        assert not h.push.on_event(frame)

    with_harness(work)


def test_the_tokens_are_reused_per_service() -> None:
    async def work(h: Harness) -> None:
        _, parsed = fresh_subscription()
        await h.push.subscribe(parsed, ["t"], "A")
        h.push.on_event({"topic": "t", "key": "1", "d": {}})
        h.push.on_event({"topic": "t", "key": "2", "d": {}})
        await h.settle()
        assert h.sends[0][1]["Authorization"] == h.sends[1][1]["Authorization"]

    with_harness(work)


@pytest.mark.parametrize("status", [404, 410])
def test_a_gone_subscription_is_removed_and_the_controller_told(status: int) -> None:
    async def work(h: Harness) -> None:
        _, parsed = fresh_subscription()
        await h.push.subscribe(parsed, ["t"], "A")
        h.answers = [(status, "gone", 0.0)]
        h.push.on_event({"topic": "t", "key": "1", "d": {}})
        await h.settle()
        assert not h.push.knows(ENDPOINT)
        assert h.frames[-1] == {"t": "ps", "on": False}
        assert h.push.counters["removed"] == 1

    with_harness(work)


@pytest.mark.parametrize("status", [400, 401, 403, 413])
def test_an_answer_that_retrying_cannot_fix_is_kept_and_reported(status: int) -> None:
    async def work(h: Harness) -> None:
        _, parsed = fresh_subscription()
        await h.push.subscribe(parsed, ["t"], "A")
        h.answers = [(status, "nope", 0.0)]
        h.push.on_event({"topic": "t", "key": "1", "d": {}})
        await h.settle()
        assert h.push.knows(ENDPOINT)
        assert len(h.sends) == 1
        assert h.push.last_error == f"{status} nope"
        assert h.push.counters["failed"] == 1
        assert h.push.activity[-1]["kind"] == "failed"

    with_harness(work)


def test_a_temporary_failure_is_retried_honoring_retry_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pauses: list[float] = []
    sleep = asyncio.sleep

    async def fake_sleep(delay: float) -> None:
        pauses.append(delay)
        await sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def work(h: Harness) -> None:
        _, parsed = fresh_subscription()
        await h.push.subscribe(parsed, ["t"], "A")
        h.answers = [(503, "", 0.0), (429, "", 40.0), (0, "TimeoutError", 0.0), (201, "", 0.0)]
        h.push.on_event({"topic": "t", "key": "1", "d": {}})
        await h.settle()
        assert len(h.sends) == 4
        assert h.push.counters["accepted"] == 1
        assert h.push.pending == 0
        assert h.push.saved["subscriptions"][device_id(ENDPOINT)]["lastError"] == ""

    with_harness(work)
    assert [p for p in pauses if p] == [5, 40.0, 120]


def test_a_failure_past_every_retry_or_the_ttl_gives_up(monkeypatch: pytest.MonkeyPatch) -> None:
    sleep = asyncio.sleep

    async def fake_sleep(_delay: float) -> None:
        await sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def work(h: Harness) -> None:
        _, parsed = fresh_subscription()
        await h.push.subscribe(parsed, ["t"], "A")
        h.answers = [(500, "", 0.0)] * 4
        h.push.on_event({"topic": "t", "key": "1", "d": {}})
        await h.settle()
        assert len(h.sends) == 4
        h.answers = [(500, "", 0.0)]
        h.sends.clear()
        h.push.on_event({"topic": "t", "key": "2", "ttl": 1, "d": {}})
        await h.settle()
        assert len(h.sends) == 1, "a retry past the event's life is not made"
        assert h.push.counters["failed"] == 2

    with_harness(work)


def test_the_device_list_is_capped_and_a_full_queue_only_counts() -> None:
    async def work(h: Harness) -> None:
        _, parsed = fresh_subscription()
        for index in range(push.MAX_DEVICES):
            ident = await h.push.subscribe((f"{ENDPOINT}{index}", parsed[1], parsed[2]), ["t"], "A")
            assert ident is not None
        assert await h.push.subscribe(parsed, ["t"], "A") is None
        assert await h.push.subscribe((f"{ENDPOINT}0", parsed[1], parsed[2]), ["x"], "B"), (
            "a known device still refreshes"
        )
        h.push.pending = push.MAX_PENDING
        h.push.on_event({"topic": "t", "key": "1", "d": {}})
        assert h.push.counters["failed"] == push.MAX_DEVICES - 1
        h.push.pending = 0

    with_harness(work)


def test_a_replaced_endpoint_keeps_its_device() -> None:
    async def work(h: Harness) -> None:
        _, parsed = fresh_subscription()
        old = device_id(ENDPOINT)
        await h.push.subscribe(parsed, ["t"], "A")
        added = h.push.saved["subscriptions"][old]["addedAt"]
        new = "https://web.push.apple.com/new"
        await h.push.subscribe((new, parsed[1], parsed[2]), ["t"], "A", ENDPOINT)
        assert not h.push.knows(ENDPOINT)
        assert h.push.saved["subscriptions"][device_id(new)]["addedAt"] == added
        assert h.frames == [{"t": "ps", "on": True}]

    with_harness(work)


def test_erase_forgets_devices_and_keeps_the_key_across_a_restart() -> None:
    async def run(data: Path) -> None:
        async with aiohttp.ClientSession() as http:
            first = Harness(data, http)
            _, parsed = fresh_subscription()
            await first.push.subscribe(parsed, ["t"], "A")
            again = Harness(data, http)
            assert again.push.public == first.push.public
            assert again.push.knows(ENDPOINT), "devices survive a restart"
            assert again.push.activity[-1]["kind"] == "subscribed"
            await again.push.erase()
            third = Harness(data, http)
            assert third.push.public == first.push.public
            assert not third.push.knows(ENDPOINT)
            assert third.push.activity == []
            assert not (data / "secrets" / "push.json").exists(), "nothing stays behind"
            await third.push.subscribe(parsed, ["t"], "A")

    with tempfile.TemporaryDirectory() as data:
        asyncio.run(run(Path(data)))
        mode = (Path(data) / "secrets" / "push.json").stat().st_mode & 0o777
        assert mode == 0o600


def test_post_never_follows_a_redirect_and_refuses_other_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run(data: Path) -> None:
        hits: list[str] = []

        async def bounce(_request: web.Request) -> web.Response:
            hits.append("bounce")
            raise web.HTTPFound("/elsewhere")

        async def elsewhere(_request: web.Request) -> web.Response:
            hits.append("elsewhere")
            return web.Response(status=201)

        app = web.Application()
        app.router.add_post("/", bounce)
        app.router.add_post("/elsewhere", elsewhere)
        server = TestServer(app, host="127.0.0.1")
        await server.start_server()
        url = str(server.make_url("/"))
        async with aiohttp.ClientSession() as http:
            sender = Push(Store(data), IDENTITY, http, asyncio.create_task, lambda _f, _k: True)
            assert await sender.post(url, {}, b"x") == (0, "not a known push service", 0.0)
            assert hits == []
            monkeypatch.setattr(push, "allowed_endpoint", lambda _endpoint: True)
            status, _detail, _wait = await sender.post(url, {}, b"x")
            assert status == 302
            assert hits == ["bounce"], "a redirect is an answer, not a new host"
            await server.close()
            status, detail, _wait = await sender.post(url, {}, b"x")
            assert status == 0
            assert detail

    with tempfile.TemporaryDirectory() as data:
        asyncio.run(run(Path(data)))


class Upstream:
    """No La Marzocco here."""

    sub = up = refused = policy = False
    ep = tok = 0

    def __init__(self, store: Store, events: Companion) -> None:
        pass

    def configure(self, *_: object) -> None:
        pass

    def stop(self) -> None:
        pass

    def erase(self) -> None:
        pass

    def signed_in_for(self, _: object) -> bool:
        raise AssertionError("no La Marzocco here")

    def rejected_for(self, _: object) -> bool:
        raise AssertionError("no La Marzocco here")

    async def read(self) -> tuple[int, dict[str, object] | None, int]:
        raise AssertionError("no La Marzocco here")

    async def command(self, *_: object) -> int:
        raise AssertionError("no La Marzocco here")


def with_service(
    monkeypatch: pytest.MonkeyPatch,
    work: Callable[[Companion, Callable[..., Awaitable[aiohttp.ClientResponse]]], Awaitable[None]],
    access: list[object],
) -> None:
    """The real routes; `access` is what the controller answers, for the session rule."""

    async def run(data: Path) -> None:
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", data, http, Upstream)

            async def ui_access(_headers: object, _live: bool = False) -> object:
                return access[0]

            monkeypatch.setattr(companion, "ui_access", ui_access)
            pages = TestServer(web_app(companion), host="127.0.0.1")
            await pages.start_server()

            async def call(route: str, body: object = None) -> aiohttp.ClientResponse:
                url = pages.make_url("/__companion/push/" + route)
                if body is None:
                    return await http.get(url)
                return await http.post(url, json=body)

            await work(companion, call)
            await asyncio.gather(*companion.tasks, return_exceptions=True)
            await pages.close()
            await companion.logs.close()

    with tempfile.TemporaryDirectory() as data:
        asyncio.run(run(Path(data)))


def subscribe_body(p256dh: str, endpoint: str = ENDPOINT) -> dict[str, object]:
    return {
        "subscription": {"endpoint": endpoint, "keys": {"p256dh": p256dh, "auth": b64url(AUTH)}},
        "topics": ["shot_result"],
        "label": "iPhone · Safari",
    }


def test_routes_follow_the_web_uis_sign_in(monkeypatch: pytest.MonkeyPatch) -> None:
    device = crypto.new_key()
    p256dh = b64url(crypto.public_point(device))
    access: list[object] = [(False, False)]

    async def work(
        companion: Companion, call: Callable[..., Awaitable[aiohttp.ClientResponse]]
    ) -> None:
        companion.push.post = sends_nothing
        body = subscribe_body(p256dh)
        assert (await call("subscribe", body)).status == 401, "a new device needs a sign-in"
        access[0] = None
        assert (await call("subscribe", body)).status == 503, "...which the controller confirms"
        access[0] = (True, False)
        assert (await call("subscribe", {**body, "topics": "x"})).status == 400
        ident = (await (await call("subscribe", body)).json())["id"]
        assert ident == device_id(ENDPOINT)

        access[0] = None
        assert (await call("subscribe", body)).status == 200, "a known device refreshes without"

        access[0] = False
        assert (await call("status")).status == 401
        sample = {"endpoint": ENDPOINT, "topic": "shot_result", "d": {"test": True}}
        assert (await call("test", sample)).status == 401
        access[0] = True
        status = await (await call("status")).json()
        assert status["devices"][0]["label"] == "iPhone · Safari"
        assert ENDPOINT not in json.dumps(status)

        assert (await call("test", {**sample, "endpoint": ENDPOINT + "x"})).status == 400
        assert (await call("test", {**sample, "delayS": 61})).status == 400
        assert (await call("test", sample)).status == 202
        assert (await call("test", sample)).status == 429, "samples are limited"

        access[0] = (True, False)
        assert (await call("remove", {"id": ident})).status == 401, "another device needs Admin"
        assert companion.push.knows(ENDPOINT)

        await call("ack", {"endpoint": ENDPOINT + "x", "mid": "m", "key": "k"})
        assert all(entry["kind"] != "received" for entry in companion.push.activity)
        await call("ack", {"endpoint": ENDPOINT, "mid": "m", "key": "k"})
        assert any(entry["kind"] == "received" for entry in companion.push.activity)

        access[0] = (True, True)
        assert (await (await call("remove", {"id": ident})).json())["removed"] is True
        await companion.push.subscribe(
            (ENDPOINT, p256dh, b64url(AUTH)), ["shot_result"], "iPhone · Safari"
        )
        access[0] = None
        assert (await call("unsubscribe", {"endpoint": ENDPOINT})).status == 200
        assert not companion.push.knows(ENDPOINT), "turning off works signed out, controller off"

    with_service(monkeypatch, work, access)


def test_events_and_the_ask_cross_the_link_as_frames(monkeypatch: pytest.MonkeyPatch) -> None:
    device = crypto.new_key()

    async def work(
        companion: Companion, _call: Callable[..., Awaitable[aiohttp.ClientResponse]]
    ) -> None:
        companion.push.post = sends_nothing
        await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": False})
        assert companion.outbox is None, "no link: nothing to tell"
        companion.outbox = asyncio.Queue()
        companion.sync_hold = False
        await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": False})
        asked = []
        while not companion.outbox.empty():
            asked.append(companion.outbox.get_nowait())
        assert all(frame["t"] != "ps" for frame in asked), "no device: nothing to ask for"
        parsed = (ENDPOINT, b64url(crypto.public_point(device)), b64url(AUTH))
        await companion.push.subscribe(parsed, ["shot_result"], "A")
        assert companion.outbox.get_nowait() == {"t": "ps", "on": True}
        await companion._on_frame({"t": "cfg", "ui": True, "log": False, "archive": False})
        asked = []
        while not companion.outbox.empty():
            asked.append(companion.outbox.get_nowait())
        assert {"t": "ps", "on": True} in asked, "a device: every session asks again"

        companion.sync_hold = True
        await companion.push.remove(device_id(ENDPOINT))
        assert companion.outbox.empty(), "a shot in progress: nothing crosses the link"
        assert companion.sync_due["push"] == {"t": "ps", "on": False}

        await companion.push.subscribe(parsed, ["shot_result"], "A")
        await companion._on_frame({**EVENT, "t": "ev"})
        assert companion.push.counters["events"] == 1
        with pytest.raises(LinkClosedError):
            await companion._on_frame({"t": "ev", "topic": "t"})
        assert companion.unknown_frames == 0

        await companion.erase("test")
        assert not companion.push.knows(ENDPOINT), "Forget erases the devices"
        assert (await companion.status())["push"] == companion.push.status_facts()
        companion.outbox = None

    with_service(monkeypatch, work, [True])


async def sends_nothing(
    endpoint: str, headers: dict[str, str], body: bytes
) -> tuple[int, str, float]:
    assert endpoint
    assert headers
    assert body
    return 201, "", 0.0
