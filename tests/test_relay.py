"""The Web UI relay against a fake controller: handshake, signing and sealing, the header
whitelist, the client id rewrite, RELAY_STALE, erase, passthrough, the Web UI switch and the
link flag. The fake controller (tests/fake_controller.py) verifies every relayed request with
its own copy of the design's formulas. Offline, inside the image (see the README).
"""

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiohttp
import pytest
from aiohttp.test_utils import TestServer
from cryptography.exceptions import InvalidTag

import fake_controller
from companion import crypto
from companion import relay as relay_module
from companion import screens as screens_module
from companion import service as service_module
from companion.service import Companion, web_app
from companion.store import Store

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from companion.store import Account

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / "tests/fixtures/companion-link-v1.vectors.json").read_text())
SECRET = bytes.fromhex(V["pairingSecret"])
ID = "0b9f6a3c-2f4e-4d7a-9c1b-5e8f0a1d2c3b"
A, B, DIRECT = "0123456789abcdef", "fedcba9876543210aa", "aaaaaaaaaaaaaaaaaaaaaaaa"


class Idle:
    """La Marzocco stays off in these tests."""

    sub = up = False
    ep = tok = 0
    refused = policy = False

    def __init__(self, store: Store, events: Companion) -> None:
        pass

    def configure(self, *args: object) -> None:
        pass

    def erase(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def signed_in_for(self, _account: Account) -> bool:
        return False

    def rejected_for(self, _account: Account) -> bool:
        return False

    async def read(self) -> tuple[int, dict[str, object] | None, int]:
        return 0, None, 0

    async def command(self, _command_id: int, _op: str, _value: int | None) -> int:
        return 0


async def eventually(predicate: Callable[[], bool], within: float = 3) -> None:
    for _ in range(int(within / 0.02)):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not reached")


def last_identity(fake: fake_controller.Controller) -> fake_controller.Identity | None:
    """The last request's relay identity; None when it arrived unsigned."""
    return fake.requests[-1][4]


def relayed(fake: fake_controller.Controller) -> fake_controller.Identity:
    """The last request's relay identity: it arrived signed."""
    identity = last_identity(fake)
    assert identity is not None
    return identity


def test_relay_vectors() -> None:
    """The relay formulas against the firmware's shared vectors and the fake controller."""
    r = V["relay"]
    rb, nc = crypto.unb64(r["challenge"], 16), crypto.unb64(r["nonce"], 16)
    assert crypto.mac(SECRET, b"R", rb, nc) == crypto.unb64(r["request"])
    assert crypto.mac(SECRET, b"Q", rb, nc) == crypto.unb64(r["reply"])
    assert crypto.mac(SECRET, b"E", nc) == crypto.unb64(r["erase"])
    key = crypto.relay_key(SECRET, rb, nc)
    assert key.hex() == r["key"]
    assert key == fake_controller.relay_key(SECRET, rb, nc)
    kb = crypto.relay_body_key(key)
    assert kb.hex() == r["bodyKey"], "Kb from the shared vectors"
    assert kb == fake_controller.body_key(key), "Kb from the shared vectors"
    # A seal opens only with its own context, its own request, and untouched bytes.
    sealed = crypto.relay_seal(kb, 0, 7, b"0123456789abcdef0123456789abcdef")
    assert fake_controller.open_(kb, b"c", 0, 7, sealed) == b"0123456789abcdef0123456789abcdef"
    openers: tuple[Callable[[], bytes], ...] = (
        lambda: fake_controller.open_(kb, b"c", 1, 7, sealed),  # another context
        lambda: fake_controller.open_(kb, b"c", 0, 8, sealed),  # another request's q
        lambda: fake_controller.open_(kb, b"c", 0, 7, sealed[:-1] + bytes((sealed[-1] ^ 1,))),
    )
    for opener in openers:
        # A seal never opens for another context, request or after tampering.
        with pytest.raises(InvalidTag):
            opener()
    for case in r["requests"]:
        _, q, addr, screen, tag = case["header"].split(" ")
        args = (case["method"], case["uri"], int(q), addr, screen, case["session"])
        assert crypto.relay_tag(key, *args) == tag == fake_controller.relay_tag(key, *args)
    assert (
        crypto.relay_tag(key, "POST", "/api/v1/config?x=1", 7, "192.168.1.50", A, "")
        != r["requests"][0]["header"].split(" ")[4]
    )


async def relay_scenario(data: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = fake_controller.Controller(SECRET, ID)
    server = TestServer(fake.app(), host="127.0.0.1")
    await server.start_server()
    assert server.port is not None
    target = ("Cafe Bar", ("127.0.0.1", server.port))
    Store(data).write("identity", {"id": ID, "key": V["companionPrivate"]})
    async with (
        aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as http,
        aiohttp.ClientSession(auto_decompress=False) as browser,
    ):
        companion = Companion("Kitchen server", data, http, Idle)
        relay = companion.relay
        pages = TestServer(web_app(companion), host="127.0.0.1")
        await pages.start_server()
        base = f"http://127.0.0.1:{pages.port}"

        async def call(
            method: str,
            path: str,
            client: str = A,
            real_ip: str = "192.168.1.50",
            *,
            headers: Mapping[str, str] | None = None,
            json: object = None,
            data: bytes | None = None,
        ) -> tuple[int, dict[str, str], bytes]:
            sent = {
                "X-Real-IP": real_ip,
                **({"X-WebUI-Client": client} if client else {}),
                **(headers or {}),
            }
            async with browser.request(
                method, base + path, headers=sent, json=json, data=data
            ) as reply:
                return reply.status, dict(reply.headers), await reply.read()

        # --- Not paired: nothing reaches the controller, with or without one known -----------
        status, _, body = await call("GET", "/api/v1/status/admin")
        assert status == 409
        assert json.loads(body)["error"] == "COMPANION_NOT_PAIRED"
        companion.pairing.auto = False
        companion.set_controller(target)
        await asyncio.sleep(0.1)
        assert relay.mode == "passthrough"
        assert (await companion.status())["relay"] == "passthrough"
        fake.active = A
        status, _, body = await call("POST", "/api/v1/auth/login", json={"password": "secret"})
        assert status == 409
        assert json.loads(body)["error"] == "COMPANION_NOT_PAIRED"
        assert fake.requests == [], "no password crosses an unpaired companion"
        with pytest.raises(aiohttp.WSServerHandshakeError) as refused_stream:
            await browser.ws_connect(base + "/api/v1/ui/ui-stream")
        assert refused_stream.value.status == 409

        # --- Paired: one relay session, every call signed and sealed --------------------------
        companion.store.save_pairing(SECRET, "Cafe Bar")
        companion.pairing.state = "paired"
        assert await relay.handshake() == "ready"
        assert fake.handshakes == 1
        assert (await companion.status())["relay"] == "ready", "no feature needs the link"
        assert (relay.mode, relay.link) == ("ready", False), "no feature needs the link"
        status, reply_headers, body = await call(
            "POST",
            "/api/v1/ui/claim",
            json={},
            headers={"X-WebUI-Session": "token", "X-Evil": "1", "Cookie": "x=1"},
        )
        assert status == 200
        assert json.loads(body)["active"] is True
        _, _, headers, _, identity = fake.requests[-1]
        assert headers["X-WebUI-Client"] == relay.client_id
        assert fake.active == relay.client_id
        assert identity == {
            "q": 2,  # The session's first request, reading the features, took 1.
            "version": 3,
            "addr": "192.168.1.50",
            "screen": A,
            "session": "token",
            "password": "",
        }
        assert not {"X-Evil", "Cookie", "X-Real-IP"} & set(headers)
        # The wire carried ciphertext: the token never travelled as itself, and the
        # sealing counter never reached the browser.
        raw_session, raw_password, raw_body = fake.wire[-1]
        assert raw_session != "token", "the body was sealed too"
        assert raw_password == "", "the body was sealed too"
        assert raw_body, "the body was sealed too"
        assert "X-OBBW-Enc" not in reply_headers
        assert companion.screens.mux.claimed == {A}
        assert (await companion.status())["owner"] is True

        # A claimed screen's calls carry the shared id; another screen's keep its own.
        status, _, _ = await call("GET", "/api/v1/time/zones?q=a%20b&x=1")
        assert status == 200, "the URI goes as sent"
        assert fake.requests[-1][1] == "/api/v1/time/zones?q=a%20b&x=1", "the URI goes as sent"
        assert relayed(fake)["q"] == 3
        assert fake.requests[-1][2]["X-WebUI-Client"] == relay.client_id
        status, _, body = await call("GET", "/api/v1/status/admin", client=B)
        assert status == 409
        assert fake.requests[-1][2]["X-WebUI-Client"] == B
        assert companion.screens.mux.claimed == {A}, (
            "an unclaimed screen's refusal is not a takeover"
        )

        # Without a client id a change is refused here; a read goes as on the controller itself.
        seen = len(fake.requests)
        status, _, body = await call("POST", "/api/v1/ui/claim", client="", json={})
        assert status == 400
        assert json.loads(body)["error"] == "UI_CLIENT_INVALID"
        assert len(fake.requests) == seen
        status, _, _ = await call("GET", "/api/v1/auth", client="")
        assert status == 200
        assert relayed(fake)["screen"] == relay.client_id

        # Addresses as nginx gives them.
        await call("GET", "/api/v1/auth", real_ip="fe80::1%eth0")
        assert relayed(fake)["addr"] == "fe80::1"
        await call("GET", "/api/v1/auth", real_ip="")
        assert relayed(fake)["addr"] == "0.0.0.0"

        # --- Firmware updates: their headers and 64 KiB chunks, the password sealed ---------
        # The range itself travels as it is (its integrity is the session sha256).
        ota = {
            "X-OTA-Transfer": "t1",
            "X-OTA-Offset": "0",
            "X-OTA-Length": "65536",
            "Content-Range": "bytes 0-65535/65536",
            "Content-Type": "application/octet-stream",
            "X-Device-Password": "pw",
        }
        status, _, body = await call("PATCH", "/api/v1/ota", data=bytes(65536), headers=ota)
        assert status == 200
        assert json.loads(body)["received"] == 65536
        assert all(fake.requests[-1][2][name] == value for name, value in ota.items())
        _, raw_password, raw_body = fake.wire[-1]
        assert raw_password != "pw", "password sealed, range plain"
        assert len(raw_body) == 65536, "password sealed, range plain"

        # --- Seals that do not open: refused, never delivered -------------------------------
        fake.corrupt_body = True
        status, _, body = await call("POST", "/api/v1/config", json={"patch": {"a": 1}})
        assert status == 400
        assert json.loads(body)["error"] == "RELAY_INVALID"
        fake.corrupt_body, fake.corrupt_reply = False, True
        status, _, body = await call("GET", "/api/v1/auth")
        assert status == 502, "a tampered answer is never delivered"
        assert last_identity(fake) is not None, "a tampered answer is never delivered"
        assert relay.key is None, "the next request makes a new relay session"
        fake.corrupt_reply = False

        # --- Downloads stream through untouched ---------------------------------------------------
        status, headers, body = await call("GET", "/api/v1/debug/export")
        assert status == 200
        assert len(body) == 4 * (32 * 1024 + 2)
        assert body[:2] == b"\x1f\x8b"
        assert headers["Content-Encoding"] == "gzip"
        assert "export.gz" in headers["Content-Disposition"]

        # A download never delays a sign-in or a claim, and one nobody reads ends.
        async with companion.screens.reads:
            status, _, _ = await asyncio.wait_for(call("GET", "/api/v1/auth"), 2)
            assert status == 200
            status, _, _ = await asyncio.wait_for(call("POST", "/api/v1/ui/claim", json={}), 2)
            assert status == 200
        screens_module.WRITE_S = 0
        with pytest.raises(aiohttp.ClientError):
            await call("GET", "/api/v1/debug/export")
        screens_module.WRITE_S = 10
        assert not companion.screens.reads.locked()

        # --- RELAY_STALE: one new session and the same request again ----------------------------
        fake.stale_next = True
        status, _, body = await call("POST", "/api/v1/config", json={"patch": {"a": 1}})
        assert status == 202, "the tampered answer cost one session already"
        assert fake.handshakes == 3, "the tampered answer cost one session already"
        assert json.loads(fake.requests[-1][3]) == {"patch": {"a": 1}}
        assert relayed(fake)["q"] == 2

        # A stale answer that arrives after another request replaced the session keeps the new
        # one: this request retries with it, and nothing pays for a further handshake.
        send, rotated = relay._send, False

        async def rotating(*args: Any) -> relay_module.Reply:
            nonlocal rotated
            reply = await send(*args)
            if not rotated:
                rotated = True
                await relay.handshake()
            return reply

        with monkeypatch.context() as patch:
            patch.setattr(relay, "_send", rotating)
            fake.stale_next = True
            handshakes = fake.handshakes
            status, _, _ = await call("GET", "/api/v1/auth")
        assert status == 200
        assert fake.handshakes == handshakes + 1

        # A counter at its end starts a new session first.
        relay.counter = relay_module.COUNTER_MAX
        await call("GET", "/api/v1/auth")
        assert fake.handshakes == 5
        assert relayed(fake)["q"] == 2

        # --- The link opens only when the controller says a feature needs it [D4]
        link = companion.spawn(companion.run_link())
        await asyncio.sleep(0.3)
        assert companion.link == "down"
        assert not [r for r in fake.requests if r[1] == "/api/v1/companion/link"]
        # Admin → Companion's actions may change the switches: the relay asks again.
        fake.link = True
        await call("POST", "/api/v1/companion/admin", json={"action": "switches", "lm": True})
        await eventually(lambda: fake.handshakes == 6 and relay.link is True)
        await eventually(lambda: any(r[1] == "/api/v1/companion/link" for r in fake.requests))
        link.cancel()

        # --- A direct browser took the Web UI
        fake.active = DIRECT
        status, _, body = await call("GET", "/api/v1/status/admin")
        assert status == 409
        assert json.loads(body)["error"] == "UI_TAKEN_OVER"
        assert companion.screens.mux.claimed == set()
        status, _, _ = await call("POST", "/api/v1/ui/claim", json={})
        assert status == 200
        assert fake.active == relay.client_id
        assert companion.screens.mux.claimed == {A}

        # --- The Web UI through the companion turned off ---------------------------------------
        fake.ui = False
        assert await relay.handshake() == "disabled"
        assert (await companion.status())["relay"] == "disabled"
        status, _, body = await call("GET", "/api/v1/status/admin")
        assert status == 409
        assert json.loads(body)["error"] == "COMPANION_UI_OFF"
        status, _, _ = await call("GET", "/api/v1/ui/ui-stream")
        assert status == 409
        async with browser.get(
            base + "/__companion/ui-gate", headers={"X-Original-URI": "/stats"}
        ) as reply:
            assert reply.status == 403
        async with browser.get(
            base + "/__companion/ui-gate", headers={"X-Original-URI": "/sw.js?v=1"}
        ) as reply:
            assert reply.status == 204, "the service worker keeps updating"
        async with browser.get(base + "/__companion/ui-off") as reply:
            page = await reply.text()
            assert reply.status == 200
            assert f"http://127.0.0.1:{server.port}/" in page
            assert "@STYLE@" not in page
        fake.ui = True
        async with browser.get(
            base + "/__companion/ui-gate", headers={"X-Original-URI": "/stats"}
        ) as reply:
            assert reply.status == 403, "a page load asks again only once a minute"
        service_module.GATE_HANDSHAKE_S = 0
        async with browser.get(
            base + "/__companion/ui-gate", headers={"X-Original-URI": "/stats"}
        ) as reply:
            assert reply.status == 204, "turned back on at the controller's own address"
        service_module.GATE_HANDSHAKE_S = 60
        assert (await companion.status())["relay"] == "ready"
        async with browser.get(
            base + "/__companion/ui-gate", headers={"X-Original-URI": "/stats"}
        ) as reply:
            assert reply.status == 204

        # A switch changed from a direct page reaches an open link as a `cfg` frame.
        fake.ui = False
        await companion._on_frame({"t": "cfg", "ui": False})
        await eventually(lambda: relay.mode == "disabled")
        fake.ui = True
        await companion._on_frame({"t": "cfg", "ui": True})
        await eventually(lambda: relay.mode == "ready")
        asked = fake.relay_gets
        await companion._on_frame({"t": "cfg", "ui": True})
        await asyncio.sleep(0.05)
        assert fake.relay_gets == asked, "an unchanged switch costs no handshake"

        # --- A failed relay handshake while paired: refused, never in clear; the link always on --
        fake.mode = "none"
        assert await relay.handshake() == "passthrough"
        assert (relay.mode, relay.link) == ("passthrough", True)
        fake.active = B
        seen = len(fake.requests)

        async def refused(client: str) -> None:
            status, _, body = await call(
                "POST", "/api/v1/ui/claim", client=client, json={}, headers={"X-WebUI-Session": "s"}
            )
            assert status == 502
            assert f"http://127.0.0.1:{server.port}" in json.loads(body)["message"]
            status, _, body = await call("GET", "/api/v1/status/admin", client=client)
            assert status == 502
            assert len(fake.requests) == seen, "nothing crossed in clear"
            assert not companion.screens.mux.claimed, "no claim without a relay session"
            with pytest.raises(aiohttp.WSServerHandshakeError) as refusal:
                await browser.ws_connect(base + "/api/v1/ui/ui-stream")
            assert refusal.value.status == 502
            assert not fake.streams, "nothing crossed in clear"
            assert await companion._web_ui_allows({"X-WebUI-Client": client}) is None
            assert len(fake.requests) == seen, "an answer in clear could be forged"

        await refused(B)
        fake.mode = "bad_proof"  # A forged answer.
        await relay.handshake()
        await refused(B)

        # A lasting failure costs one handshake every RENEW_S, however many requests ask.
        relay.renew_at = float("-inf")
        asked = fake.relay_gets
        for _ in range(3):
            await call("GET", "/api/v1/status/admin", client=B)
        assert fake.relay_gets == asked + 1

        fake.mode = "unknown"  # An unsigned refusal: no secret in common, as far as anyone knows.
        await relay.handshake()
        assert companion.pairing.state == "not_recognized", "unsigned: nothing erased"
        assert companion.store.pairing(), "unsigned: nothing erased"
        status, _, body = await call("GET", "/api/v1/status/admin", client=B)
        assert status == 409
        assert json.loads(body)["error"] == "COMPANION_NOT_PAIRED"
        assert len(fake.requests) == seen, "nothing crossed in clear"
        async with browser.get(base + "/__companion/status") as reply:
            assert (await reply.json())["relay"] == "passthrough"
        # An answer from the controller needs no wait: a handshake the announcement starts
        # brings the session back, and the requests with it.
        fake.mode = "ok"
        assert await relay.handshake() == "ready"
        status, _, _ = await call("GET", "/api/v1/auth", client=B)
        assert status == 200
        assert last_identity(fake) is not None

        # A busy controller ends nothing: the session stays.
        fake.mode = "busy"
        assert await relay.handshake() == "ready"
        assert relay.body_key is not None
        fake.ui = False
        fake.mode = "ok"
        assert await relay.handshake() == "disabled"
        fake.mode = "busy"
        assert await relay.handshake() == "disabled", "the switch stays known"
        fake.ui = True
        fake.mode = "ok"
        assert await relay.handshake() == "ready"

        # A session lost after a success renews at once, whatever failed before.
        relay.key, relay.body_key = None, None
        status, _, _ = await call("GET", "/api/v1/auth", client=B)
        assert status == 200

        # A companion that starts paired has no session yet: its first request makes one.
        relay.reset()
        assert relay.mode == "passthrough"
        status, _, _ = await call("GET", "/api/v1/auth", client=B)
        assert status == 200
        assert (relay.mode, last_identity(fake) is not None) == ("ready", True)

        # --- An erased pairing relays nothing again ----------------------------------------------
        fake.mode = "bad_erase"
        await relay.handshake()
        assert companion.store.pairing()
        assert relay.mode == "passthrough"
        fake.mode = "forgotten"
        relay.renew_at = float("-inf")
        seen = len(fake.requests)
        assert await relay.handshake() == "passthrough", "a signed erase, this time"
        status, _, body = await call("GET", "/api/v1/status/admin", client=B)
        assert status == 409, "nothing is relayed after the erase"
        assert json.loads(body)["error"] == "COMPANION_NOT_PAIRED"
        assert len(fake.requests) == seen
        assert companion.store.pairing() is None
        assert companion.pairing.state == "unpaired"
        assert (relay.mode, relay.link) == ("passthrough", None)

        async with browser.get(base + "/__companion/status") as reply:
            facts = await reply.json()
        assert facts["relay"] == "passthrough"
        assert facts["screens"] == 0
        assert facts["paired"] is False
        assert set(facts["views"]) == {
            "home",
            "settings",
            "diagnostic",
            "log",
            "history",
            "stats",
        }

        await pages.close()
        await relay.close()
    await server.close()


def test_relay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Companion relay: handshake, signing, sealing, whitelist, client id, stale retry, erase,
    passthrough and switch."""
    asyncio.run(relay_scenario(tmp_path, monkeypatch))
