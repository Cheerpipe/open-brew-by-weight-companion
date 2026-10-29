#!/usr/bin/env python3
"""The Web UI relay against a fake controller: handshake, signing, the header whitelist, the client id
rewrite, RELAY_STALE, erase, passthrough, the Web UI switch and the link flag.

The fake controller (tests/fake_controller.py) verifies every relayed request with its own copy of the
design's formulas. Offline, inside the image (see the README).
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import aiohttp  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import fake_controller  # noqa: E402
from companion import crypto, relay as relay_module, service  # noqa: E402
from companion.service import Companion, web_app  # noqa: E402

V = json.loads((ROOT / "tests/fixtures/companion-link-v1.vectors.json").read_text())
SECRET = bytes.fromhex(V["pairingSecret"])
ID = "0b9f6a3c-2f4e-4d7a-9c1b-5e8f0a1d2c3b"
A, B, DIRECT = "0123456789abcdef", "fedcba9876543210aa", "aaaaaaaaaaaaaaaaaaaaaaaa"


class Idle:
    """La Marzocco stays off in these tests."""

    sub = up = False
    ep = tok = 0
    refused = False

    def __init__(self, store, events):
        pass

    def configure(self, *args):
        pass

    def erase(self):
        pass

    def stop(self):
        pass


async def eventually(predicate, timeout=3):
    for _ in range(int(timeout / 0.02)):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not reached")


def relay_vectors():
    """The relay formulas against the firmware's shared vectors and the fake controller."""
    r = V["relay"]
    rb, nc = crypto.unb64(r["challenge"], 16), crypto.unb64(r["nonce"], 16)
    assert crypto.mac(SECRET, b"R", rb, nc) == crypto.unb64(r["request"])
    assert crypto.mac(SECRET, b"Q", rb, nc) == crypto.unb64(r["reply"])
    assert crypto.mac(SECRET, b"E", nc) == crypto.unb64(r["erase"])
    key = crypto.relay_key(SECRET, rb, nc)
    assert key.hex() == r["key"] and key == fake_controller.relay_key(SECRET, rb, nc)
    for case in r["requests"]:
        _, q, addr, screen, tag = case["header"].split(" ")
        args = (case["method"], case["uri"], int(q), addr, screen, case["session"])
        assert crypto.relay_tag(key, *args) == tag == fake_controller.relay_tag(key, *args)
    assert crypto.relay_tag(key, "POST", "/api/v1/config?x=1", 7, "192.168.1.50", A, "") != \
        r["requests"][0]["header"].split(" ")[4]


async def main():
    relay_vectors()
    fake = fake_controller.Controller(SECRET, ID)
    server = TestServer(fake.app(), host="127.0.0.1")
    await server.start_server()
    target = ("Cafe Bar", ("127.0.0.1", server.port))
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-relay-") as temporary:
        data = Path(temporary)
        service.Store(data).write("identity", {"id": ID, "key": V["companionPrivate"]})
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as http, \
                aiohttp.ClientSession(auto_decompress=False) as browser:
            companion = Companion("Kitchen server", data, http, Idle)
            relay = companion.relay
            pages = TestServer(web_app(companion), host="127.0.0.1")
            await pages.start_server()
            base = f"http://127.0.0.1:{pages.port}"

            async def call(method, path, client=A, real_ip="192.168.1.50", **kwargs):
                headers = {"X-Real-IP": real_ip, **({"X-WebUI-Client": client} if client else {}),
                           **kwargs.pop("headers", {})}
                async with browser.request(method, base + path, headers=headers, **kwargs) as reply:
                    return reply.status, dict(reply.headers), await reply.read()

            # --- No controller yet -------------------------------------------------------
            status, _, body = await call("GET", "/api/v1/status/admin")
            assert status == 503 and json.loads(body)["error"] == "NO_CONTROLLER"

            # --- Not paired: the plain proxy it always was -----------------------------------
            companion.pairing.auto = False
            companion.set_controller(target)
            await asyncio.sleep(0.1)
            assert relay.mode == "passthrough" and (await companion.status())["relay"] == "passthrough"
            fake.active = A
            status, _, body = await call("GET", "/api/v1/status/admin", headers={"Cookie": "x=1"})
            method, uri, headers, _, identity = fake.requests[-1]
            assert status == 200 and identity is None and headers["X-WebUI-Client"] == A
            assert "Cookie" not in headers and "X-Real-IP" not in headers and "X-OBBW-Relay" not in headers

            # --- Paired: one relay session, every call signed -----------------------------------
            companion.store.save_pairing(SECRET, "Cafe Bar")
            companion.pairing.state = "paired"
            assert await relay.handshake() == "ready" and fake.handshakes == 1
            assert (await companion.status())["relay"] == "ready" and relay.link is False, "no feature needs the link"
            status, _, body = await call("POST", "/api/v1/ui/claim", json={}, headers={
                "X-WebUI-Session": "token", "X-Evil": "1", "Cookie": "x=1"})
            assert status == 200 and json.loads(body)["active"] is True
            method, uri, headers, _, identity = fake.requests[-1]
            assert headers["X-WebUI-Client"] == relay.client_id and fake.active == relay.client_id
            assert identity == {"q": 1, "addr": "192.168.1.50", "screen": A, "session": "token"}
            assert not {"X-Evil", "Cookie", "X-Real-IP"} & set(headers)
            assert companion.screens.mux.claimed == {A} and (await companion.status())["owner"] is True

            # A claimed screen's calls carry the shared id; another screen's keep its own.
            status, _, _ = await call("GET", "/api/v1/time/zones?q=a%20b&x=1")
            assert status == 200 and fake.requests[-1][1] == "/api/v1/time/zones?q=a%20b&x=1", "the URI goes as sent"
            assert fake.requests[-1][4]["q"] == 2 and fake.requests[-1][2]["X-WebUI-Client"] == relay.client_id
            status, _, body = await call("GET", "/api/v1/status/admin", client=B)
            assert status == 409 and fake.requests[-1][2]["X-WebUI-Client"] == B
            assert companion.screens.mux.claimed == {A}, "an unclaimed screen's refusal is not a takeover"

            # Addresses as nginx gives them.
            await call("GET", "/api/v1/auth", real_ip="fe80::1%eth0")
            assert fake.requests[-1][4]["addr"] == "fe80::1"
            await call("GET", "/api/v1/auth", real_ip="")
            assert fake.requests[-1][4]["addr"] == "0.0.0.0"

            # --- Firmware updates: their headers and 64 KiB chunks --------------------------------
            ota = {"X-OTA-Transfer": "t1", "X-OTA-Offset": "0", "X-OTA-Length": "65536",
                   "Content-Range": "bytes 0-65535/65536", "Content-Type": "application/octet-stream",
                   "X-Device-Password": "pw"}
            status, _, body = await call("PATCH", "/api/v1/ota", data=bytes(65536), headers=ota)
            assert status == 200 and json.loads(body)["received"] == 65536
            assert all(fake.requests[-1][2][name] == value for name, value in ota.items())

            # --- Downloads stream through untouched ---------------------------------------------------
            status, headers, body = await call("GET", "/api/v1/debug/export")
            assert status == 200 and len(body) == 4 * (32 * 1024 + 2) and body[:2] == b"\x1f\x8b"
            assert headers["Content-Encoding"] == "gzip" and "export.gz" in headers["Content-Disposition"]

            # --- RELAY_STALE: one new session and the same request again ----------------------------
            fake.stale_next = True
            status, _, body = await call("POST", "/api/v1/config", json={"patch": {"a": 1}})
            assert status == 202 and fake.handshakes == 2
            assert json.loads(fake.requests[-1][3]) == {"patch": {"a": 1}} and fake.requests[-1][4]["q"] == 1

            # A counter at its end starts a new session first.
            relay.counter = relay_module.COUNTER_MAX
            await call("GET", "/api/v1/auth")
            assert fake.handshakes == 3 and fake.requests[-1][4]["q"] == 1

            # --- The link opens only when the controller says a feature needs it [D4] ------------------
            link = companion.spawn(companion.run_link())
            await asyncio.sleep(0.3)
            assert companion.link == "down" and not [r for r in fake.requests if r[1] == "/api/v1/companion/link"]
            # Admin → Companion's actions may change the switches: the relay asks again.
            fake.link = True
            await call("POST", "/api/v1/companion/admin", json={"action": "switches", "lm": True})
            await eventually(lambda: fake.handshakes == 4 and relay.link is True)
            await eventually(lambda: any(r[1] == "/api/v1/companion/link" for r in fake.requests))
            link.cancel()

            # --- A direct browser took the Web UI ------------------------------------------------------
            fake.active = DIRECT
            status, _, body = await call("GET", "/api/v1/status/admin")
            assert status == 409 and json.loads(body)["error"] == "UI_TAKEN_OVER"
            assert companion.screens.mux.claimed == set()
            status, _, _ = await call("POST", "/api/v1/ui/claim", json={})
            assert status == 200 and fake.active == relay.client_id and companion.screens.mux.claimed == {A}

            # --- The Web UI through the companion turned off ---------------------------------------
            fake.ui = False
            assert await relay.handshake() == "disabled" and (await companion.status())["relay"] == "disabled"
            status, _, body = await call("GET", "/api/v1/status/admin")
            assert status == 409 and json.loads(body)["error"] == "COMPANION_UI_OFF"
            status, _, _ = await call("GET", "/api/v1/ui/ui-stream")
            assert status == 409
            async with browser.get(base + "/__companion/ui-gate", headers={"X-Original-URI": "/stats"}) as reply:
                assert reply.status == 403
            async with browser.get(base + "/__companion/ui-gate", headers={"X-Original-URI": "/sw.js?v=1"}) as reply:
                assert reply.status == 204, "the service worker keeps updating"
            async with browser.get(base + "/__companion/ui-off") as reply:
                page = await reply.text()
                assert reply.status == 200 and f"http://127.0.0.1:{server.port}/" in page and "@STYLE@" not in page
            fake.ui = True
            assert await relay.handshake() == "ready"
            async with browser.get(base + "/__companion/ui-gate", headers={"X-Original-URI": "/stats"}) as reply:
                assert reply.status == 204

            # --- A controller without the relay (phase 1): passthrough, the link always on -------------
            fake.mode = "none"
            assert await relay.handshake() == "passthrough" and relay.link is True
            fake.active = B
            status, _, _ = await call("GET", "/api/v1/status/admin", client=B)
            assert status == 200 and fake.requests[-1][4] is None and fake.requests[-1][2]["X-WebUI-Client"] == B
            fake.require_relay_stream = False
            async with browser.ws_connect(base + "/api/v1/ui/ui-stream") as ws:
                await ws.send_str(json.dumps({"op": "bind", "client": B}))
                assert json.loads((await ws.receive()).data)["type"] == "home"
                assert fake.streams[-1].identity is None, "the browser's own session, unsigned"
            async with browser.ws_connect(base + "/api/v1/ui/ui-stream") as ws:
                await ws.send_str(json.dumps({"op": "bind", "client": A}))
                message = await ws.receive()
                assert message.type is aiohttp.WSMsgType.CLOSE and message.data == 4001, "close codes pass through"

            # --- A forged answer, an unsigned refusal, then a real erase ----------------------------------
            fake.mode = "bad_proof"
            assert await relay.handshake() == "passthrough" and companion.store.pairing()
            fake.mode = "unknown"
            await relay.handshake()
            assert companion.pairing.state == "not_recognized" and companion.store.pairing(), "unsigned: nothing erased"
            fake.mode = "ok"
            assert await relay.handshake() == "ready" and companion.pairing.state == "paired"
            fake.mode = "bad_erase"
            await relay.handshake()
            assert companion.store.pairing() and relay.mode == "passthrough"
            fake.mode = "forgotten"
            await relay.handshake()
            assert companion.store.pairing() is None and companion.pairing.state == "unpaired"
            assert relay.mode == "passthrough" and relay.link is None

            async with browser.get(base + "/__companion/status") as reply:
                status = await reply.json()
            assert status["relay"] == "passthrough" and status["screens"] == 0 and status["paired"] is False
            assert set(status["views"]) == {"home", "settings", "diagnostic", "log", "history", "stats"}
            await pages.close()
            await relay.close()
    await server.close()
    print("Companion relay: handshake, signing, whitelist, client id, stale retry, erase, passthrough and switch OK")


asyncio.run(main())
