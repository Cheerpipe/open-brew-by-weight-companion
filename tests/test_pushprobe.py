"""The Web Push probe: RFC 8291's vector, the VAPID token and the page's routes. Offline."""

import asyncio
import json
import tempfile
from pathlib import Path

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from companion import crypto, pushprobe
from companion.pushprobe import b64url, unb64url
from companion.store import Store

PAGE = Path(pushprobe.__file__).parent / "push-probe.html"
ENDPOINT = "https://web.push.apple.com/abc"
HTTPS = {"X-Real-IP": "192.0.2.1"}


def rfc_key(text: str) -> ec.EllipticCurvePrivateKey:
    return crypto.load_key(unb64url(text))


def subscription(key: ec.EllipticCurvePrivateKey, auth: bytes) -> dict[str, object]:
    return {
        "endpoint": ENDPOINT,
        "keys": {"p256dh": b64url(crypto.public_point(key)), "auth": b64url(auth)},
    }


def open_record(body: bytes, key: ec.EllipticCurvePrivateKey, auth: bytes) -> bytes:
    salt, length = body[:16], body[20]
    theirs = body[21 : 21 + length]
    secret = key.exchange(ec.ECDH(), crypto.load_point(theirs))
    info = b"WebPush: info\0" + crypto.public_point(key) + theirs

    def derive(ikm: bytes, use_salt: bytes, use_info: bytes, size: int) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=size, salt=use_salt, info=use_info).derive(
            ikm
        )

    ikm = derive(secret, auth, info, 32)
    cek = derive(ikm, salt, b"Content-Encoding: aes128gcm\0", 16)
    nonce = derive(ikm, salt, b"Content-Encoding: nonce\0", 12)
    return AESGCM(cek).decrypt(nonce, body[21 + length :], None)


def test_encrypt_matches_rfc8291_vector() -> None:
    body = pushprobe.encrypt(
        b"When I grow up, I want to be a watermelon",
        unb64url(
            "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
        ),
        unb64url("BTBZMqHH6r4Tts7J_aSIgg"),
        rfc_key("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"),
        unb64url("DGv6ra1nlYgDCS1FRnbzlw"),
    )
    assert b64url(body) == (
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmY"
        "WAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexS"
        "gSxsj_Qulcy4a-fN"
    )


def test_vapid_header_verifies_with_its_key() -> None:
    key = crypto.new_key()
    header = pushprobe.vapid_header(key, ENDPOINT, 1000.0)
    token, _, public = header.removeprefix("vapid t=").partition(", k=")
    head, claims, signature = token.split(".")
    assert unb64url(public) == crypto.public_point(key)
    parsed = json.loads(unb64url(claims))
    assert parsed["aud"] == "https://web.push.apple.com"
    assert parsed["exp"] == 1000 + pushprobe.JWT_LIFE_S
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
        ("http://web.push.apple.com/x", False),
        ("https://evilpush.apple.com/x", False),
        ("https://fcm.googleapis.com.evil.test/x", False),
        ("https://192.168.1.1/x", False),
    ],
)
def test_only_push_services_are_allowed(endpoint: str, allowed: bool) -> None:
    assert pushprobe.allowed_endpoint(endpoint) is allowed


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
    assert pushprobe.parse_subscription(body) is None


def test_post_reports_the_answer_and_an_unreachable_service() -> None:
    async def run() -> None:
        async def answer(request: web.Request) -> web.Response:
            assert await request.read() == b"body"
            return web.Response(status=201, text="created")

        app = web.Application()
        app.router.add_post("/", answer)
        server = TestServer(app, host="127.0.0.1")
        await server.start_server()
        url = str(server.make_url("/"))
        assert await pushprobe.post(url, {}, b"body") == (201, "created")
        await server.close()
        status, _detail = await pushprobe.post(url, {}, b"body")
        assert status == 0

    asyncio.run(run())


def test_page_subscribe_and_delayed_send(monkeypatch: pytest.MonkeyPatch) -> None:
    device, auth = crypto.new_key(), b"\x01" * 16
    sent: list[tuple[str, dict[str, str], bytes]] = []

    async def fake_post(endpoint: str, headers: dict[str, str], body: bytes) -> tuple[int, str]:
        sent.append((endpoint, headers, body))
        return 201, ""

    monkeypatch.setattr(pushprobe, "post", fake_post)

    async def run(data: Path) -> None:
        app = web.Application()
        app.router.add_routes(pushprobe.routes(Store(data), PAGE))
        server = TestServer(app, host="127.0.0.1")
        await server.start_server()
        base = pushprobe.BASE
        async with aiohttp.ClientSession() as http:

            async def get(path: str) -> aiohttp.ClientResponse:
                return await http.get(server.make_url(base + path))

            async def post(
                path: str, body: object, headers: dict[str, str] | None = None
            ) -> aiohttp.ClientResponse:
                return await http.post(
                    server.make_url(base + path),
                    json=body,
                    headers=HTTPS if headers is None else headers,
                )

            page = await (await get("")).text()
            assert "@VAPID_KEY@" not in page
            assert (await get("sw.js")).content_type == "application/javascript"
            manifest = await (await get("manifest.webmanifest")).json(content_type=None)
            assert manifest["display"] == "standalone"

            body = subscription(device, auth)
            assert (await post("subscribe", body, {})).status == 403
            refused = await http.post(server.make_url(base + "subscribe"), data="x", headers=HTTPS)
            assert refused.status == 415
            assert (await post("subscribe", {"endpoint": "https://evil.test/"})).status == 400
            ident = (await (await post("subscribe", body)).json())["id"]

            assert (await post("send", {"id": "nobody"})).status == 404
            assert (await post("send", {"id": ident, "delayS": 301})).status == 400
            assert (await post("send", {"id": ident, "delayS": 0})).status == 202
            for _ in range(100):
                if sent:
                    break
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.01)
            result = await (await get(f"result?id={ident}")).json()
            assert result["status"] == 201
        await server.close()

    with tempfile.TemporaryDirectory() as data:
        asyncio.run(run(Path(data)))
        saved = json.loads((Path(data) / "secrets" / "push-probe.json").read_text())

    endpoint, headers, record = sent[0]
    assert endpoint == ENDPOINT
    assert headers["Content-Encoding"] == "aes128gcm"
    assert headers["Authorization"].startswith("vapid t=")
    assert next(iter(saved["subscriptions"].values()))["endpoint"] == ENDPOINT
    message = json.loads(open_record(record, device, auth)[:-1])
    assert message["title"] == "Open Brew by Weight"
