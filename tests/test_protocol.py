"""Link crypto against the shared firmware vectors, the frame codec and the dashboard filter.

Needs aiohttp and cryptography, so it runs inside the image (see the README).
"""

import copy
import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

from companion import crypto, dashboard
from companion.link import FrameCodec, LinkClosedError

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / "tests/fixtures/companion-link-v1.vectors.json").read_text())
D = json.loads((ROOT / "tests/fixtures/lamarzocco-dashboard.json").read_text())


def raises(call: Callable[[], object], code: str = "PROTOCOL") -> None:
    with pytest.raises(LinkClosedError) as closed:
        call()
    assert closed.value.code == code, closed.value


def test_shared_vectors() -> None:
    """Crypto: every value of the shared vectors."""
    companion_private = crypto.load_key(bytes.fromhex(V["companionPrivate"]))
    controller_private = crypto.load_key(bytes.fromhex(V["controllerPrivate"]))
    companion_key, controller_key = (
        crypto.unb64(V["companionKey"], 65),
        crypto.unb64(V["controllerKey"], 65),
    )
    assert crypto.public_point(companion_private) == companion_key
    assert crypto.public_point(controller_private) == controller_key
    assert crypto.scalar(companion_private).hex() == V["companionPrivate"]
    assert crypto.sas(companion_key, controller_key) == V["sas"]
    assert crypto.b64(crypto.commitment(companion_key)) == V["commitment"]
    assert (
        companion_private.exchange(ec.ECDH(), crypto.load_point(controller_key)).hex() == V["ecdhX"]
    )
    secret = crypto.pairing_secret(companion_private, companion_key, controller_key)
    assert secret.hex() == V["pairingSecret"]
    assert crypto.pairing_secret(controller_private, companion_key, companion_key) != secret
    nc, ns = crypto.unb64(V["companionNonce"], 16), crypto.unb64(V["controllerNonce"], 16)
    session = crypto.session_key(secret, nc, ns)
    assert session.hex() == V["sessionKey"]
    assert crypto.b64(crypto.mac(secret, b"C", nc, ns)) == V["proof"]
    assert crypto.b64(crypto.mac(secret, b"F", nc, ns)) == V["ready"]
    assert crypto.b64(crypto.mac(secret, b"E", nc)) == V["erase"]
    assert crypto.credentials_key(secret).hex() == V["credentialsKey"]
    bundle = V["credentials"]
    plain = crypto.decrypt_credentials(
        secret, bundle["gen"], crypto.unb64(bundle["iv"], 12), crypto.unb64(bundle["ct"])
    )
    assert plain.decode() == bundle["plaintext"]
    # A wrong generation or secret must not decrypt.
    for generation, key in ((bundle["gen"] + 1, secret), (bundle["gen"], bytes(32))):
        with pytest.raises(InvalidTag):
            crypto.decrypt_credentials(
                key, generation, crypto.unb64(bundle["iv"]), crypto.unb64(bundle["ct"])
            )
    for bad in ("not base64!", None, "AAAA="):
        with pytest.raises(ValueError, match="invalid base64 field"):
            crypto.unb64(bad, 16)
    # Compressed or short points are rejected.
    with pytest.raises(ValueError, match="not an uncompressed P-256 point"):
        crypto.load_point(companion_key[:33])


def test_frame_codec() -> None:
    """The frame codec on the shared vectors' session key."""
    session = bytes.fromhex(V["sessionKey"])
    companion = FrameCodec(session)
    controller = FrameCodec(session, send=b"f", receive=b"c")
    assert companion.encode({"t": "ping", "up": True}) == V["companionFrame"]
    assert (
        controller.encode({"t": "cfg", "lm": True, "conn": "ws", "observe": True})
        == V["controllerFrame"]
    )
    assert (
        FrameCodec(session, send=b"f").encode({"t": "dev", "name": "openbrewbyweight"})
        == V["deviceFrame"]
    )
    assert controller.decode(V["companionFrame"]) == {"q": 1, "t": "ping", "up": True}
    assert companion.decode(V["controllerFrame"])["conn"] == "ws"
    second = controller.encode({"t": "route", "to": "companion"})
    assert companion.decode(second) == {"q": 2, "t": "route", "to": "companion"}
    raises(lambda: companion.decode(second))  # A replay repeats q.
    third, fourth = (
        controller.encode({"t": "hold", "on": True}),
        controller.encode({"t": "hold", "on": False}),
    )
    raises(lambda: FrameCodec(session).decode(fourth))  # q must start at 1...
    fresh = FrameCodec(session)
    fresh.decode(V["controllerFrame"])
    raises(lambda: fresh.decode(fourth))  # ...and grow by exactly one.
    tampered = third.replace('"on":true', '"on":false')
    raises(lambda: FrameCodec(session).decode(tampered))
    raises(lambda: FrameCodec(session).decode(V["companionFrame"]))  # Direction is part of the MAC.
    raises(lambda: FrameCodec(bytes(32)).decode(V["controllerFrame"]))
    raises(lambda: FrameCodec(session).decode("no dot at all"))
    other = FrameCodec(session, send=b"f", receive=b"c")
    # An unknown t is authentic: the codec passes it on, and the service ignores and counts it.
    assert FrameCodec(session).decode(other.encode({"t": "webhook"})) == {"q": 1, "t": "webhook"}
    boolean = FrameCodec(session, send=b"f")
    body = '{"q":true,"t":"cfg"}'
    raises(lambda: FrameCodec(session).decode(f"{boolean._tag(b'f', body)}.{body}"))
    big = FrameCodec(session, send=b"f")
    raises(lambda: FrameCodec(session).decode(big._tag(b"f", "{}") + "." + " " * 4096))
    sender = FrameCodec(session)
    # Frames over 4,096 bytes are never sent.
    with pytest.raises(ValueError, match="exceeds 4096"):
        sender.encode({"t": "st", "d": "x" * 4096})
    receiver = FrameCodec(session, send=b"f", receive=b"c")
    assert receiver.decode(sender.encode({"t": "ping", "up": False}))["q"] == 1, (
        "a dropped frame uses no sequence number"
    )


def test_dashboard_filter() -> None:
    """The dashboard filter: only the consumed fields, per event."""
    read = dashboard.reduce(D["read"], push=False)
    assert read == {
        "connected": True,
        "widgets": [
            {"code": "CMMachineStatus", "output": {"mode": "BrewingMode"}},
            {
                "code": "CMCoffeeBoiler",
                "output": {
                    "status": "HeatingUp",
                    "targetTemperature": 93.0,
                    "readyStartTime": 1760000460000,
                },
            },
            {
                "code": "CMSteamBoilerLevel",
                "output": {
                    "status": "HeatingUp",
                    "targetLevel": "Level3",
                    "readyStartTime": 1760000820500,
                },
            },
        ],
    }, read
    as_push = dashboard.reduce(D["read"], push=True)
    assert as_push is not None
    assert as_push["widgets"][-1] == {"code": "CMBackFlush", "output": {"status": "Off"}}, (
        "CMBackFlush only in pushes"
    )
    assert len(json.dumps(read)) < 400 < len(json.dumps(D["read"]))
    pushes = D["pushes"]
    assert dashboard.reduce(pushes["standby"], push=True) == {
        "connected": True,
        "widgets": [
            {"code": "CMMachineStatus", "output": {"mode": "StandBy"}},
            {
                "code": "CMCoffeeBoiler",
                "output": {"status": "StandBy", "targetTemperature": 93.0, "readyStartTime": None},
            },
        ],
    }
    assert dashboard.reduce(pushes["standby"], push=True) == dashboard.reduce(
        copy.deepcopy(pushes["standby"]), push=True
    ), "the same event is forwarded again: filter, never diff"
    assert dashboard.reduce(pushes["commandsOnly"], push=True) is None, (
        "an event carrying no consumed field is dropped"
    )
    backflush = dashboard.reduce(pushes["backflush"], push=True)
    assert backflush is not None
    assert backflush["widgets"] == [{"code": "CMBackFlush", "output": {"status": "Requested"}}]
    assert dashboard.reduce(pushes["backflush"], push=False) == {"connected": True}
    assert dashboard.reduce(pushes["removed"], push=True) == {
        "removedWidgets": ["CMBackFlush", "CMSteamBoilerLevel"]
    }
    assert dashboard.reduce(pushes["removed"], push=False) == {
        "removedWidgets": ["CMSteamBoilerLevel"]
    }
    assert dashboard.reduce(pushes["offline"], push=True) == {"connected": False}
    assert dashboard.reduce({}, push=True) is None
    # Values pass through untouched: the controller's decoder keeps its own strictness.
    odd = {
        "widgets": [
            {"code": "CMCoffeeBoiler", "output": {"targetTemperature": "93"}},
            {"code": "CMMachineStatus", "output": "broken"},
            "note",
            {"code": 7},
            {"code": "CMSteamBoilerLevel", "output": {"enabled": True}},
        ],
        "removedWidgets": "x",
    }
    assert dashboard.reduce(odd, push=True) == {
        "widgets": [{"code": "CMCoffeeBoiler", "output": {"targetTemperature": "93"}}]
    }
    assert dashboard.parse('{"widgets":[],"serialNumber":"a","serialNumber":"b"}') == {
        "widgets": [],
        "serialNumber": "b",
    }
    # Each must be rejected like the controller rejects it.
    for repeated, why in (
        ('{"connected":true,"connected":false}', "a consumed key is repeated"),
        (
            '{"widgets":[{"code":"CMMachineStatus","output":{"mode":"a","mode":"b"}}]}',
            "a consumed key is repeated",
        ),
        ("[]", "not a JSON object"),
        ("nope", "Expecting value"),
    ):
        with pytest.raises(ValueError, match=why):
            dashboard.parse(repeated)
    assert dashboard.confirms(pushes["temperature"], "temp", 935)
    assert not dashboard.confirms(pushes["temperature"], "temp", 930)
    assert dashboard.confirms(pushes["standby"], "standby", None)
    assert not dashboard.confirms(pushes["standby"], "on", None)
    assert not dashboard.confirms(pushes["commandsOnly"], "on", None)
