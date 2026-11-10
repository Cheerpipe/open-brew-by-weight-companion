"""Beanconqueror machine endpoints: every served case of the firmware's vectors
(tests/fixtures/beanconqueror-v1.vectors.json, byte-identical) gives the same flow, JSON and
bytes from the archive as from the controller."""

import asyncio
import base64
import json
import math
import struct
from pathlib import Path
from typing import cast

import aiohttp
from aiohttp.test_utils import TestClient, TestServer
from test_hardening import dead_target
from test_relay import ID, SECRET, Idle

from companion import beanconqueror
from companion.service import Companion, web_app
from companion.store import Store

VECTORS = json.loads((Path(__file__).parent / "fixtures/beanconqueror-v1.vectors.json").read_text())
SERVED = [case for case in VECTORS["cases"] if case["served"]]


def test_cases_match_the_controller() -> None:
    assert len(SERVED) >= 6
    assert any(not case["served"] for case in VECTORS["cases"])
    for case in VECTORS["cases"]:
        row, shot = case["shot"], beanconqueror.shot_of(case["shot"])
        if not case["served"]:
            assert shot is None
            continue
        assert shot is not None
        rates = beanconqueror.flow(row, shot)
        for (tenths, hundredths), expected in zip(rates, case["flowGS"], strict=True):
            value = expected or 0
            assert tenths == math.floor(value * 10 + 0.5), case["name"]
            assert hundredths == min(32767, math.floor(value * 100 + 0.5)), case["name"]
        assert beanconqueror.gaggiuino_shot(row, shot) == case["gaggiuino"]["shot"]
        gaggimate = case["gaggimate"]
        assert beanconqueror.index_entry(shot) == base64.b64decode(gaggimate["indexEntry"])
        assert beanconqueror.slog(row, shot) == base64.b64decode(gaggimate["slog"])
        assert beanconqueror.notes(shot) == gaggimate["notes"]


def test_indexes_are_newest_first() -> None:
    shots = [beanconqueror.shot_of(case["shot"]) for case in SERVED]
    newest = sorted((shot for shot in shots if shot), key=lambda shot: shot.id, reverse=True)
    assert [shot.id for shot in newest] == VECTORS["newestFirstIds"]
    assert beanconqueror.index(newest, newest[0].id + 1) == base64.b64decode(
        VECTORS["gaggimate"]["index"]
    )
    assert beanconqueror.index(newest[:2], 0) == base64.b64decode(
        VECTORS["gaggimate"]["recentLimit2"]
    )


def test_the_host_names_the_companion_or_is_an_address() -> None:
    """The firmware's rule: an IP literal cannot be rebound; a name is the companion's own."""
    allowed = "192.168.1.20 10.0.0.7:8080 [fe80::1] kitchen-server.local Kitchen-Server"
    allowed += " kitchen-server.lan:8080 kitchen-server.home.arpa"
    refused = "evil.test kitchen-server.evil.test 192.168.1.20.evil.test kitchen-server2.local"
    for host in ["", *allowed.split()]:
        assert beanconqueror.host_allowed(host, "kitchen-server"), host
    for host in [".local", *refused.split()]:
        assert not beanconqueror.host_allowed(host, "kitchen-server"), host
    assert not beanconqueror.host_allowed(".local", "")


CURVE = ("wD", "wBreakBefore", "wHeld", "dropS", "endS", "atmS", "atmClearedS")


def archived(shot: dict[str, object]) -> dict[str, object]:
    """A vector row as the archive keeps it: the curve as the `wD` stream."""
    row = dict(shot)
    stream, t0, w0 = b"", 0, 0
    at, weights = cast("list[int]", row.pop("wAtMs")), cast("list[int]", row.pop("wCg"))
    for t, cg in zip(at, weights, strict=True):
        dt, dw = t - t0, cg - w0
        stream += bytes([dt]) if dt <= 254 else b"\xff" + struct.pack("<H", t)
        stream += struct.pack("b", dw) if -127 <= dw <= 127 else b"\x80" + struct.pack("<h", cg)
        t0, w0 = t, cg
    row["wD"] = base64.b64encode(stream).decode()
    return row


def test_archive_rows_decode_their_curve() -> None:
    """An archived row carries the curve as `wD`; it reads back to the same readings."""
    row = archived(SERVED[1]["shot"])
    shot = beanconqueror.shot_of(row)
    assert shot is not None
    assert beanconqueror.slog(row, shot) == base64.b64decode(SERVED[1]["gaggimate"]["slog"])


def test_endpoints_answer_from_the_archive_alone(tmp_path: Path) -> None:
    """With the controller unreachable, the archive answers both formats; Off, an unknown Host
    and a bad shot do not."""

    async def scenario() -> None:
        store = Store(tmp_path)
        store.write("identity", {"id": ID, "key": "11" * 32})
        store.save_pairing(SECRET, "Cafe Bar")
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", tmp_path, http, Idle)
            await companion.open_log()
            companion.set_controller(dead_target())  # Nothing may reach the controller.
            companion.device_id = "AA:BB:CC:DD:EE:FF"
            companion.address = ("kitchen-server.local", "192.168.1.20", 80)
            records: list[tuple[int, str, int, dict[str, object], dict[str, object]]] = []
            for case in VECTORS["cases"]:
                row = archived(case["shot"])
                curve = {key: row.pop(key) for key in CURVE if key in row}
                record_id = cast("int", row["id"])
                records.append((record_id, f"1:{record_id}", 1, row, curve))
            await companion.archive.store.put(companion.device_id, "shots", 1, records)
            client = TestClient(TestServer(web_app(companion)))
            await client.start_server()
            try:
                host = {"Host": "192.168.1.20"}
                assert (await client.get("/beanconqueror/api/status", headers=host)).status == 404
                companion.beanconqueror = "gaggimate"
                wrong = await client.get("/beanconqueror/api/status", headers={"Host": "evil.test"})
                assert wrong.status == 403
                recent = await client.get(
                    "/beanconqueror/api/history/recent.bin?limit=2", headers=host
                )
                assert await recent.read() == base64.b64decode(VECTORS["gaggimate"]["recentLimit2"])
                # A limit that is no number reads as GaggiMate's toInt(): 0, so the least, 1.
                for limit, entries in (("%C2%B2", 1), ("-5", 1), ("2abc", 2), ("999999999999", 6)):
                    odd = await client.get(
                        f"/beanconqueror/api/history/recent.bin?limit={limit}", headers=host
                    )
                    assert (odd.status, len(await odd.read())) == (200, 32 + 128 * entries), limit
                huge = await client.get(
                    "/beanconqueror/api/history/" + "9" * 30 + ".slog", headers=host
                )
                assert huge.status == 404
                newest = VECTORS["newestFirstIds"][0]
                case = next(c for c in SERVED if c["shot"]["id"] == newest)
                shot = await client.get(
                    f"/beanconqueror/api/history/{newest:06d}.slog", headers=host
                )
                assert await shot.read() == base64.b64decode(case["gaggimate"]["slog"])
                bad = next(c for c in VECTORS["cases"] if not c["served"])["shot"]["id"]
                missing = await client.get(f"/beanconqueror/api/history/{bad}.slog", headers=host)
                assert missing.status == 404
                companion.beanconqueror = "gaggiuino"
                latest = await client.get("/beanconqueror/api/shots/latest", headers=host)
                assert await latest.json() == [{"lastShotId": newest}]
                served = await client.get(f"/beanconqueror/api/shots/{newest}", headers=host)
                assert await served.json() == case["gaggiuino"]["shot"]
            finally:
                await client.close()
                await companion.logs.close()

    asyncio.run(scenario())


def test_the_format_survives_a_restart(tmp_path: Path) -> None:
    """The format cfg named is kept, so the endpoints answer before the controller is back."""

    async def scenario() -> None:
        async with aiohttp.ClientSession() as http:
            first = Companion("Kitchen server", tmp_path, http, Idle)
            await first.open_log()
            await first.logs.set_meta("beanconqueror", "gaggimate")
            await first.logs.close()
            again = Companion("Kitchen server", tmp_path, http, Idle)
            await again.open_log()
            assert again.beanconqueror == "gaggimate"
            await again.logs.close()

    asyncio.run(scenario())
