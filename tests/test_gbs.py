"""Mahlkönig Grind-by-Sync through the companion: the firmware's golden vectors
(tests/fixtures/mahlkonig-gbs-v1.vectors.json and the `gbs` cases of companion-link-v1, both
byte-identical), the E64 WS answered on port 80, an E65/E80 asked over pinned HTTPS against the
grinder simulator, attribution from recorded hold/record sequences, and older peers."""

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from grinder_simulator import PushGrinder
from test_hardening import dead_target
from test_relay import ID, SECRET, Idle

from companion import gbs, service
from companion.service import Companion
from companion.store import Store

if TYPE_CHECKING:
    import pytest

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / "tests/fixtures/mahlkonig-gbs-v1.vectors.json").read_text())
LINK = json.loads((ROOT / "tests/fixtures/companion-link-v1.vectors.json").read_text())["gbs"]
PUSH = V["push"]


def test_reporting_rules_match_the_controller() -> None:
    for case in V["report"]:
        result = gbs.report(case["row"])
        assert result.success == (case["result"] == "Success"), case["name"]
        assert (result.time_ms, result.mass_mg) == (case["durationMs"], case["massMg"]), case[
            "name"
        ]
        pull = gbs.Pull()
        assert pull.execute(1.0, 1000.0, 0)
        assert pull.settle(gbs.Shot(1, 1010.0, 1040.0, result), 2.0, 0)
        assert f"{pull.volume // 10}.{pull.volume % 10}" == case["volume"], case["name"]


def test_attribution_and_bodies_match_the_controller() -> None:
    for case in V["attribution"]:
        args = (case["priorS"], case["seenS"], case["startS"], case["endS"])
        assert gbs.attributable(*map(float, args)) is case["result"], case["name"]
    pull = V["pull"]
    assert gbs.machine_body(pull["machine"]["deviceId"]) == pull["machine"]["body"]
    for case in pull["mako"]:
        body = gbs.mako_body(
            case["state"],
            case["nowMs"] - case["armedAtMs"],
            case["timeMs"],
            case["volumeDg"],
            case["unixS"],
        )
        assert body == case["body"], case["name"]
    for case in pull["numbers"]:
        value = gbs.json_number(case["body"], case["key"])
        assert value == case["value"], case["name"]
        assert (value == 9 and case["key"] == "ID") is case["arms"], case["name"]
    assert gbs.uuid_v4(bytes.fromhex(PUSH["uuid"]["random"])) == PUSH["uuid"]["text"]
    identity = PUSH["identity"]
    for case in PUSH["requests"]:
        body = gbs.request_body(
            case["request"],
            device=identity["brewDeviceId"],
            application=identity["applicationId"],
            pairing=identity["pairingId"],
            uuid=case.get("grindUuid", ""),
            dose=case.get("doseType", 0),
            time=case.get("durationMs", 0),
            mass=case.get("massMg", 0),
            event=case.get("brewEventUuid", ""),
            success=case.get("result") == "Success",
        )
        assert body == case["body"], case["name"]
        assert gbs.PATHS[case["request"]] == case["path"]
    for case in PUSH["responses"]:
        reply = gbs.parse_reply(case["request"], case["http"], case["body"])
        assert reply.status == case["status"], case["name"]
        if "applicationId" in case:
            assert (reply.application, reply.code) == (case["applicationId"], case["pairingCode"])
        if "accepted" in case:
            assert reply.accepted is case["accepted"]
        if "pairingId" in case:
            assert reply.pairing == case["pairingId"]
        if "job" in case:
            job = case["job"]
            if job is None:
                assert reply.job is None, case["name"]
            else:
                assert reply.job == gbs.Job(
                    job["grindUuid"], job["doseType"], job["durationMs"], job["weightMg"]
                )


def test_cfg_and_frames_match_the_link_vectors() -> None:
    for case in LINK["cfg"]:
        setup = gbs.setup_of(json.loads(case["gbs"])) if case["gbs"] else None
        if not case["gbs"]:
            continue
        assert setup is not None
        assert setup.model == case["model"]
        if setup.push:
            assert (setup.host, setup.device, setup.pairing) == (
                case["host"],
                case["brewDeviceId"],
                case["pairingId"],
            )
            assert setup.pin.hex() == case["pin"]
    for frame in LINK["frames"]:
        parsed = json.loads(frame)
        assert set(parsed) == {"t", "own", "st", "ok"}
    names = {case["st"] for case in LINK["status"] if case["state"]}
    assert names == {"ok", "unreach", "unpaired", "identity", "seen", "lost"}
    # Unusable setups are nothing to do, never a guess.
    for value in (
        {"m": "e99"},
        {"m": "e65w"},
        {"m": "e65w", "h": "a b", "d": "x", "p": 1, "fp": "0" * 64},
    ):
        assert gbs.setup_of(value) is None
    assert gbs.setup_of(None) is None


class Clock:
    def __init__(self) -> None:
        self.mono, self.unix = 1000.0, 1_762_268_000.0

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.unix += seconds


def make(
    clock: Clock, frames: list[dict[str, object]], http: aiohttp.ClientSession | None = None
) -> gbs.Gbs:
    return gbs.Gbs(
        frames.append, http=http, clock=lambda: clock.mono, wall=lambda: clock.unix, random=bytes
    )


def row(
    record: int, start: float, duration: float = 28.4, grams: float | None = 36.2, **extra: object
) -> dict[str, object]:
    return {
        "id": record,
        "durationS": duration,
        "actualG": grams,
        "endedAtUnixSec": start + duration,
        "hasWallTime": True,
        "shotType": "auto",
        "stopDetail": "normal_target",
        "channeling": False,
        "actualWeightSource": "post_drip",
        "badReason": None,
        **extra,
    }


def test_e64ws_answers_on_port_80(tmp_path: Path) -> None:
    """The grinder polls the companion; a grind arms it, its shot reports, a poll clears it."""
    clock, frames = Clock(), cast("list[dict[str, object]]", [])
    grinder = make(clock, frames)
    grinder.device_id = "AA:BB:CC:DD:EE:FF"

    async def scenario() -> None:
        app = web.Application()

        async def route(request: web.Request) -> web.Response:
            return await grinder.route(request, "kitchen-server")

        app.router.add_route("*", "/api/v2/{tail:.*}", route)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            headers = {"Host": "192.168.1.20", "X-Real-IP": "192.168.1.87"}
            assert (await client.get("/api/v2/mako", headers=headers)).status == 404  # not set up
            grinder.configure({"m": "e64ws"})
            machine = await (await client.get("/api/v2/machine/", headers=headers)).text()
            assert machine == V["pull"]["machine"]["body"]
            assert await (await client.get("/api/v2/other", headers=headers)).text() == "{}"
            for refused in (
                {**headers, "Origin": "http://evil.test"},
                {**headers, "X-Real-IP": "8.8.8.8"},
                {"Host": "evil.test", "X-Real-IP": "192.168.1.87"},
            ):
                assert (await client.get("/api/v2/mako", headers=refused)).status == 403
            big = await client.post(
                "/api/v2/brewratio", data=b"{" + b" " * 2000 + b"}", headers=headers
            )
            assert big.status == 413

            async def poll() -> dict[str, object]:
                async with client.get("/api/v2/mako", headers=headers) as response:
                    return cast("dict[str, object]", await response.json())

            assert (await poll())["MA_STATUS"] == 1
            await client.post(
                "/api/v2/brewratio", json={"SYNC_BEVERAGE_WEIGHT": 36.5}, headers=headers
            )
            for _ in range(3):  # The grinder's retries.
                await client.post("/api/v2/scripts/execute", json={"ID": 9}, headers=headers)
            assert grinder.pull.recipe_dg == 365
            clock.advance(5)
            answer = await poll()
            assert (answer["MA_STATUS"], answer["MA_EXTRACTION_STATUS"]) == (3, 1)
            # The shot: a sync hold, then its record after the drip.
            grinder.on_hold(True)
            await grinder.step()
            assert grinder.pull.state == "brewing"
            clock.advance(40)
            grinder.on_hold(False)
            grinder.on_shots([row(7, clock.unix - 40)])
            answer = await poll()
            assert (answer["MA_STATUS"], answer["REAL_EXTRACTION_TIME_MS"]) == (4, 28400)
            assert answer["PU_SENS_FLOW_METER_VOLUME"] == 36.2
            clock.advance(6)
            await grinder.step()
            assert grinder.pull.state == "ready"
            assert grinder.delivered == 7
            assert frames[-1] == {"t": "gbs", "own": True, "st": "seen", "ok": 7}
            # Release, and the 180 s window.
            await client.post("/api/v2/scripts/execute", json={"ID": 9}, headers=headers)
            assert grinder.pull.release(clock.mono, grinder.polls)
            clock.advance(61)
            await grinder.step()
            await client.post("/api/v2/scripts/execute", json={"ID": 9}, headers=headers)
            clock.advance(180)
            await grinder.step()
            assert grinder.pull.state == "aborted"
            assert grinder.pull.time_ms == 180000
            # A shot started before the grind settles nothing.
            assert not grinder.pull.settle(
                gbs.Shot(8, clock.unix - 500, clock.unix - 470, gbs.report(row(8, 0))),
                clock.mono,
                0,
            )
        finally:
            await client.close()

    asyncio.run(scenario())
    assert tmp_path.exists()


def test_push_through_the_simulator() -> None:
    """Pinned HTTPS against the simulated E65W: jobs taken and delivered at the companion's 2 s,
    a job seen after its shot, Clear Pairing, a new certificate and an unreachable grinder."""
    clock, frames = Clock(), cast("list[dict[str, object]]", [])

    async def scenario() -> None:
        sim = PushGrinder(clock=lambda: clock.mono)
        await sim.start()
        sim.paired["3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b"] = 4821
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as http:
            grinder = make(clock, frames, http)
            setup = {
                "m": "e65w",
                "h": "127.0.0.1",
                "d": "3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b",
                "p": 4821,
                "fp": sim.fingerprint,
            }
            grinder.port = sim.port
            grinder.configure(setup)
            await grinder.step()
            assert sim.requests == ["brewJobs"]
            assert grinder.push.link == "ok"
            await grinder.step()
            assert sim.requests == ["brewJobs"]  # every 2 s, not more
            job = sim.grind()
            clock.advance(2)
            await grinder.step()  # seen
            await grinder.step()  # taken
            assert sim.requests[-1] == "brewAccept"
            assert job.taken is not None
            grinder.on_hold(True)
            clock.advance(35)
            grinder.on_hold(False)
            grinder.on_shots([row(11, clock.unix - 33)])
            await grinder.step()
            assert sim.results[-1]["result"] == "Success"
            assert sim.results[-1]["durationFinalMs"] == 28400
            assert grinder.delivered == 11
            await grinder.step()
            assert sim.requests[-1] == "brewJobs"  # one poll right after
            # A job ground just before the shot and first seen after it.
            clock.advance(30)
            grinder.on_hold(True)
            late = sim.grind()
            clock.advance(30)
            grinder.on_hold(False)
            grinder.on_shots([row(12, clock.unix - 29)])
            assert grinder.push.poll_now
            await grinder.step()  # the poll that sees the job claims the shot
            await grinder.step()  # taken
            await grinder.step()  # delivered
            assert sim.results[-1]["grindUuid"] == late.uuid
            assert grinder.delivered == 12
            # Clear Pairing: 403s for a minute mean unpaired.
            sim.clear_pairing()
            for _ in range(32):
                clock.advance(2)
                await grinder.step()
            assert grinder.push.link == "unpaired"
            assert frames[-1]["st"] == "unpaired"
            # Another certificate: identity, and nothing more is sent.
            sim.paired["3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b"] = 4821
            grinder.configure({**setup, "fp": "0" * 64})
            clock.advance(2)
            await grinder.step()
            assert grinder.push.link == "identity"
            count = len(sim.requests)
            clock.advance(10)
            await grinder.step()
            assert len(sim.requests) == count
            # An unreachable grinder backs off to 60 s.
            await sim.stop()
            grinder.configure(setup)
            grinder.configure({**setup, "h": "127.0.0.2"})
            await grinder.step()
            clock.advance(2)
            await grinder.step()
            assert grinder.push.link == "unreach"
            assert grinder.push.due_at == clock.mono + 60
            # The link dropping hands the grinder back to the controller.
            grinder.link_down()
            assert not grinder.own

    asyncio.run(scenario())


def test_attribution_without_a_clock() -> None:
    """A controller without a clock: the sync hold that began after the grind is the shot."""
    clock, frames = Clock(), cast("list[dict[str, object]]", [])
    grinder = make(clock, frames)
    grinder.configure({"m": "e64ws"})
    assert grinder.pull.execute(clock.mono, clock.unix, 0)
    clock.advance(20)
    grinder.on_hold(True)
    clock.advance(40)
    grinder.on_hold(False)
    grinder.on_shots([row(5, 0, hasWallTime=False, endedAtUnixSec=0)])
    assert grinder.pull.state == "finishing"
    assert grinder.pull.time_ms == 28400
    # A hold that began before the grind is no shot of it.
    grinder.pull = gbs.Pull()
    grinder.on_hold(True)
    clock.advance(5)
    assert grinder.pull.execute(clock.mono, clock.unix, 0)
    grinder.on_hold(False)
    grinder.on_shots([row(6, 0, hasWallTime=False, endedAtUnixSec=0)])
    assert grinder.pull.state == "armed"


def test_older_peers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An older controller sends no cfg.gbs: the companion does nothing for a grinder and says
    nothing. A newer one's cfg.gbs reaches the service, its frame goes as a sync request."""
    monkeypatch.setattr(service, "log", lambda _: None)

    async def scenario() -> None:
        store = Store(tmp_path)
        store.write("identity", {"id": ID, "key": "11" * 32})
        store.save_pairing(SECRET, "Cafe Bar")
        async with aiohttp.ClientSession() as http:
            companion = Companion("Kitchen server", tmp_path, http, Idle)
            await companion.open_log()
            companion.set_controller(dead_target())
            companion.outbox = asyncio.Queue()
            companion.sync_hold = False
            await companion._on_frame(
                {"t": "cfg", "ui": True, "log": False, "archive": True, "bc": "off"}
            )
            assert not companion.gbs.own
            outbox = companion.outbox
            assert all(outbox.get_nowait().get("t") != "gbs" for _ in range(outbox.qsize()))
            assert {companion.ping_route} == {"direct"}
            await companion._on_frame(
                {
                    "t": "cfg",
                    "ui": True,
                    "log": False,
                    "archive": True,
                    "bc": "off",
                    "gbs": {"m": "e64ws"},
                }
            )
            assert companion.gbs.facts()["own"] is True
            assert {companion.ping_route} == {"companion"}
            sent = [companion.outbox.get_nowait() for _ in range(companion.outbox.qsize())]
            assert {"t": "gbs", "own": True, "st": "lost", "ok": 0} in sent
            assert (await companion.status())["gbs"] == {
                "model": "e64ws",
                "pull": True,
                "own": True,
                "st": "lost",
                "polls": 0,
                "delivered": 0,
            }
            # During a sync hold the frame waits for its end.
            companion.sync_hold = True
            await companion._on_frame(
                {"t": "cfg", "ui": True, "log": False, "archive": True, "bc": "off"}
            )
            assert "gbs" in companion.sync_due
            await companion.logs.close()

    asyncio.run(scenario())
