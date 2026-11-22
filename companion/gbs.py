"""Mahlkönig Grind-by-Sync through the companion (the firmware's docs/MAHLKONIG_GBS.md).

The controller sends its grinder setup in `cfg.gbs` and pairs the grinder itself; the companion
then carries the grinder so the controller does no work per grinder poll: it answers an E64 WS on
its own port 80 (pull) and asks an E65W, E65T, E80W or E80T every 2 s over HTTPS, pinned to the
certificate the controller trusted (push). Shots come from the archive the controller syncs right
after each shot; which grind a shot belongs to and what is reported follow the firmware's rules,
pinned by tests/fixtures/mahlkonig-gbs-v1.vectors.json (byte-identical to the firmware's). It
tells the controller only what the controller uses: `{"t":"gbs","own","st","ok"}`, on change.

Grinder input is a signal only: nothing here reaches the controller's machine.
"""

import ipaddress
import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

import aiohttp
from aiohttp import web

from . import beanconqueror, clip, log

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

MODELS = ("e64ws", "e65w", "e65t", "e80w", "e80t")
PULL_WINDOW_S, RESULT_HOLD_S, RESULT_CAP_S, SEEN_S = 180.0, 6.0, 60.0, 30.0
POLL_S = 2.0  # Mahlkönig's own cadence; the controller alone asks every 15-25 s.
BACKOFF_S = (60.0, 120.0)  # After the first retry, which waits one cadence.
PAIR_UNPAIRED_S, LATE_JOB_S, JOB_WINDOW_S = 60.0, 60.0, 180.0
RESULT_RETRY_S, CANCEL_RETRY_S, RETRY_S, TIMEOUT_S = 120.0, 20.0, 5.0, 8.0
PORT = 30001
SKEW_S = 3.0  # The controller's and the companion's wall clocks may differ this much.
BODY_MAX = 1024
CUTS = frozenset(
    {
        "normal_target",
        "extended_max_weight",
        "extended_min_time",
        "slow_max_time",
        "slow_min_weight",
        "wall_limit",
    }
)
_UUID = re.compile(r"[A-Za-z0-9-]{1,40}")
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,46}")
_NAME = "Open Brew by Weight"
type Request = Literal["pair_apply", "pair_status", "brew_jobs", "brew_accept", "brew_done"]
PATHS: dict[Request, str] = {
    "pair_apply": "/grinderApi/pairingApplication",
    "pair_status": "/grinderApi/pairingStatus",
    "brew_jobs": "/grinderApi/brewJobs",
    "brew_accept": "/grinderApi/brewAccept",
    "brew_done": "/grinderApi/brewDone",
}


def _half_up(value: float) -> int:
    return math.floor(value + 0.5)


def _number(row: Mapping[str, object], key: str) -> float | None:
    value = row.get(key)
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


# --- The shared rules ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Report:
    success: bool
    time_ms: int  # pump time, drip excluded
    mass_mg: int  # yield after the drip; 0 for a cancelled shot


def report(row: Mapping[str, object]) -> Report:
    """Success only for a shot cut by weight or at the max shot time, with the scale throughout
    and its yield settled after the drip; anything else is cancelled (the firmware's gbsReport)."""
    time_ms = _half_up((_number(row, "durationS") or 0) * 10) * 100
    grams = _number(row, "actualG")
    success = (
        row.get("stopDetail") in CUTS
        and row.get("shotType") != "manual"
        and row.get("channeling") is not True
        and not row.get("badReason")
        and row.get("actualWeightSource") == "post_drip"
        and grams is not None
        and grams > 0
    )
    return Report(success, time_ms, _half_up(grams * 100) * 10 if success and grams else 0)


def attributable(prior: float, seen: float, start: float, end: float) -> bool:
    """A shot belongs to a grind seen at `seen` (the poll before it at `prior`) when it started
    after that poll and either after the grind or, for a job seen late, ended under 60 s before."""
    return start > prior and (start >= seen or seen - end < LATE_JOB_S)


def volume_dg(mass_mg: int) -> int:
    return (mass_mg + 50) // 100


def mako_body(state: str, elapsed_ms: int, time_ms: int, volume: int, unix_s: int) -> str:
    """GET /api/v2/mako, byte for byte as the controller answers it."""
    status, extraction, shown, dg = 1, 0, 0, 0
    if state in {"armed", "brewing"}:
        status, extraction, shown = 3, 1, elapsed_ms
    elif state == "finishing":
        status, shown, dg = 4, time_ms, volume
    elif state == "aborted":
        status, extraction, shown = 4, 2, time_ms
    return (
        f'{{"MA_STATUS":{status},"MA_EXTRACTION_STATUS":{extraction},'
        f'"REAL_EXTRACTION_TIME_MS":{shown},"PU_SENS_FLOW_METER_VOLUME":{dg // 10}.{dg % 10},'
        f'"BG_SET_TEMP":93.0,"BG_SENS_TEMP":93.0,"TANK_LEVEL":1,"script":0,"TIMESTAMP":{unix_s}}}'
    )


def machine_body(device_id: str) -> str:
    serial = ("OBBW" + device_id.replace(":", ""))[:19]
    return (
        f'{{"MA_TYPE":1,"MA_SUBTYPE":1,"MA_SN":"{serial}","FW_VERSION_MAJOR":1,'
        '"FW_VERSION_MINOR":0,"ESP_FW_MAJOR":1,"ESP_FW_MINOR":0,"MA_MAX_AMPERE":16,'
        '"MA_FIX_WATER_SUPPLY":0,"BLE":0,"MA_DELAY":0}'
    )


def json_number(body: str, key: str) -> float | None:
    """One number member of the grinder's flat JSON object, the first of duplicates."""

    def first(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for name, value in pairs:
            out.setdefault(name, value)
        return out

    try:
        parsed = json.loads(body, object_pairs_hook=first, parse_constant=lambda _: None)
    except ValueError:
        return None
    value = parsed.get(key) if isinstance(parsed, dict) else None
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        return None
    return float(value)


def uuid_valid(text: object) -> bool:
    return isinstance(text, str) and _UUID.fullmatch(text) is not None


def host_valid(text: object) -> bool:
    return isinstance(text, str) and _HOST.fullmatch(text) is not None


def uuid_v4(random: bytes) -> str:
    b = bytearray(random[:16])
    b[6], b[8] = (b[6] & 0x0F) | 0x40, (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def request_body(request: Request, **v: object) -> str:
    """The wire bodies, byte for byte as the controller sends them."""
    if request == "pair_apply":
        return (
            f'{{"version":1,"name":"{_NAME}","model":"{_NAME}","manufacturer":"{_NAME}",'
            f'"brewDeviceId":"{v["device"]}","numOfGroupHeads":1,"progressSupported":false}}'
        )
    if request == "pair_status":
        return f'{{"version":1,"applicationId":{v["application"]}}}'
    if request == "brew_jobs":
        return f'{{"version":1,"pairingId":{v["pairing"]}}}'
    if request == "brew_accept":
        return (
            f'{{"version":1,"pairingId":{v["pairing"]},"grindUuid":"{v["uuid"]}",'
            f'"groupHeadId":1,"doseType":{v["dose"]}}}'
        )
    return (
        f'{{"version":1,"pairingId":{v["pairing"]},"grindUuid":"{v["uuid"]}",'
        f'"durationFinalMs":{v["time"]},"massFinalMg":{v["mass"]},"brewEventUuid":"{v["event"]}",'
        f'"result":"{"Success" if v["success"] else "Canceled"}"}}'
    )


@dataclass(frozen=True)
class Job:
    uuid: str
    dose: int = 0
    duration_ms: int = 0
    weight_mg: int = 0


@dataclass(frozen=True)
class Reply:
    status: str  # ok, already_paired, app_not_found, job_not_existing, refused, failed, malformed
    application: int = 0
    code: int = 0
    pairing: int = 0
    accepted: bool = False
    job: Job | None = None


def _uint(source: Mapping[str, object], key: str) -> int | None:
    value = _number(source, key)
    return _half_up(value) if value is not None and 0 <= value <= 4294967295 else None


_ERRORS = {
    "ClientErrorDevAlreadyPaired": "already_paired",
    "ClientErrorPairingAppIdNotFound": "app_not_found",
    "ClientErrorOngoingJobNotExisting": "job_not_existing",
}


def parse_reply(request: Request, http: int, body: str) -> Reply:
    """A grinder's answer as the controller reads it (gbsParseResponse)."""
    if http == 403:
        return Reply("refused")
    if not 200 <= http <= 299:
        return Reply("failed")
    try:
        root = json.loads(body)
    except ValueError:
        return Reply("malformed")
    if not isinstance(root, dict):
        return Reply("malformed")
    status = root.get("status")
    if isinstance(status, str) and status in _ERRORS:
        return Reply(_ERRORS[status])
    if isinstance(status, str) and status != "Ok":
        return Reply("failed")
    if request == "pair_apply":
        application, code = _uint(root, "applicationId"), _uint(root, "pairingCode")
        if application is None or code is None:
            return Reply("malformed")
        return Reply("ok", application=application, code=code)
    if request == "pair_status":
        accepted, pairing = root.get("accepted"), _uint(root, "pairingId")
        if not isinstance(accepted, bool) or (accepted and pairing is None):
            return Reply("malformed")
        return Reply("ok", accepted=accepted, pairing=pairing or 0)
    if request != "brew_jobs":
        return Reply("ok")
    jobs = root.get("brewJobs")
    if not isinstance(jobs, list):
        return Reply("malformed")
    for job in jobs:
        if not isinstance(job, dict) or not uuid_valid(job.get("grindUuid")):
            continue
        if "groupHeadId" in job and _uint(job, "groupHeadId") != 1:
            continue  # Grouphead 1 only.
        return Reply(
            "ok",
            job=Job(
                str(job["grindUuid"]),
                _uint(job, "doseTypeExpected") or 0,
                _uint(job, "durationExpectedMs") or 0,
                _uint(job, "brewWeightExpectedMg") or 0,
            ),
        )
    return Reply("ok")


@dataclass(frozen=True)
class Setup:
    """`cfg.gbs` as the controller sent it."""

    model: str
    host: str = ""
    device: str = ""
    pairing: int = 0
    pin: bytes = b""

    @property
    def push(self) -> bool:
        return self.model != "e64ws"


def setup_of(value: object) -> Setup | None:
    """`cfg.gbs`, or None when absent or unusable (the companion then does nothing for GbS)."""
    if not isinstance(value, dict) or value.get("m") not in MODELS:
        return None
    model = str(value["m"])
    if model == "e64ws":
        return Setup(model)
    host, device, pairing, pin = value.get("h"), value.get("d"), value.get("p"), value.get("fp")
    if (
        not host_valid(host)
        or not uuid_valid(device)
        or type(pairing) is not int
        or not isinstance(pin, str)
        or re.fullmatch(r"[0-9a-f]{64}", pin) is None
    ):
        return None
    return Setup(model, str(host), str(device), pairing, bytes.fromhex(pin))


# --- A shot as both modes need it ---------------------------------------------------------------


@dataclass(frozen=True)
class Shot:
    id: int
    start: float  # wall clock
    end: float
    result: Report


# --- The E64 WS --------------------------------------------------------------------------------


@dataclass
class Pull:
    """The E64 WS state machine (the firmware's GbsPull), on the companion's clocks."""

    state: str = "ready"
    armed_at: float = 0.0  # monotonic
    armed_wall: float = 0.0
    entered_at: float = 0.0
    polls_at: int = 0
    idle_since: float = 0.0
    time_ms: int = 0
    volume: int = 0
    recipe_dg: int = 0
    shot: int = 0  # the record reported

    def enter(self, state: str, now: float, polls: int) -> None:
        self.state, self.entered_at, self.polls_at = state, now, polls

    def execute(self, now: float, wall: float, polls: int) -> bool:
        if self.state in {"armed", "brewing"}:
            return False
        self.armed_at, self.armed_wall, self.idle_since = now, wall, now
        self.time_ms = self.volume = self.shot = 0
        self.enter("armed", now, polls)
        return True

    def abort(self, time_ms: int, now: float, polls: int) -> None:
        self.time_ms, self.volume = time_ms, 0
        self.enter("aborted", now, polls)

    def release(self, now: float, polls: int) -> bool:
        if self.state not in {"armed", "brewing"}:
            return False
        self.abort(int((now - self.armed_at) * 1000), now, polls)
        return True

    def settle(self, shot: Shot, now: float, polls: int) -> bool:
        armed = self.armed_wall - SKEW_S
        if self.state not in {"armed", "brewing"} or not attributable(
            armed, armed, shot.start, shot.start
        ):
            return False
        self.shot = shot.id
        volume = volume_dg(shot.result.mass_mg) if shot.result.mass_mg else self.recipe_dg
        if not shot.result.success or not volume:
            self.abort(shot.result.time_ms, now, polls)
        else:
            self.time_ms, self.volume = shot.result.time_ms, volume
            self.enter("finishing", now, polls)
        return True

    def tick(self, now: float, polls: int, busy: bool) -> bool:
        before = self.state
        if self.state == "armed":
            if busy:
                self.idle_since = now
                self.enter("brewing", now, polls)
            elif now - self.armed_at >= PULL_WINDOW_S:
                self.abort(int(PULL_WINDOW_S * 1000), now, polls)
        elif self.state == "brewing":
            if busy:
                self.idle_since = now
            elif now - self.idle_since >= RESULT_CAP_S:
                self.enter("armed", now, polls)
        elif self.state in {"finishing", "aborted"} and (
            (now - self.entered_at >= RESULT_HOLD_S and polls != self.polls_at)
            or now - self.entered_at >= RESULT_CAP_S
        ):
            self.enter("ready", now, polls)
        return self.state != before


# --- The E65/E80 ---------------------------------------------------------------------------------


@dataclass
class Result:
    uuid: str
    dose: int
    report: Report
    event: str
    since: float
    retry_at: float
    retake: bool
    shot: int


@dataclass
class Push:
    """The direct client's decisions (the firmware's GbsPush), at the companion's 2 s."""

    link: str = "unknown"  # ok, unreach, unpaired, identity
    failures: int = 0
    due_at: float = 0.0
    refused_since: float | None = None
    last_poll: float | None = None
    job: Job | None = None
    job_taken: bool = False
    job_seen: float = 0.0  # wall clock
    job_prior: float = 0.0
    result: Result | None = None
    poll_now: bool = False

    def next(self, now: float) -> Request | None:
        if self.link in {"identity", "unpaired"}:
            return None
        if self.result is not None and now >= self.result.retry_at:
            return "brew_accept" if self.result.retake else "brew_done"
        if self.job is not None and not self.job_taken:
            return "brew_accept"
        return "brew_jobs" if self.poll_now or now >= self.due_at else None

    def claim(self, shot: Shot, random: bytes, now: float) -> bool:
        if self.job is None or not attributable(
            self.job_prior - SKEW_S, self.job_seen - SKEW_S, shot.start, shot.end
        ):
            return False
        self.result = Result(
            self.job.uuid,
            self.job.dose,
            shot.result,
            uuid_v4(random),
            now,
            now,
            not self.job_taken,
            shot.id,
        )
        self.job, self.job_taken = None, False
        return True

    def expire(self, wall: float, random: bytes, now: float) -> bool:
        if self.job is None or self.result is not None or wall - self.job_seen < JOB_WINDOW_S:
            return False
        self.job_prior = self.job_seen
        return self.claim(
            Shot(0, self.job_seen + 0.001, self.job_seen + 0.001, Report(False, 0, 0)), random, now
        )

    def reply(self, request: Request, answer: Reply | None, now: float, wall: float) -> None:
        """`answer` None: no answer (a connect error, a timeout, a TLS failure)."""
        if answer is None or answer.status in {"failed", "malformed"}:
            self.failures += 1
            self.link = "unreach"
            self.due_at = now + (
                POLL_S if self.failures <= 1 else BACKOFF_S[min(self.failures, 3) - 2]
            )
            if self.result is not None:
                limit = RESULT_RETRY_S if self.result.report.success else CANCEL_RETRY_S
                self.result.retry_at = now + RETRY_S
                if now - self.result.since >= limit:
                    self.result = None
            return
        self.failures = 0
        if request != "brew_jobs" or answer.status != "refused":
            self.refused_since = None
            if self.link != "unpaired":
                self.link = "ok"
        if request == "brew_jobs":
            self.poll_now, self.due_at = False, now + POLL_S
            if answer.status == "refused":
                if self.refused_since is None:
                    self.refused_since = now
                elif now - self.refused_since >= PAIR_UNPAIRED_S:
                    self.link = "unpaired"
                return
            job = answer.job
            if (
                job
                and (self.job is None or self.job.uuid != job.uuid)
                and not (self.result is not None and self.result.uuid == job.uuid)
            ):
                self.job, self.job_taken, self.job_seen = job, False, wall
                self.job_prior = self.last_poll if self.last_poll is not None else wall - POLL_S
            elif job and self.job is not None:
                self.job_taken = False  # Handed out again: take it again.
            self.last_poll = wall
        elif request == "brew_accept":
            if self.result is not None and self.result.retake:
                self.result.retake = False
            else:
                self.job_taken = answer.status == "ok"
                if answer.status != "ok":
                    self.job = None
        elif request == "brew_done":
            if answer.status == "job_not_existing" and self.result is not None:
                self.result.retake = True
            else:
                self.result, self.poll_now = None, True


# --- The service ------------------------------------------------------------------------------


@dataclass
class Gbs:
    """The companion's side: configured by cfg.gbs, fed by holds and archived shots."""

    post: Callable[[dict[str, object]], object]  # a sync frame to the controller
    on_own: Callable[[], object] = lambda: None  # its ping cadence follows `own`
    http: aiohttp.ClientSession | None = None
    clock: Callable[[], float] = time.monotonic
    wall: Callable[[], float] = time.time
    random: Callable[[int], bytes] = os.urandom
    port: int = PORT  # the grinder's; a test's simulator listens elsewhere
    setup: Setup | None = None
    device_id: str = ""
    pull: Pull = field(default_factory=Pull)
    push: Push = field(default_factory=Push)
    polls: int = 0
    seen_at: float | None = None
    hold: bool = False
    hold_start: float = 0.0  # wall clock of the last sync hold's start and end
    hold_end: float = 0.0
    newest: int = 0
    pending: Shot | None = None  # the newest shot no push job has claimed yet
    delivered: int = 0
    reported: tuple[bool, str, int] | None = None

    @property
    def own(self) -> bool:
        return self.setup is not None

    def configure(self, value: object) -> None:
        setup = setup_of(value)
        if setup == self.setup:
            return
        # Another grinder, address, pairing or certificate starts over.
        self.pull, self.push = Pull(), Push()
        self.setup = setup
        log(f"Mahlkönig: {setup.model if setup else 'off'}")
        self.report()

    def state(self) -> str:
        if self.setup is None:
            return "unknown"
        if not self.setup.push:
            seen = self.seen_at is not None and self.clock() - self.seen_at < SEEN_S
            return "seen" if seen else "lost"
        return self.push.link if self.push.link != "unknown" else "ok"

    def report(self) -> None:
        """The controller's `gbs` frame, on change; post waits for the end of a sync hold."""
        now = (self.own, self.state(), self.delivered)
        if now != self.reported:
            if self.reported is None or self.reported[0] != now[0]:
                self.on_own()
            self.reported = now
            self.post({"t": "gbs", "own": now[0], "st": now[1], "ok": now[2]})

    def session(self) -> None:
        """A new link session hears the state again."""
        self.reported = None

    def link_down(self) -> None:
        """Without the link the controller asks an E65/E80 itself: stop, so it has one owner. An
        E64 WS keeps its answers (it was pointed here); its shots wait for the link."""
        if self.setup is not None and self.setup.push:
            self.configure(None)
        self.reported = None

    def on_hold(self, sync: bool) -> None:
        if sync and not self.hold:
            self.hold_start = self.wall()
        if not sync and self.hold:
            self.hold_end = self.wall()
        self.hold = sync

    def shot_of(self, row: Mapping[str, object]) -> Shot | None:
        record = _number(row, "id")
        if record is None:
            return None
        unix, duration = _number(row, "endedAtUnixSec"), _number(row, "durationS") or 0
        if row.get("hasWallTime") is True and unix:
            return Shot(int(record), unix - duration, unix, report(row))
        # No clock on the controller: the sync hold the shot was.
        return Shot(int(record), self.hold_start, self.hold_end or self.wall(), report(row))

    def on_shots(self, rows: Iterable[Mapping[str, object]]) -> None:
        """Newly archived shot rows: the newest new one may settle the grind in hand."""
        shots = [shot for row in rows if (shot := self.shot_of(row)) and shot.id > self.newest]
        if not shots or self.setup is None:
            return
        shot = max(shots, key=lambda s: s.id)
        self.newest = shot.id
        now = self.clock()
        if not self.setup.push:
            if self.pull.settle(shot, now, self.polls):
                log(f"Mahlkönig: shot {shot.id} reported to the E64 WS")
        elif self.push.claim(shot, self.random(16), now):
            log(f"Mahlkönig: shot {shot.id} will be delivered")
        else:
            self.pending, self.push.poll_now = shot, True

    async def step(self) -> None:
        """One push decision and its request, or one pull tick."""
        now = self.clock()
        if self.setup is None:
            return
        if not self.setup.push:
            before, polled = self.pull.state, self.polls != self.pull.polls_at
            self.pull.tick(now, self.polls, self.hold)
            if before == "finishing" and self.pull.state == "ready" and polled:
                self.delivered = self.pull.shot  # The grinder read the result.
            self.report()
            return
        if self.push.expire(self.wall(), self.random(16), now):
            log("Mahlkönig: no shot followed the grind; it is reported as cancelled")
        request = self.push.next(now)
        if request is not None:
            await self.send(request, now)
        self.report()

    async def send(self, request: Request, now: float) -> None:
        setup, push = self.setup, self.push
        if setup is None or self.http is None:
            return
        result, job = push.result, push.job
        retake = result is not None and result.retake and request == "brew_accept"
        body = request_body(
            request,
            device=setup.device,
            pairing=setup.pairing,
            uuid=(
                result.uuid
                if (retake or request == "brew_done") and result
                else job.uuid
                if job
                else ""
            ),
            dose=result.dose if retake and result else job.dose if job else 0,
            time=result.report.time_ms if result else 0,
            mass=result.report.mass_mg if result else 0,
            event=result.event if result else "",
            success=bool(result and result.report.success),
            application=0,
        )
        answer: Reply | None
        delivered = request == "brew_done" and result is not None and result.report.success
        try:
            async with self.http.post(
                f"https://{setup.host}:{self.port}{PATHS[request]}",
                data=body.encode(),
                headers={"Content-Type": "application/json", "Connection": "close"},
                ssl=aiohttp.Fingerprint(setup.pin),
                timeout=aiohttp.ClientTimeout(total=TIMEOUT_S),
            ) as response:
                answer = parse_reply(
                    request, response.status, (await response.read()).decode(errors="replace")
                )
        except aiohttp.ServerFingerprintMismatch:
            if push.link != "identity":
                log("Mahlkönig: the grinder presented another certificate")
            push.link = "identity"
            return
        except (aiohttp.ClientError, TimeoutError, OSError) as error:
            if push.failures == 0:
                log(f"Mahlkönig: {request} to {setup.host} failed ({clip(error)})")
            answer = None
        was = push.link
        push.reply(request, answer, now, self.wall())
        if push.link != was and push.link in {"ok", "unpaired"}:
            log(f"Mahlkönig: the grinder link is {push.link}")
        if delivered and answer is not None and answer.status == "ok" and result is not None:
            self.delivered = result.shot
        pending = self.pending
        if (
            request == "brew_jobs"
            and pending is not None
            and push.claim(pending, self.random(16), now)
        ):
            self.pending = None
            log(f"Mahlkönig: shot {pending.id} matched a grinder job seen after it")

    # --- The E64 WS's requests, from nginx on port 80 ------------------------------------------

    async def route(self, request: web.Request, own_name: str) -> web.Response:
        missing = web.json_response({"error": "NOT_FOUND"}, status=404)
        if self.setup is None or self.setup.push:
            return missing
        if not beanconqueror.host_allowed(request.headers.get("Host", ""), own_name):
            return web.json_response({"error": "HOST_NOT_ALLOWED"}, status=403)
        try:
            peer = ipaddress.ip_address(request.headers.get("X-Real-IP", ""))
        except ValueError:
            peer = None
        if (
            peer is None
            or not (peer.is_private or peer.is_link_local or peer.is_loopback)
            or "Origin" in request.headers
            or "Sec-Fetch-Site" in request.headers
        ):
            return web.json_response({"error": "MAHLKONIG_PEER"}, status=403)
        path = "/" + request.match_info["tail"].rstrip("/")
        now = self.clock()
        if request.method == "GET":
            if path == "/mako":
                self.polls += 1
                if self.seen_at is None or now - self.seen_at >= SEEN_S:
                    log("Mahlkönig: the E64 WS checked in")
                self.seen_at = now
                self.report()
                p = self.pull
                body = mako_body(
                    p.state, int((now - p.armed_at) * 1000), p.time_ms, p.volume, int(self.wall())
                )
            else:
                body = machine_body(self.device_id) if path == "/machine" else "{}"
            return web.Response(
                text=body, content_type="application/json", headers={"Connection": "close"}
            )
        if request.content_length is not None and request.content_length > BODY_MAX:
            return web.json_response({"error": "PAYLOAD_TOO_LARGE"}, status=413)
        text = (await request.content.read(BODY_MAX + 1))[:BODY_MAX].decode(errors="replace")
        value = json_number(text, "ID") if path == "/scripts/execute" else None
        if value == 9 and self.pull.execute(now, self.wall(), self.polls):
            log("Mahlkönig: the grinder ground for a shot; waiting up to 3 min for it")
        ratio = json_number(text, "SYNC_BEVERAGE_WEIGHT") if path == "/brewratio" else None
        if ratio is not None and 0 < ratio < 1000:
            self.pull.recipe_dg = _half_up(ratio * 10)
        return web.Response(
            text="{}", content_type="application/json", headers={"Connection": "close"}
        )

    def facts(self) -> dict[str, object]:
        """For the status page and the controller's Settings (the E64 WS address rule)."""
        return {
            "model": self.setup.model if self.setup else None,
            "pull": self.setup is not None and not self.setup.push,
            "own": self.own,
            "st": self.state(),
            "polls": self.polls,
            "delivered": self.delivered,
        }
