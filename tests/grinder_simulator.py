"""A Mahlkönig Grind-by-Sync grinder for tests, written from the protocol facts in the firmware's
docs/MAHLKONIG_GBS.md (no other implementation's code).

- `PushGrinder`: an E65/E80. HTTPS on a self-signed certificate, one request per connection (it
  closes every connection), pairing with a code, an already-paired grinder, a forgotten
  application, a freeze after accepting, jobs that expire untaken and are handed out again while
  taken, Clear Pairing (403), 403 while booting, slow and dropped answers and a new certificate.
- `PullGrinder`: an E64 WS polling a machine (2 s polls, `brewratio`, `execute` with retries).

Tests drive both on localhost with their own clock. Run on its own (no packages beyond the
companion's) for a device test on the LAN:

    python3 tests/grinder_simulator.py push --listen 0.0.0.0 --port 30001
    python3 tests/grinder_simulator.py pull --machine http://192.168.1.42
"""

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import socket
import ssl
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

import aiohttp
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from collections.abc import Callable


def certificate() -> tuple[bytes, bytes]:
    """A self-signed certificate naming no host, as the grinder's, and its key (PEM)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Grinder")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


@dataclass
class Job:
    uuid: str
    created: float
    dose: int = 2
    duration_ms: int = 28000
    weight_mg: int = 36000
    taken: float | None = None
    handed: float = 0.0


@dataclass
class PushGrinder:
    """An E65/E80 on its own clock (`clock`); timers are tunable."""

    clock: Callable[[], float] = time.monotonic
    untaken_s: float = 60.0  # an untaken job is dropped after this
    rehand_s: float = 50.0  # a taken job is handed out again this often
    code: int = 73
    pairing_mode: bool = False
    paired: dict[str, int] = field(default_factory=dict)  # brewDeviceId -> pairingId
    applications: dict[int, str] = field(default_factory=dict)
    accepted: set[int] = field(default_factory=set)
    jobs: list[Job] = field(default_factory=list)
    results: list[dict[str, object]] = field(default_factory=list)
    requests: list[str] = field(default_factory=list)
    booting_until: float = 0.0
    frozen_until: float = 0.0
    delay_s: float = 0.0
    drop: int = 0  # answer nothing to this many requests
    next_id: int = 10
    pem: tuple[bytes, bytes] = field(default_factory=certificate)
    runner: web.AppRunner | None = None
    port: int = 0

    @property
    def fingerprint(self) -> str:
        der = x509.load_pem_x509_certificate(self.pem[0]).public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()

    def grind(self) -> Job:
        job = Job(str(uuid.uuid4()), self.clock())
        self.jobs.append(job)
        return job

    def accept(self, application: int) -> None:
        self.accepted.add(application)

    def clear_pairing(self) -> None:
        self.paired.clear()

    def new_certificate(self) -> None:
        self.pem = certificate()

    def _pairing(self, body: dict[str, object]) -> int | None:
        pairing = body.get("pairingId")
        return pairing if type(pairing) is int and pairing in self.paired.values() else None

    def _visible(self) -> list[Job]:
        now = self.clock()
        self.jobs = [
            j for j in self.jobs if j.taken is not None or now - j.created < self.untaken_s
        ]
        return [j for j in self.jobs if j.taken is None or now - j.handed >= self.rehand_s]

    async def handle(self, request: web.Request) -> web.StreamResponse:
        name = request.match_info["name"]
        self.requests.append(name)
        if self.drop:
            self.drop -= 1
            await asyncio.sleep(30)
        if self.delay_s:
            await asyncio.sleep(self.delay_s)
        now = self.clock()
        if now < self.frozen_until:
            await asyncio.sleep(30)  # A grinder restarting after it accepted answers nothing.
        body = json.loads(await request.read())
        headers = {"Connection": "close"}  # Kept-open connections are dropped.
        if now < self.booting_until and name == "brewJobs":
            return web.Response(status=403, headers=headers)
        answer: dict[str, object]
        if name == "pairingApplication":
            device = str(body["brewDeviceId"])
            if device in self.paired:
                answer = {"status": "ClientErrorDevAlreadyPaired"}
            elif not self.pairing_mode:
                answer = {"status": "ClientErrorPairingNotActive"}
            else:
                self.next_id += 1
                self.applications[self.next_id] = device
                answer = {"status": "Ok", "applicationId": self.next_id, "pairingCode": self.code}
        elif name == "pairingStatus":
            application = body.get("applicationId")
            if application not in self.applications:
                answer = {"status": "ClientErrorPairingAppIdNotFound"}
            elif application in self.accepted:
                pairing = 4000 + int(str(application))
                self.paired[self.applications[int(str(application))]] = pairing
                answer = {"accepted": True, "pairingId": pairing}
            else:
                answer = {"accepted": False}
        elif self._pairing(body) is None:
            return web.Response(status=403, headers=headers)
        elif name == "brewJobs":
            jobs = self._visible()
            for visible in jobs:
                visible.handed = now
            answer = {
                "brewJobs": [
                    {
                        "grindUuid": j.uuid,
                        "groupHeadId": 1,
                        "doseTypeExpected": j.dose,
                        "durationExpectedMs": float(j.duration_ms),
                        "brewWeightExpectedMg": float(j.weight_mg),
                    }
                    for j in jobs
                ],
                "status": "Ok",
            }
        elif name == "brewAccept":
            wanted = next((j for j in self.jobs if j.uuid == body.get("grindUuid")), None)
            if wanted is not None:
                wanted.taken = wanted.handed = now
            answer = {"status": "Ok" if wanted is not None else "ClientErrorOngoingJobNotExisting"}
        else:
            done = next(
                (j for j in self.jobs if j.uuid == body.get("grindUuid") and j.taken is not None),
                None,
            )
            if done is None:
                answer = {"status": "ClientErrorOngoingJobNotExisting"}
            else:
                self.jobs.remove(done)
                self.results.append(body)
                answer = {"status": "Ok"}
        return web.json_response(answer, headers=headers)

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> None:
        app = web.Application()
        app.router.add_post("/grinderApi/{name}", self.handle)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        with tempfile.TemporaryDirectory() as folder:
            cert, key = Path(folder) / "cert.pem", Path(folder) / "key.pem"
            cert.write_bytes(self.pem[0])
            key.write_bytes(self.pem[1])
            context.load_cert_chain(cert, key)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        self.port = int(sock.getsockname()[1])
        await web.SockSite(self.runner, sock, ssl_context=context).start()

    async def restart(self, host: str = "127.0.0.1") -> None:
        """Serve again, on the same port, with the current certificate."""
        if self.runner is not None:
            await self.runner.cleanup()
        await self.start(host, self.port)

    async def stop(self) -> None:
        if self.runner is not None:
            await self.runner.cleanup()


@dataclass
class PullGrinder:
    """An E64 WS polling `machine` (base URL)."""

    machine: str
    http: aiohttp.ClientSession
    statuses: list[dict[str, object]] = field(default_factory=list)

    async def poll(self) -> dict[str, object]:
        async with self.http.get(self.machine + "/api/v2/mako") as response:
            answer = cast("dict[str, object]", await response.json())
        self.statuses.append(answer)
        return answer

    async def grind(self, weight_g: float = 36.5, retries: int = 3) -> None:
        await self._post("/api/v2/brewratio", {"SYNC_BEVERAGE_WEIGHT": weight_g, "SYNC_FILTER": 0})
        for _ in range(retries):
            await self._post("/api/v2/scripts/execute", {"ID": 9})

    async def _post(self, path: str, body: dict[str, object]) -> None:
        async with self.http.post(self.machine + path, json=body) as response:
            await response.read()


async def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("mode", choices=("push", "pull"))
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=30001)
    parser.add_argument("--machine", default="http://127.0.0.1")
    args = parser.parse_args()
    if args.mode == "push":
        grinder = PushGrinder(pairing_mode=True)
        await grinder.start(args.listen, args.port)
        print(f"push grinder on {args.listen}:{grinder.port}, certificate {grinder.fingerprint}")
        print("commands: g = grind, a = accept the last application, c = Clear Pairing, q = quit")
        loop = asyncio.get_running_loop()
        while (line := (await loop.run_in_executor(None, input)).strip()) != "q":
            if line == "g":
                print("job", grinder.grind().uuid)
            elif line == "a" and grinder.applications:
                grinder.accept(max(grinder.applications))
            elif line == "c":
                grinder.clear_pairing()
        await grinder.stop()
        return
    async with aiohttp.ClientSession() as http:
        pull = PullGrinder(args.machine, http)
        await pull.grind()
        while True:
            print(await pull.poll())
            await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(_main())
