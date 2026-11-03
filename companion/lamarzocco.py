"""La Marzocco cloud client: the same minimal client the controller has.

It mirrors src/machine/OpenBrewByWeightMicraService.cpp (installation key and
id, /auth/init, sign-in, token refresh, signed headers, dashboard, the two
commands) and OpenBrewByWeightMicraWebSocket.inc (STOMP over the WebSocket,
WebSocket ping every 15 s, 30 s pong timeout, the socket's instant-first
reconnect ladder). The companion owns its own installation, so the
controller's key never leaves the controller.
"""

import asyncio
import contextlib
import json
import time
import traceback
import uuid
from typing import TYPE_CHECKING, Protocol

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import clip, crypto, dashboard, log
from .store import Account, Store, offload

if TYPE_CHECKING:
    from collections.abc import Coroutine, Mapping

API_ROOT = "https://lion.lamarzocco.io/api/customer-app"
WS_URL = "wss://lion.lamarzocco.io/ws/connect"
STOMP_HOST = "lion.lamarzocco.io"
HTTP_TIMEOUT_S = 10
RENEW_AFTER_S = 50 * 60  # Tokens live 60 minutes; renewing at 50 keeps far more than 210 s in hand.
RENEW_RETRY_S = 60
POLL_S = 30
PING_S = 15
PONG_TIMEOUT_S = 30
SUBSCRIBE_TIMEOUT_S = 10
CONNECT_TIMEOUT_S = 25
RETRY_S = (
    0,
    1,
    3,
    6,
    9,
    60,
)  # An immediate first retry, then the controller's delays and cooldown.
COMMANDS = {
    "temp": "CoffeeMachineSettingCoffeeBoilerTargetTemperature",
    "standby": "CoffeeMachineChangeMode",
    "on": "CoffeeMachineChangeMode",
}


class AuthRejectedError(Exception):
    """La Marzocco answered 401 or 403 to a sign-in: the account itself was refused."""


class TransportError(Exception):
    pass


class Events(Protocol):
    """What the client reports to (the companion): see LaMarzocco."""

    def account(self, ok: bool) -> None: ...
    def upstream(self) -> None: ...
    def subscribed(self) -> None: ...
    def pushed(self, data: dict[str, object], ac: int) -> None: ...
    def polled(self, data: dict[str, object], ac: int, first: bool) -> None: ...
    def renewed(self) -> None: ...


def _answered(what: str, status: int, text: str = "") -> str:
    """`<what> answered <status>`, with a trimmed excerpt of the body when there is one."""
    return f"{what} answered {status} {clip(text)}".rstrip()


def _uuid(raw: bytes) -> str:
    return str(uuid.UUID(bytes=raw[:16], version=4))


def request_proof(text: str, secret: bytes) -> str:
    """La Marzocco's request proof, byte for byte as the controller computes it."""
    work = bytearray(secret)
    for byte in text.encode():
        index = byte % 32
        shift = work[(index + 1) % 32] & 7
        value = byte ^ work[index]
        work[index] = (value << shift | value >> (8 - shift)) & 0xFF if shift else value
    return crypto.b64(crypto.sha256(bytes(work)))


class Installation:
    """Identity of the companion's own La Marzocco installation."""

    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        self.key = key
        self.id = _uuid(crypto.sha256(crypto.scalar(key)))
        self.public_der = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_b64 = crypto.b64(self.public_der)
        id_hash = crypto.b64(crypto.sha256(self.id.encode()))
        self.secret = crypto.sha256(f"{self.id}.{self.public_b64}.{id_hash}".encode())

    def registration(self) -> tuple[dict[str, str], str]:
        """Headers and body of POST /auth/init."""
        proof = request_proof(
            f"{self.id}.{crypto.b64(crypto.sha256(self.public_der))}", self.secret
        )
        return {
            "X-App-Installation-Id": self.id,
            "X-Request-Proof": proof,
        }, f'{{"pk":"{self.public_b64}"}}'

    def signed_headers(self) -> dict[str, str]:
        nonce = str(uuid.uuid4())
        timestamp = str(time.time_ns() // 1000000)
        base = f"{self.id}.{nonce}.{timestamp}"
        message = f"{base}.{request_proof(base, self.secret)}".encode()
        signature = self.key.sign(message, ec.ECDSA(hashes.SHA256()))
        return {
            "X-App-Installation-Id": self.id,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Request-Signature": crypto.b64(signature),
        }


def stomp_frame(command: str, headers: Mapping[str, str], body: str = "") -> str:
    return (
        command
        + "\n"
        + "".join(f"{key}:{value}\n" for key, value in headers.items())
        + "\n"
        + body
        + "\0"
    )


def stomp_parse(frame: str) -> tuple[str, dict[str, str], str] | None:
    """(command, headers, body) of one NUL-delimited STOMP frame, or None for a heart-beat."""
    frame = frame.lstrip("\r\n")
    if not frame:
        return None
    lines: list[str] = []
    rest = frame
    while True:
        line, newline, rest = rest.partition("\n")
        if not newline:
            raise ValueError("STOMP frame without a header end")
        line = line.removesuffix("\r")
        if not line:
            break
        lines.append(line)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, colon, value = line.partition(":")
        if not colon:
            raise ValueError("malformed STOMP header")
        unescape = {"\\c": ":", "\\n": "\n", "\\r": "\r", "\\\\": "\\"}
        for escaped, plain in unescape.items():
            value = value.replace(escaped, plain)
        headers.setdefault(key, value)  # STOMP: the first occurrence wins.
    return lines[0], headers, rest


class LaMarzocco:
    """Signs in, keeps the token fresh, follows the machine and sends commands.

    `events` receives: account(ok), upstream(), subscribed(), pushed(data, ac),
    polled(data, ac, first) and renewed(). It runs while configured with an
    account and observation on; the companion configures it from the
    controller's cfg and creds. With observation off the controller keeps La
    Marzocco on its own connection, so this client does not even sign in.
    """

    def __init__(
        self,
        store: Store,
        http: aiohttp.ClientSession,
        events: Events,
        api_root: str = API_ROOT,
        ws_url: str = WS_URL,
    ) -> None:
        self.store, self.http, self.events = store, http, events
        self.api_root, self.ws_url = api_root, ws_url
        self.wanted: tuple[tuple[str, str, str] | None, str, bool] = (None, "ws", True)
        self.account: tuple[str, str, str] | None = None
        self.installation: Installation | None = None
        self.access: str | None = None
        self.refresh: str | None = None
        self.issued_at = 0.0
        self.issued = asyncio.Event()  # Set by each sign-in: the renewal deadline moved.
        self.rejected = False
        self.sub, self.ep, self.alive_at = False, 0, 0.0
        self.last_message_at = 0.0
        self.refused = False
        self.last_command = 0
        self.tasks: set[asyncio.Task[None]] = set()
        self.renewal: asyncio.Task[None] | None = None
        self.session_lock = asyncio.Lock()

    # --- State the companion reports ---------------------------------------
    @property
    def up(self) -> bool:
        window = PONG_TIMEOUT_S if self.wanted[1] == "ws" else 2 * POLL_S + HTTP_TIMEOUT_S
        return self.sub and time.monotonic() - self.alive_at < window

    @property
    def tok(self) -> int:
        return max(0, int(self.issued_at + RENEW_AFTER_S - time.monotonic())) if self.access else 0

    def signed_in_for(self, account: Account) -> bool:
        return self.access is not None and self.account == _identity(account)

    def rejected_for(self, account: Account) -> bool:
        return self.rejected and self.account == _identity(account)

    # --- Lifecycle -----------------------------------------------------------
    def configure(self, account: Account | None, conn: str, observe: bool) -> None:
        """Run with this account (None stops), connection type ('ws' or 'api') and observation."""
        wanted = (_identity(account), conn, observe)
        if wanted == self.wanted:
            return
        self.wanted = wanted
        self.stop()
        if wanted[0] != self.account:
            self.account, self.rejected = wanted[0], False
            self.access = self.refresh = None
        if self._usable():
            _ = self._spawn(self._run())

    def stop(self) -> None:
        for task in self.tasks:
            task.cancel()
        self.tasks.clear()
        self.refused = False
        self._set_subscribed(False)

    def _usable(self) -> bool:
        return self.account is not None and not self.rejected and self.wanted[2]

    def erase(self) -> None:
        """Forget the account and the installation (the pairing is gone).

        A later account registers a new one.
        """
        self.configure(None, *self.wanted[1:])
        self.installation = None
        self.access = self.refresh = None
        self.refused = False

    def _spawn(self, coroutine: Coroutine[object, object, None]) -> asyncio.Task[None]:
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self._done)
        return task

    def _done(self, task: asyncio.Task[None]) -> None:
        self.tasks.discard(task)
        if not task.cancelled() and (error := task.exception()) is not None:
            log("La Marzocco task failed:\n" + "".join(traceback.format_exception(error)))

    def _set_subscribed(self, subscribed: bool) -> None:
        if subscribed:
            self.ep += 1
            self.alive_at = time.monotonic()
        if subscribed or self.sub:
            self.sub = subscribed
            self.events.upstream()

    def _refused(self, refused: bool) -> None:
        """Reads or commands answered 401/403: the subscription lives, the data plane does not."""
        if refused != self.refused:
            self.refused = refused
            log(
                "La Marzocco answers 401/403 to reads and commands; the subscription still lives"
                if refused
                else "La Marzocco accepts reads and commands again"
            )
            self.events.upstream()

    async def _run(self) -> None:
        attempt = 0
        while True:
            try:
                await self._session()
                if self.renewal not in self.tasks:
                    self.renewal = self._spawn(self._renew_loop())
                attempt = 0
                if self.wanted[1] == "ws":
                    await self._websocket()
                else:
                    await self._poll()
            except AuthRejectedError:
                self._reject()
                return
            except (
                TransportError,
                aiohttp.ClientError,
                TimeoutError,
                ValueError,
                OSError,
            ) as error:
                self._set_subscribed(False)
                delay = RETRY_S[min(attempt, len(RETRY_S) - 1)]
                attempt = attempt + 1 if attempt < len(RETRY_S) - 1 else 0
                log(
                    f"La Marzocco connection lost ({str(error) or type(error).__name__});"
                    f" retrying in {delay} s"
                )
                await asyncio.sleep(delay)

    def _reject(self) -> None:
        log("La Marzocco refused the account; waiting for new credentials from the controller")
        self.rejected = True
        self.access = self.refresh = None
        self.stop()
        self.events.account(False)

    # --- HTTP ----------------------------------------------------------------
    async def _request(
        self,
        method: str,
        path: str,
        body: str | None = None,
        authenticated: bool = True,
        registration: bool = False,
    ) -> tuple[int, str]:
        if self.installation is None:
            self.installation = Installation((await offload(self.store.installation_key))[0])
        headers = {"Accept": "application/json", "User-Agent": "OpenBrewByWeight/1"}
        if registration:
            extra, body = self.installation.registration()
            headers.update(extra)
        else:
            headers.update(self.installation.signed_headers())
        if authenticated:
            headers["Authorization"] = f"Bearer {self.access}"
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            async with self.http.request(
                method,
                self.api_root + path,
                data=body,
                headers=headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_S),
            ) as reply:
                return reply.status, await reply.text()
        except (aiohttp.ClientError, TimeoutError, OSError) as error:
            why = clip(f"{type(error).__name__}: {error}")
            raise TransportError(f"{method} {path.rsplit('/', 1)[-1]}: {why}") from None

    def _tokens(self, text: str) -> None:
        tokens = dashboard.parse(text)
        access, refresh = tokens.get("accessToken"), tokens.get("refreshToken")
        if not isinstance(access, str) or not isinstance(refresh, str):
            raise TransportError("sign-in answer without tokens")
        self.access, self.refresh = access, refresh
        self.issued_at = time.monotonic()
        self.issued.set()

    async def _sign_in(self) -> None:
        saved = await offload(self.store.credentials)
        account: Mapping[str, object] = saved or {}
        if not (await offload(self.store.installation_key))[1]:
            status, text = await self._request(
                "POST", "/auth/init", authenticated=False, registration=True
            )
            if not 200 <= status < 300:
                raise TransportError(_answered("installation registration", status, text))
            await offload(self.store.installation_registered)
            log("registered the companion's La Marzocco installation")
        body = json.dumps({"username": account.get("email"), "password": account.get("password")})
        status, text = await self._request("POST", "/auth/signin", body, authenticated=False)
        if status in (401, 403):
            raise AuthRejectedError
        if status != 200:
            raise TransportError(_answered("sign-in", status, text))
        self._tokens(text)
        log("signed in to La Marzocco")

    async def _session(self, renew: bool = False) -> None:
        """An access token. Only the renew loop (renew) replaces a valid one; a missing one (at
        start, after a 401) is refreshed or signed in here, and every new token outside the renew
        loop is reported."""
        async with self.session_lock:
            if self.access and not renew:
                return
            refreshed = False
            if self.refresh:
                saved = await offload(self.store.credentials)
                account: Mapping[str, object] = saved or {}
                body = json.dumps({"username": account.get("email"), "refreshToken": self.refresh})
                try:
                    status, text = await self._request(
                        "POST", "/auth/refreshtoken", body, authenticated=False
                    )
                    if status == 200:
                        self._tokens(text)
                        refreshed = True
                except TransportError, ValueError:
                    pass
            if not refreshed:
                self.access = None
                await self._sign_in()
            if not (renew and refreshed):
                self.events.account(True)

    async def _renew_loop(self) -> None:
        while True:
            while (due := self.issued_at + RENEW_AFTER_S - time.monotonic()) > 0:
                # A sign-in meanwhile (after a 401) moves the deadline: wait for it again.
                self.issued.clear()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self.issued.wait(), due)
            try:
                await self._session(renew=True)
            except AuthRejectedError:
                self._reject()
                return
            except (TransportError, ValueError) as error:
                log(
                    f"La Marzocco token renewal failed ({error}); trying again in {RENEW_RETRY_S} s"
                )
                await asyncio.sleep(RENEW_RETRY_S)
                continue
            self.events.renewed()

    async def read(self) -> tuple[int, dict[str, object] | None, int]:
        """One dashboard read: (HTTP status, parsed dashboard or None, last command id when
        taken)."""
        ac = self.last_command
        if self.account is None or not self._usable():
            return 0, None, ac
        try:
            await self._session()
            status, text = await self._request("GET", f"/things/{self.account[2]}/dashboard")
        except AuthRejectedError:
            self._reject()
            return 0, None, ac
        except (TransportError, ValueError) as error:
            log(f"La Marzocco read failed ({error})")
            return 0, None, ac
        if status in (401, 403):
            self.access = None  # A stale token: the next request signs in again.
            self._refused(True)
        elif status == 200:
            self._refused(False)
        else:
            log(_answered("dashboard read", status, text))
        try:
            return status, dashboard.parse(text) if status == 200 else None, ac
        except ValueError as error:
            log(
                "La Marzocco sent a dashboard the controller could not decode"
                f" ({clip(error)}); dropped"
            )
            return status, None, ac

    async def command(self, command_id: int, op: str, value: int | None = None) -> int:
        """Send one command; returns its HTTP status (0 for a transport failure)."""
        if self.account is None or not self._usable():
            return 0
        if op == "temp":
            if value is None:
                raise TypeError("a temp command needs its value")
            body = f'{{"boilerIndex":1,"targetTemperature":{value // 10}.{value % 10}}}'
        else:
            body = '{"mode":"StandBy"}' if op == "standby" else '{"mode":"BrewingMode"}'
        self.last_command = command_id
        try:
            await self._session()
            status, _ = await self._request(
                "POST", f"/things/{self.account[2]}/command/{COMMANDS[op]}", body
            )
        except AuthRejectedError:
            self._reject()
            return 0
        except (TransportError, ValueError) as error:
            log(f"La Marzocco command failed ({error})")
            return 0
        if status in (401, 403):
            self.access = None
            self._refused(True)
        elif status == 200:
            self._refused(False)
        return status

    # --- Observation ---------------------------------------------------------
    async def _poll(self) -> None:
        first = True
        while True:
            _, data, ac = await self.read()
            if data is None:
                raise TransportError("the dashboard read failed")  # read() named the reason.
            if first:
                self._set_subscribed(True)
            self.alive_at = time.monotonic()
            self.events.polled(data, ac, first)
            first = False
            await asyncio.sleep(POLL_S)

    async def _websocket(self) -> None:
        if self.account is None or self.installation is None:
            raise RuntimeError("no session to follow")  # _run opens one first.
        serial = self.account[2]
        destination, subscription = f"/ws/sn/{serial}/dashboard", "companion"
        headers = {"User-Agent": "OpenBrewByWeight/1", **self.installation.signed_headers()}
        try:
            ws = await asyncio.wait_for(
                self.http.ws_connect(self.ws_url, headers=headers, autoping=False),
                CONNECT_TIMEOUT_S,
            )
        except aiohttp.WSServerHandshakeError as error:
            if error.status in (401, 403):
                self.access = None
            raise TransportError(f"WebSocket upgrade answered {error.status}") from None
        async with ws:
            await ws.send_str(
                stomp_frame(
                    "CONNECT",
                    {
                        "host": STOMP_HOST,
                        "accept-version": "1.2,1.1",
                        "heart-beat": "0,0",
                        "Authorization": f"Bearer {self.access}",
                    },
                )
            )
            connected_at = next_ping = time.monotonic()
            next_ping += PING_S
            buffer = ""
            try:
                while True:
                    now = time.monotonic()
                    deadline = (
                        self.alive_at + PONG_TIMEOUT_S
                        if self.sub
                        else connected_at + SUBSCRIBE_TIMEOUT_S
                    )
                    if now >= deadline:
                        raise TransportError(
                            f"no pong within {PONG_TIMEOUT_S} s"
                            if self.sub
                            else f"no CONNECTED frame within {SUBSCRIBE_TIMEOUT_S} s"
                        )
                    try:
                        message = await ws.receive(timeout=min(deadline, next_ping) - now)
                    except TimeoutError:
                        if time.monotonic() >= next_ping:
                            await ws.ping()
                            next_ping = time.monotonic() + PING_S
                        continue
                    if message.type is aiohttp.WSMsgType.PING:
                        await ws.pong(message.data)
                        continue
                    if message.type is aiohttp.WSMsgType.PONG:
                        self.alive_at = time.monotonic()
                        continue
                    if message.type not in (aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY):
                        code = message.data if isinstance(message.data, int) else ws.close_code
                        why = (
                            type(message.data).__name__
                            if isinstance(message.data, BaseException)
                            else f"code {code}"
                        )
                        idle = (
                            f"{time.monotonic() - self.last_message_at:.0f} s"
                            " since its last message"
                            if self.last_message_at
                            else "no message ever arrived"
                        )
                        raise TransportError(f"La Marzocco closed the WebSocket ({why}, {idle})")
                    buffer += (
                        message.data if isinstance(message.data, str) else message.data.decode()
                    )
                    *frames, buffer = buffer.split("\0")
                    for frame in frames:
                        await self._stomp(ws, frame, destination, subscription)
            finally:
                self._set_subscribed(False)

    async def _stomp(
        self,
        ws: aiohttp.ClientWebSocketResponse,
        frame: str,
        destination: str,
        subscription: str,
    ) -> None:
        parsed = stomp_parse(frame)
        if parsed is None:
            return
        command, headers, body = parsed
        if command == "CONNECTED" and not self.sub and headers.get("version") in ("1.2", "1.1"):
            await ws.send_str(
                stomp_frame(
                    "SUBSCRIBE",
                    {
                        "destination": destination,
                        "ack": "auto",
                        "id": subscription,
                        "content-length": "0",
                    },
                )
            )
            self._set_subscribed(True)
            self.events.subscribed()
        elif (
            command == "MESSAGE"
            and self.sub
            and headers.get("destination") == destination
            and headers.get("subscription") == subscription
        ):
            self.last_message_at = time.monotonic()
            self.events.pushed(dashboard.parse(body), self.last_command)
        else:
            raise TransportError(f"unexpected STOMP {command}")


def _identity(account: Account | None) -> tuple[str, str, str] | None:
    """What makes a different La Marzocco session: email, password and machine serial."""
    return (account["email"], account["password"], account["serial"]) if account else None
