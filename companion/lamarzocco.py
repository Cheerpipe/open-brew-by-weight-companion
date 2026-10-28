"""La Marzocco cloud client: the same minimal client the controller has.

It mirrors src/machine/OpenBrewByWeightMicraService.cpp (installation key and
id, /auth/init, sign-in, token refresh, signed headers, dashboard, the two
commands) and OpenBrewByWeightMicraWebSocket.inc (STOMP over the WebSocket,
WebSocket ping every 15 s, 30 s pong timeout). The companion owns its own
installation, so the controller's key never leaves the controller.
"""

import asyncio
import json
import time
import uuid

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import crypto, dashboard, log

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
RETRY_S = (3, 6, 9, 60)  # The controller's reconnection delays, then its cooldown.
COMMANDS = {
    "temp": "CoffeeMachineSettingCoffeeBoilerTargetTemperature",
    "standby": "CoffeeMachineChangeMode",
    "on": "CoffeeMachineChangeMode",
}


class AuthRejected(Exception):
    """La Marzocco answered 401 or 403 to a sign-in: the account itself was refused."""


class TransportError(Exception):
    pass


def _uuid(raw):
    return str(uuid.UUID(bytes=raw[:16], version=4))


def request_proof(text, secret):
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

    def __init__(self, key):
        self.key = key
        self.id = _uuid(crypto.sha256(crypto.scalar(key)))
        self.public_der = key.public_key().public_bytes(serialization.Encoding.DER,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_b64 = crypto.b64(self.public_der)
        id_hash = crypto.b64(crypto.sha256(self.id.encode()))
        self.secret = crypto.sha256(f"{self.id}.{self.public_b64}.{id_hash}".encode())

    def registration(self):
        """Headers and body of POST /auth/init."""
        proof = request_proof(f"{self.id}.{crypto.b64(crypto.sha256(self.public_der))}", self.secret)
        return {"X-App-Installation-Id": self.id, "X-Request-Proof": proof}, f'{{"pk":"{self.public_b64}"}}'

    def signed_headers(self):
        nonce = str(uuid.uuid4())
        timestamp = str(time.time_ns() // 1000000)
        base = f"{self.id}.{nonce}.{timestamp}"
        message = f"{base}.{request_proof(base, self.secret)}".encode()
        signature = self.key.sign(message, ec.ECDSA(hashes.SHA256()))
        return {"X-App-Installation-Id": self.id, "X-Timestamp": timestamp, "X-Nonce": nonce,
                "X-Request-Signature": crypto.b64(signature)}


def stomp_frame(command, headers, body=""):
    return command + "\n" + "".join(f"{key}:{value}\n" for key, value in headers.items()) + "\n" + body + "\0"


def stomp_parse(frame):
    """(command, headers, body) of one NUL-delimited STOMP frame, or None for a heart-beat."""
    frame = frame.lstrip("\r\n")
    if not frame:
        return None
    lines, rest = [], frame
    while True:
        line, newline, rest = rest.partition("\n")
        if not newline:
            raise ValueError("STOMP frame without a header end")
        line = line.removesuffix("\r")
        if not line:
            break
        lines.append(line)
    headers = {}
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

    def __init__(self, store, http, events, api_root=API_ROOT, ws_url=WS_URL):
        self.store, self.http, self.events = store, http, events
        self.api_root, self.ws_url = api_root, ws_url
        self.wanted = (None, "ws", True)
        self.account = None
        self.installation = None
        self.access = self.refresh = None
        self.issued_at = 0.0
        self.rejected = False
        self.sub, self.ep, self.alive_at = False, 0, 0.0
        self.refused = False
        self.last_command = 0
        self.tasks = set()
        self.renewal = None
        self.session_lock = asyncio.Lock()

    # --- State the companion reports ---------------------------------------
    @property
    def up(self):
        window = PONG_TIMEOUT_S if self.wanted[1] == "ws" else 2 * POLL_S + HTTP_TIMEOUT_S
        return self.sub and time.monotonic() - self.alive_at < window

    @property
    def tok(self):
        return max(0, int(self.issued_at + RENEW_AFTER_S - time.monotonic())) if self.access else 0

    def signed_in_for(self, account):
        return self.access is not None and self.account == _identity(account)

    def rejected_for(self, account):
        return self.rejected and self.account == _identity(account)

    # --- Lifecycle -----------------------------------------------------------
    def configure(self, account, conn, observe):
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
            self._spawn(self._run())

    def stop(self):
        for task in self.tasks:
            task.cancel()
        self.tasks.clear()
        self.refused = False
        self._set_subscribed(False)

    def _usable(self):
        return self.account is not None and not self.rejected and self.wanted[2]

    def erase(self):
        """Forget the account and the installation (the pairing is gone): a later account registers a new one."""
        self.configure(None, *self.wanted[1:])
        self.installation = None
        self.access = self.refresh = None
        self.refused = False

    def _spawn(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self._done)
        return task

    def _done(self, task):
        self.tasks.discard(task)
        if not task.cancelled() and task.exception():
            log(f"La Marzocco task failed: {task.exception()!r}")

    def _set_subscribed(self, subscribed):
        if subscribed:
            self.ep += 1
            self.alive_at = time.monotonic()
        if subscribed or self.sub:
            self.sub = subscribed
            self.events.upstream()

    def _refused(self, refused):
        """Reads or commands answered 401/403: the subscription lives, but the data plane does not."""
        if refused != self.refused:
            self.refused = refused
            self.events.upstream()

    async def _run(self):
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
            except AuthRejected:
                self._reject()
                return
            except (TransportError, aiohttp.ClientError, asyncio.TimeoutError, ValueError, OSError) as error:
                self._set_subscribed(False)
                delay = RETRY_S[min(attempt, len(RETRY_S) - 1)]
                attempt = attempt + 1 if attempt < len(RETRY_S) - 1 else 0
                log(f"La Marzocco connection lost ({error or type(error).__name__}); retrying in {delay} s")
                await asyncio.sleep(delay)

    def _reject(self):
        log("La Marzocco refused the account; waiting for new credentials from the controller")
        self.rejected = True
        self.access = self.refresh = None
        self.stop()
        self.events.account(False)

    # --- HTTP ----------------------------------------------------------------
    async def _request(self, method, path, body=None, authenticated=True, registration=False):
        if self.installation is None:
            self.installation = Installation(self.store.installation_key()[0])
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
            async with self.http.request(method, self.api_root + path, data=body, headers=headers,
                                         allow_redirects=False,
                                         timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_S)) as reply:
                return reply.status, await reply.text()
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as error:
            raise TransportError(f"{method} {path.rsplit('/', 1)[-1]}: {type(error).__name__}") from None

    def _tokens(self, text):
        tokens = dashboard.parse(text)
        if not isinstance(tokens.get("accessToken"), str) or not isinstance(tokens.get("refreshToken"), str):
            raise TransportError("sign-in answer without tokens")
        self.access, self.refresh = tokens["accessToken"], tokens["refreshToken"]
        self.issued_at = time.monotonic()

    async def _sign_in(self):
        account = self.store.credentials() or {}
        if not self.store.installation_key()[1]:
            status, _ = await self._request("POST", "/auth/init", authenticated=False, registration=True)
            if not 200 <= status < 300:
                raise TransportError(f"installation registration answered {status}")
            self.store.installation_registered()
            log("registered the companion's La Marzocco installation")
        body = json.dumps({"username": account.get("email"), "password": account.get("password")})
        status, text = await self._request("POST", "/auth/signin", body, authenticated=False)
        if status in (401, 403):
            raise AuthRejected()
        if status != 200:
            raise TransportError(f"sign-in answered {status}")
        self._tokens(text)
        log("signed in to La Marzocco")

    async def _session(self, renew=False):
        """An access token. Only the renew loop (renew) replaces a valid one; a missing one (at start, after a
        401) is refreshed or signed in here, and every new token outside the renew loop is reported."""
        async with self.session_lock:
            if self.access and not renew:
                return
            refreshed = False
            if self.refresh:
                account = self.store.credentials() or {}
                body = json.dumps({"username": account.get("email"), "refreshToken": self.refresh})
                try:
                    status, text = await self._request("POST", "/auth/refreshtoken", body, authenticated=False)
                    if status == 200:
                        self._tokens(text)
                        refreshed = True
                except (TransportError, ValueError):
                    pass
            if not refreshed:
                self.access = None
                await self._sign_in()
            if not (renew and refreshed):
                self.events.account(True)

    async def _renew_loop(self):
        while True:
            while (due := self.issued_at + RENEW_AFTER_S - time.monotonic()) > 0:
                await asyncio.sleep(due)  # A sign-in meanwhile (after a 401) moves the deadline.
            try:
                await self._session(renew=True)
            except AuthRejected:
                self._reject()
                return
            except (TransportError, ValueError) as error:
                log(f"La Marzocco token renewal failed ({error}); trying again in {RENEW_RETRY_S} s")
                await asyncio.sleep(RENEW_RETRY_S)
                continue
            self.events.renewed()

    async def read(self):
        """One dashboard read: (HTTP status, parsed dashboard or None, last command id when taken)."""
        ac = self.last_command
        if not self._usable():
            return 0, None, ac
        try:
            await self._session()
            status, text = await self._request("GET", f"/things/{self.account[2]}/dashboard")
        except AuthRejected:
            self._reject()
            return 0, None, ac
        except (TransportError, ValueError):
            return 0, None, ac
        if status in (401, 403):
            self.access = None  # A stale token: the next request signs in again.
            self._refused(True)
        elif status == 200:
            self._refused(False)
        try:
            return status, dashboard.parse(text) if status == 200 else None, ac
        except ValueError:
            log("La Marzocco sent a dashboard the controller could not decode; dropped")
            return status, None, ac

    async def command(self, command_id, op, value=None):
        """Send one command; returns its HTTP status (0 for a transport failure)."""
        if not self._usable():
            return 0
        body = (f'{{"boilerIndex":1,"targetTemperature":{value // 10}.{value % 10}}}' if op == "temp"
                else '{"mode":"StandBy"}' if op == "standby" else '{"mode":"BrewingMode"}')
        self.last_command = command_id
        try:
            await self._session()
            status, _ = await self._request("POST", f"/things/{self.account[2]}/command/{COMMANDS[op]}", body)
        except AuthRejected:
            self._reject()
            return 0
        except (TransportError, ValueError):
            return 0
        if status in (401, 403):
            self.access = None
            self._refused(True)
        elif status == 200:
            self._refused(False)
        return status

    # --- Observation ---------------------------------------------------------
    async def _poll(self):
        first = True
        while True:
            status, data, ac = await self.read()
            if data is None:
                raise TransportError(f"dashboard read answered {status}")
            if first:
                self._set_subscribed(True)
            self.alive_at = time.monotonic()
            self.events.polled(data, ac, first)
            first = False
            await asyncio.sleep(POLL_S)

    async def _websocket(self):
        serial = self.account[2]
        destination, subscription = f"/ws/sn/{serial}/dashboard", "companion"
        headers = {"User-Agent": "OpenBrewByWeight/1", **self.installation.signed_headers()}
        try:
            ws = await asyncio.wait_for(self.http.ws_connect(self.ws_url, headers=headers, autoping=False),
                                        CONNECT_TIMEOUT_S)
        except aiohttp.WSServerHandshakeError as error:
            if error.status in (401, 403):
                self.access = None
            raise TransportError(f"WebSocket upgrade answered {error.status}") from None
        async with ws:
            await ws.send_str(stomp_frame("CONNECT", {"host": STOMP_HOST, "accept-version": "1.2,1.1",
                                                      "heart-beat": "0,0", "Authorization": f"Bearer {self.access}"}))
            connected_at = next_ping = time.monotonic()
            next_ping += PING_S
            buffer = ""
            try:
                while True:
                    now = time.monotonic()
                    deadline = self.alive_at + PONG_TIMEOUT_S if self.sub else connected_at + SUBSCRIBE_TIMEOUT_S
                    if now >= deadline:
                        raise TransportError("La Marzocco stopped answering")
                    try:
                        message = await ws.receive(timeout=min(deadline, next_ping) - now)
                    except asyncio.TimeoutError:
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
                        raise TransportError("La Marzocco closed the WebSocket")
                    buffer += message.data if isinstance(message.data, str) else message.data.decode()
                    *frames, buffer = buffer.split("\0")
                    for frame in frames:
                        await self._stomp(ws, frame, destination, subscription)
            finally:
                self._set_subscribed(False)

    async def _stomp(self, ws, frame, destination, subscription):
        parsed = stomp_parse(frame)
        if parsed is None:
            return
        command, headers, body = parsed
        if command == "CONNECTED" and not self.sub and headers.get("version") in ("1.2", "1.1"):
            await ws.send_str(stomp_frame("SUBSCRIBE", {"destination": destination, "ack": "auto",
                                                        "id": subscription, "content-length": "0"}))
            self._set_subscribed(True)
            self.events.subscribed()
        elif command == "MESSAGE" and self.sub and headers.get("destination") == destination \
                and headers.get("subscription") == subscription:
            self.events.pushed(dashboard.parse(body), self.last_command)
        else:
            raise TransportError(f"unexpected STOMP {command}")


def _identity(account):
    """What makes a different La Marzocco session: email, password and machine serial."""
    return (account["email"], account["password"], account["serial"]) if account else None

