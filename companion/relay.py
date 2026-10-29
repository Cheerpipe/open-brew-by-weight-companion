"""The relay: every screen's REST call reaches the controller signed and sealed.

A relay session needs no clock and nothing stored: a GET returns the
controller's challenge, a POST proves the pairing secret and both sides derive
Kr (signing) and Kb (sealing) from it. Each request then carries
`X-OBBW-Relay: 2 <q> <addr> <screen> <mac>`, its body and credential headers
sealed with AES-256-GCM under Kb (protocol 2): no password, session token or
sign-in body crosses the hop in the clear. Without a relay session (not
paired, a controller without the relay route, or one that turned the Web UI
through the companion off) the companion forwards as a plain proxy
(passthrough) or refuses (disabled).
"""

import asyncio
import hmac
import ipaddress
import json
import os
import re

import aiohttp
from cryptography.exceptions import InvalidTag
from yarl import URL

from . import crypto, log
from .store import offload

PATH = "/api/v1/companion/relay"
PROTOCOL = 1
CTX_SESSION, CTX_PASSWORD, CTX_BODY = 0, 1, 2
COUNTER_MAX = 0xFFFFFFFF
CLIENT_ID = re.compile(r"[0-9a-f]{16,24}")
# What the controller reads from a browser's request; everything else stays here.
FORWARDED = ("Content-Type", "X-WebUI-Session", "X-WebUI-Activity", "X-Device-Password",
             "X-OTA-Transfer", "X-OTA-Offset", "X-OTA-Length", "X-OTA-Allow-Downgrade", "Content-Range")
HOP_BY_HOP = frozenset({"connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer",
                        "upgrade", "content-length"})
# Sealed values stay out of the hop-by-hop set and of the browser's answer.
SEALED_RESPONSE_HEADER = "X-OBBW-Enc"
READ_LIMIT = 64 * 1024  # JSON answers are read whole: claims, commands and errors are small.
# Every relayed request is bounded (an OTA chunk is one 64 KiB POST, far under
# this), matching nginx's own 5-minute proxy_read_timeout. The total does not
# reach the two WebSockets: aiohttp drops the timer on upgrade, by design.
TIMEOUT = aiohttp.ClientTimeout(total=300, connect=5, sock_read=180)


def address(text):
    """The browser's address from nginx's X-Real-IP, as the header carries it."""
    try:
        return str(ipaddress.ip_address((text or "").split("%")[0]))
    except ValueError:
        return "0.0.0.0"


class Relay:
    def __init__(self, companion):
        self.companion = companion
        self.client_id = os.urandom(12).hex()  # The controller's one Web UI client for every screen.
        self.mode = "passthrough"  # passthrough, ready or disabled
        self.link = None  # Whether the controller wants the link; None until it answered.
        self.key, self.body_key, self.counter, self.generation = None, None, 0, 0
        self.lock = asyncio.Lock()
        self.http = None
        self.reported = None

    def session(self):
        """Connections that close after each request and pass bodies through untouched."""
        if self.http is None or self.http.closed:
            self.http = aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True),
                                              auto_decompress=False, timeout=TIMEOUT)
        return self.http

    async def close(self):
        if self.http is not None:
            await self.http.close()

    def reset(self, link=None):
        self.key, self.body_key, self.counter, self.mode = None, None, 0, "passthrough"
        self._set_link(link)

    def _set_link(self, link):
        if link != self.link:
            self.link = link
            self.companion.link_wanted(link)

    def _note(self, state):
        if state != self.reported:
            self.reported = state
            log(state)

    # --- Handshake -------------------------------------------------------------
    async def handshake(self):
        """A new relay session; callers waiting at the same time share one."""
        generation = self.generation
        async with self.lock:
            if generation == self.generation:
                self.generation += 1
                try:
                    await self._handshake()
                except ValueError:
                    self.reset(True)
                    self._note("the controller sent a malformed relay answer; the Web UI passes straight through")
        return self.mode

    async def _handshake(self):
        companion, pairing = self.companion, await offload(self.companion.store.pairing)
        if companion.controller is None:
            return
        if pairing is None:
            self.reset()
            return
        url = companion.base_url() + PATH
        status, reply = await companion.controller_request("GET", url)
        if status is None:
            return  # Unreachable: keep what we have and try again when it announces itself.
        if status == 404 and reply.get("error") == "COMPANION_NOT_PAIRED":
            await self._prove(url, pairing["secret"], bytes(16))  # Only to learn whether it forgot us.
        elif status != 200 or reply.get("protocol") != PROTOCOL:
            self.reset(True)  # A controller without the relay: everything as before, link included.
            self._note("the controller has no relay; the Web UI passes straight through, one screen at a time"
                       if status in (200, 404) else
                       f"the relay handshake answered HTTP {status}; the Web UI passes straight through")
        else:
            await self._prove(url, pairing["secret"], crypto.unb64(reply.get("challenge"), 16))

    async def _prove(self, url, secret, challenge):
        companion, nonce = self.companion, os.urandom(16)
        proof = crypto.mac(secret, b"R", challenge, nonce)
        status, reply = await companion.controller_request(
            "POST", url, {"id": companion.id, "nonce": crypto.b64(nonce), "mac": crypto.b64(proof)})
        if status is None:
            return
        if status == 200:
            if not hmac.compare_digest(crypto.unb64(reply.get("mac"), 32), crypto.mac(secret, b"Q", challenge, nonce)):
                self.reset()
                self._note("the controller did not prove the pairing secret; the Web UI passes straight through")
                return
            key = crypto.relay_key(secret, challenge, nonce)
            self.key, self.body_key, self.counter = key, crypto.relay_body_key(key), 0
            self.mode = "disabled" if reply.get("ui") is False else "ready"
            self._set_link(reply.get("link") is True)
            await companion.recognized()
            self._note("relay ready: every screen shares the controller's Web UI" if self.mode == "ready" else
                       "the controller turned the Web UI through the companion off")
        elif status == 404 and reply.get("error") == "COMPANION_NOT_PAIRED":
            erase = reply.get("erase")
            if erase and hmac.compare_digest(crypto.unb64(erase, 32), crypto.mac(secret, b"E", nonce)):
                self.reset()
                await companion.erase("the controller forgot this companion")
            else:
                self.reset()
                companion.not_recognized()
        else:
            self.reset()
            self._note(f"the controller refused the relay: HTTP {status} {reply.get('error') or ''}".strip())

    # --- Requests --------------------------------------------------------------
    def admit(self, method, uri, addr, screen, session=""):
        """Allocate q and build the header with the session sealed for it.

        Returns (header, q, sealed session or ""), or (None, 0, "") when the
        session needs a new handshake first.
        """
        if self.key is None or self.body_key is None or self.counter >= COUNTER_MAX:
            return None, 0, ""
        self.counter += 1
        q = self.counter
        sealed = "" if session == "" else crypto.b64(
            crypto.relay_seal(self.body_key, CTX_SESSION, q, session.encode()))
        tag = crypto.relay_tag(self.key, method, uri, q, addr, screen, sealed)
        return f"2 {q} {addr} {screen} {tag}", q, sealed

    def header(self, method, uri, addr, screen, session=""):
        """The signed X-OBBW-Relay value; None when the session needs a new handshake first."""
        return self.admit(method, uri, addr, screen, session)[0]

    async def signed(self, method, uri, addr, screen, session=""):
        value = self.header(method, uri, addr, screen, session)
        if value is None and self.mode != "disabled":
            await self.handshake()
            value = self.header(method, uri, addr, screen, session) if self.mode == "ready" else None
        return value

    async def sealed(self, method, uri, addr, screen, session=""):
        """`signed`, keeping the q and the sealed session that belong to it."""
        value, q, sealed_session = self.admit(method, uri, addr, screen, session)
        if value is None and self.mode != "disabled":
            await self.handshake()
            if self.mode == "ready":
                value, q, sealed_session = self.admit(method, uri, addr, screen, session)
        return value, q, sealed_session

    @staticmethod
    def forwarded(incoming, client=None):
        """The whitelisted request headers; `client` replaces the browser's X-WebUI-Client."""
        headers = {name: incoming[name] for name in FORWARDED if name in incoming}
        client = client or incoming.get("X-WebUI-Client")
        if client:
            headers["X-WebUI-Client"] = client
        return headers

    async def request(self, method, uri, incoming, body, addr, screen, rewrite):
        """One relayed request, sealed and signed, retried once after RELAY_STALE (no handler ran then).

        Returns the open response with `data` set to its whole body when it is a small
        JSON answer (None otherwise: the caller streams it), or None without a relay session.
        """
        for attempt in (0, 1):
            session = incoming.get("X-WebUI-Session", "")
            value, q, sealed_session = await self.sealed(method, uri, addr, screen, session)
            if value is None:
                return None
            headers = self.forwarded(incoming, self.client_id if rewrite else None)
            if sealed_session:
                headers["X-WebUI-Session"] = sealed_session
            if headers.get("X-Device-Password"):
                headers["X-Device-Password"] = crypto.b64(
                    crypto.relay_seal(self.body_key, CTX_PASSWORD, q,
                                      headers["X-Device-Password"].encode()))
            headers["X-OBBW-Relay"] = value
            sealed_body = body and crypto.relay_seal(self.body_key, CTX_BODY, q, body)
            reply = await self._send(method, uri, headers, sealed_body)
            if reply.data is not None and reply.status == 401 and attempt == 0 and _error(reply.data) == "RELAY_STALE":
                reply.release()
                self.key, self.body_key = None, None
                continue
            await self._open(reply)
            return reply

    async def _open(self, reply):
        """Open a sealed answer; a seal that does not open is never delivered."""
        counter = reply.headers.get(SEALED_RESPONSE_HEADER)
        if counter is None:
            return
        sealed = reply.data if reply.data is not None else (
            await reply.read() if (reply.content_length or 0) <= READ_LIMIT else None)
        reply.release()
        try:
            reply.data = crypto.relay_open(self.body_key, int(counter), sealed)
        except (InvalidTag, ValueError, TypeError):
            log("the controller's sealed answer did not open; starting a new relay session")
            self.key, self.body_key = None, None  # The next request makes a new session.
            raise aiohttp.ClientResponseError(reply.request_info, (), status=502,
                                              message="the sealed answer did not open")

    async def passthrough(self, method, uri, incoming, body):
        """Today's transparent proxy: the browser's own id, nothing signed."""
        return await self._send(method, uri, self.forwarded(incoming), body)

    async def _send(self, method, uri, headers, body):
        reply = await self.session().request(
            method, URL(self.companion.base_url() + uri, encoded=True), headers=headers, data=body or None,
            allow_redirects=False, skip_auto_headers=("User-Agent", "Accept", "Accept-Encoding"))
        reply.data = None
        if reply.content_type == "application/json" and (reply.content_length or 0) <= READ_LIMIT and not any(
                name in reply.headers for name in ("Content-Encoding", "Content-Disposition")):
            reply.data = await reply.read()
        return reply


def _error(data):
    try:
        value = json.loads(data)
    except ValueError:
        return None
    return value.get("error") if isinstance(value, dict) else None


def response_headers(reply):
    return [(name, value) for name, value in reply.headers.items()
            if name.lower() not in HOP_BY_HOP and name != SEALED_RESPONSE_HEADER]
