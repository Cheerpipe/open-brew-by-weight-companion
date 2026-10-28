"""Browser screens: the Web UI's API and live updates, relayed for every screen.

nginx sends `/api/` and `/api/v1/ui/ui-stream` here with the browser's
address in X-Real-IP. With a relay session every REST call goes signed, with
the companion's one client id for screens that claimed through it, and live
updates come from the multiplexer. Without one the companion is the plain
proxy it always was (one screen at a time); with the Web UI through the
companion turned off it refuses and names the direct address.
"""

import asyncio
import json

import aiohttp
from aiohttp import web
from multidict import CIMultiDict

from . import log
from .mux import Mux
from .relay import CLIENT_ID, address, response_headers
from .upstream import MAX_FRAME, PATH as STREAM, REQUEST_BYTES

CLAIM, LOGIN, COMPANION_ADMIN = "/api/v1/ui/claim", "/api/v1/auth/login", "/api/v1/companion/admin"
COMMAND_SETTLE_S = 10
CHUNK = 16 * 1024


def _error(status, code, message):
    return web.json_response({"error": code, "message": message}, status=status,
                             headers={"Cache-Control": "no-store"})


def _json(data):
    try:
        value = json.loads(data)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


class Screens:
    def __init__(self, companion, relay):
        self.companion, self.relay = companion, relay
        self.mux = Mux(companion, relay)
        # Mutations one at a time, in order, beside at most one read: two controller sockets at most.
        self.commands, self.reads = asyncio.Lock(), asyncio.Lock()

    def routes(self):
        return [web.get(STREAM, self.stream), web.route("*", "/api/{tail:.*}", self.api)]

    def _refusal(self):
        if self.companion.controller is None:
            return _error(503, "NO_CONTROLLER", "The companion has not found the controller yet")
        if self.relay.mode == "disabled":
            return _error(409, "COMPANION_UI_OFF", "The Web UI opens directly on the controller at "
                          + self.companion.base_url())
        return None

    # --- Live updates ------------------------------------------------------------------
    async def stream(self, request):
        refusal = self._refusal()
        if refusal is not None:
            return refusal
        if self.relay.mode != "ready":
            return await self._passthrough_stream(request)
        ws = web.WebSocketResponse(max_msg_size=REQUEST_BYTES, autoping=True)
        await ws.prepare(request)
        screen = self.mux.connect(ws, address(request.headers.get("X-Real-IP")))
        try:
            async for message in ws:
                if message.type is not aiohttp.WSMsgType.TEXT or screen.closed:
                    break
                self.mux.on_message(screen, message.data)
        finally:
            self.mux.disconnect(screen)
        return ws

    async def _passthrough_stream(self, request):
        """One browser, one controller session, exactly as without the companion."""
        host = self.companion.base_url().removeprefix("http://")
        try:
            upstream = await self.relay.session().ws_connect(
                self.companion.base_url("ws") + STREAM, headers={"Origin": f"http://{host}"}, autoping=True,
                max_msg_size=MAX_FRAME)
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            return _error(502, "CONTROLLER_UNREACHABLE", "The controller did not answer")
        ws = web.WebSocketResponse(max_msg_size=MAX_FRAME, autoping=True)
        await ws.prepare(request)

        async def pipe(source, target):
            async for message in source:
                if message.type is aiohttp.WSMsgType.TEXT:
                    await target.send_str(message.data)
                elif message.type is aiohttp.WSMsgType.BINARY:
                    await target.send_bytes(message.data)
                else:
                    return

        tasks = [asyncio.create_task(pipe(ws, upstream)), asyncio.create_task(pipe(upstream, ws))]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (aiohttp.ClientError, ConnectionError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            code = upstream.close_code
            await upstream.close()
            await ws.close(code=code if code and code >= 3000 else aiohttp.WSCloseCode.GOING_AWAY)
        return ws

    # --- REST ----------------------------------------------------------------------------
    async def api(self, request):
        refusal = self._refusal()
        if refusal is not None:
            return refusal
        body = await request.read()
        method, uri, path = request.method, request.raw_path, request.path
        client = request.headers.get("X-WebUI-Client", "")
        screen = client if CLIENT_ID.fullmatch(client) else None
        session_route = path == CLAIM or path.startswith("/api/v1/auth/")
        lane = self.reads if method in ("GET", "HEAD") or session_route else self.commands
        await lane.acquire()
        held = False
        try:
            if request.transport is None or request.transport.is_closing():
                return web.Response(status=499)  # The browser left while its request waited.
            rewrite = path in (CLAIM, LOGIN) or screen in self.mux.claimed
            try:
                reply = None
                if self.relay.mode == "ready":
                    reply = await self.relay.request(method, uri, request.headers, body,
                                                     address(request.headers.get("X-Real-IP")),
                                                     screen or self.relay.client_id, rewrite)
                if reply is None:
                    refusal = self._refusal()
                    if refusal is not None:
                        return refusal
                    reply = await self.relay.passthrough(method, uri, request.headers, body)
                    rewrite = False
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                return _error(502, "CONTROLLER_UNREACHABLE", "The controller did not answer")
            try:
                request_id = self._observe(path, screen, rewrite, reply)
                if reply.data is not None:
                    response = web.Response(status=reply.status, body=reply.data,
                                            headers=CIMultiDict(response_headers(reply)))
                    if request_id and lane is self.commands and self.mux.upstream.state == "open":
                        held = True  # The next mutation waits for this one's lastCommand.
                        self.companion.spawn(self._settle(lane, request_id))
                    return response
                response = web.StreamResponse(status=reply.status, headers=CIMultiDict(response_headers(reply)))
                if reply.content_length is not None:
                    response.content_length = reply.content_length
                await response.prepare(request)
                async for chunk in reply.content.iter_chunked(CHUNK):
                    await response.write(chunk)
                await response.write_eof()
                return response
            finally:
                reply.release()
        finally:
            if not held:
                lane.release()

    def _observe(self, path, screen, rewrite, reply):
        """Claims, takeovers and accepted commands as the controller answered them."""
        data = _json(reply.data) if reply.data is not None else {}
        if screen and reply.status == 200 and (path == CLAIM or (path == LOGIN and data.get("active") is True)):
            self.mux.claimed.add(screen)
        elif rewrite and reply.status == 409 and data.get("error") == "UI_TAKEN_OVER":
            self.mux.takeover()
        elif path == COMPANION_ADMIN and reply.status == 200:
            self.companion.spawn(self.relay.handshake())  # Its switches may have changed what it wants.
        request_id = data.get("requestId")
        if reply.status == 202 and isinstance(request_id, int) and not isinstance(request_id, bool):
            return request_id
        return None

    async def _settle(self, lane, request_id):
        try:
            if not await self.mux.command_done(request_id, COMMAND_SETTLE_S):
                log(f"command {request_id} did not settle within {COMMAND_SETTLE_S} s; the next one goes anyway")
        finally:
            lane.release()
