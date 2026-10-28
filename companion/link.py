"""Companion link v1: the opening handshake and the signed frame codec."""

import asyncio
import hashlib
import hmac
import json
import os
import socket

import aiohttp

from . import PROTOCOL, crypto

MAX_FRAME = 4096
STEP_TIMEOUT_S = 10
# A ping the controller has not acknowledged within this time closes the link: the controller sends
# nothing on its own, so this finds a half-open link at the next ping without any extra traffic.
ACK_TIMEOUT_S = 30


class LinkClosed(Exception):
    """The link failed or the controller refused it; `code` is the reason shown on the status page."""

    def __init__(self, code, detail=""):
        super().__init__(f"{code} {detail}".strip())
        self.code = code


class Erased(Exception):
    """The controller forgot this companion and proved it with the pairing secret."""


class FrameCodec:
    """`<mac>.<json>` frames with a per-direction sequence that starts at 1 and grows by one."""

    def __init__(self, key, send=b"c", receive=b"f"):
        self.key, self.send_dir, self.receive_dir = key, send, receive
        self.sent = self.received = 0

    def _tag(self, direction, body):
        return hmac.new(self.key, direction + body.encode(), hashlib.sha256).hexdigest()[:32]

    def encode(self, frame):
        body = json.dumps({"q": self.sent + 1, **frame}, separators=(",", ":"))
        text = f"{self._tag(self.send_dir, body)}.{body}"
        if len(text) > MAX_FRAME:
            raise ValueError(f"{frame.get('t')} frame of {len(text)} bytes exceeds {MAX_FRAME}")
        self.sent += 1
        return text

    def decode(self, text):
        tag, dot, body = text.partition(".")
        if len(text.encode()) > MAX_FRAME or not dot or not hmac.compare_digest(tag, self._tag(self.receive_dir, body)):
            raise LinkClosed("PROTOCOL", "frame failed its MAC check")
        try:
            frame = json.loads(body)
        except ValueError:
            raise LinkClosed("PROTOCOL", "malformed frame") from None
        if not isinstance(frame, dict) or type(frame.get("q")) is not int or frame["q"] != self.received + 1:
            raise LinkClosed("PROTOCOL", "frame out of sequence")
        self.received += 1
        return frame


async def _receive(ws):
    message = await ws.receive(timeout=STEP_TIMEOUT_S)
    if message.type is not aiohttp.WSMsgType.TEXT:
        raise LinkClosed("CLOSED", "the controller closed the link while opening it")
    try:
        reply = json.loads(message.data)
    except ValueError:
        reply = None
    if not isinstance(reply, dict):
        raise LinkClosed("PROTOCOL", "malformed opening frame")
    return reply


async def open_link(http, url, hello, secret):
    """Open and authenticate the link; returns (websocket, codec), or raises LinkClosed or Erased."""
    try:
        ws = await http.ws_connect(url, autoping=True, max_msg_size=MAX_FRAME,
                                   timeout=aiohttp.ClientWSTimeout(ws_close=STEP_TIMEOUT_S))
    except aiohttp.WSServerHandshakeError as error:
        raise LinkClosed("NOT_PAIRED" if error.status == 404 else f"HTTP_{error.status}") from None
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as error:
        raise LinkClosed("UNREACHABLE", type(error).__name__) from None
    try:
        ws.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, ACK_TIMEOUT_S * 1000)
        nc = os.urandom(16)
        await ws.send_str(json.dumps({"t": "hello", **hello, "protocol": PROTOCOL, "nonce": crypto.b64(nc)}))
        reply = await _receive(ws)
        if reply.get("t") == "erase":
            if hmac.compare_digest(crypto.unb64(reply.get("mac"), 32), crypto.mac(secret, b"E", nc)):
                raise Erased()
            raise LinkClosed("AUTH", "erase failed its MAC check")
        if reply.get("t") == "error":
            code = str(reply.get("code") or "ERROR")
            raise LinkClosed("VERSION" if code == "PROTOCOL" else code)
        if reply.get("t") != "challenge":
            raise LinkClosed("PROTOCOL", "expected a challenge")
        ns = crypto.unb64(reply.get("nonce"), 16)
        await ws.send_str(json.dumps({"t": "proof", "mac": crypto.b64(crypto.mac(secret, b"C", nc, ns))}))
        ready = await _receive(ws)
        if ready.get("t") != "ready" or not hmac.compare_digest(
                crypto.unb64(ready.get("mac"), 32), crypto.mac(secret, b"F", nc, ns)):
            raise LinkClosed("AUTH", "the controller did not prove the pairing secret")
        return ws, FrameCodec(crypto.session_key(secret, nc, ns))
    except ValueError:
        await ws.close()
        raise LinkClosed("PROTOCOL", "malformed opening field") from None
    except (asyncio.TimeoutError, aiohttp.ClientError, ConnectionError):
        await ws.close()
        raise LinkClosed("CLOSED", "the link failed while opening") from None
    except BaseException:
        await ws.close()
        raise
