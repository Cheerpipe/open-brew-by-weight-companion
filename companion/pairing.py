"""Pairing client: one request per controller, polled about once a second while pending."""

import asyncio
import time

from . import PROTOCOL, VERSION, crypto, log

PATH = "/api/v1/companion/pair"
POLL_S = 1
REFUSALS = {"COMPANION_IGNORED": "ignored", "ALREADY_PAIRED": "already_paired", "PAIRING_BUSY": "busy",
            "PAIRING_RATE_LIMITED": "rate_limited"}


class Pairing:
    def __init__(self, companion):
        self.companion = companion
        self.state = "paired" if companion.store.pairing() else "unpaired"
        self.code = None
        self.expires_at = 0.0
        self.auto = True  # Entry point (a): one request on its own, until it is answered.
        self.task = None

    def status(self):
        status = {"state": self.state}
        if self.state == "pending":
            status.update(code=self.code, expiresInS=max(0, int(self.expires_at - time.monotonic())))
        return status

    def start(self, manual=False):
        """Send one request to the known controller (the Pair button sets manual); False if none was sent."""
        if self.companion.controller is None or (self.task and not self.task.done()):
            return False
        if not manual and (not self.auto or self.state != "unpaired"):
            return False
        self.auto = False
        self.task = self.companion.spawn(self._run())
        return True

    def _controller_key(self, reply):
        try:
            key = crypto.unb64(reply.get("controllerKey"), 65) if reply.get("controllerKey") else None
            if key:
                crypto.load_point(key)
        except ValueError:
            log("the controller sent an invalid pairing key; ignored")
            return None
        return key

    async def _run(self):
        companion, url = self.companion, self.companion.base_url() + PATH
        self.state, self.code, key = "requesting", None, None
        status, reply = await companion.controller_request("POST", url, {
            "id": companion.id, "name": companion.name, "version": VERSION, "protocol": PROTOCOL,
            "publicKey": crypto.b64(companion.public)})
        if status != 202:
            self.state = "unreachable" if status is None else REFUSALS.get(reply.get("error"), "error")
            self.auto = self.state in ("unreachable", "rate_limited")
            log("the controller did not answer the pairing request" if status is None else
                f"pairing request refused: HTTP {status} {reply.get('error') or ''}".strip())
            return
        self.state = "pending"
        self.expires_at = time.monotonic() + int(reply.get("expiresInS") or 600)
        log(f"pairing requested from {companion.controller[0]}; waiting for approval in Admin → Companion")
        while time.monotonic() < self.expires_at:
            if key is None and (key := self._controller_key(reply)):
                self.code = crypto.sas(companion.public, key)
            await asyncio.sleep(POLL_S)
            status, reply = await companion.controller_request("GET", f"{url}?id={companion.id}")
            state = reply.get("state") if status == 200 else "pending"
            if state == "pending":
                continue
            key = key or self._controller_key(reply)
            if state == "approved" and key:
                companion.paired(crypto.pairing_secret(companion.key, companion.public, key))
                self.state = "paired"
            else:
                self.state = "error" if state == "approved" else state if state in ("denied", "expired") \
                    else "expired"
            if self.state != "paired":
                log(f"pairing {self.state}")
            return
        self.state = "expired"
        log("pairing expired")
