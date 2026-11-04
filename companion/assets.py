"""The Web UI's files, verified: what the browser runs under the companion's trusted origin.

Files reach the companion from the controller over plain HTTP, where a device on the network could
change them, so nginx never fetches them itself. Here each one is checked against the list of hashes
the controller sends sealed under the pairing, its headers come from that list, and anything not on
it goes to the Web UI. nginx keeps its cache in front, so only misses arrive. With no list yet, or
with the controller off, the answer is an error that lets nginx serve its last verified copy.

Before pairing there is nothing to check against, so no file is served: everything leads to the
companion's pairing page, and a service worker from an earlier pairing removes itself. A controller
from before the list keeps working unverified, which Diagnostic says.
"""

import asyncio
import base64
import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import aiohttp
from aiohttp import web
from cryptography.exceptions import InvalidTag
from multidict import CIMultiDict
from yarl import URL

from . import log
from .relay import NO_ADDRESS, read_capped

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .service import Companion

LIST_PATH = "/api/v1/companion/assets"
LIST_VERSION = 1
PAIRING_PAGE = "/__companion/?pair=1"
MAX_PLAIN_BYTES = 1 << 20  # Far above any file the controller serves; only unverified ones read it.
FETCHES = 2  # At once, for every screen: the controller's sockets are few.
FETCH_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=5)
SHELL_CONTROL = "public, max-age=86400, stale-if-error=604800"
IMMUTABLE_CONTROL = "public, max-age=31536000, immutable"
# A worker's update fetch bypasses the worker itself, so this reaches any worker left behind.
UNREGISTER = b"self.registration.unregister();\n"
NOT_VERIFIED = (
    "The Web UI's files could not be verified, so they were not opened. Something on your network "
    "may be changing them. Do not sign in until this goes away.\n"
)
# What passes from a controller nothing can be checked against.
PLAIN_HEADERS = frozenset(
    {
        "cache-control",
        "content-encoding",
        "content-security-policy",
        "content-type",
        "etag",
        "vary",
        "x-content-type-options",
        "x-frame-options",
    }
)


@dataclass(frozen=True)
class Row:
    """One file, as the list names it. `path` ends in `*` for a prefix."""

    path: str
    digest: bytes
    length: int
    content_type: str
    gzip: bool


@dataclass(frozen=True)
class Listing:
    tag: str
    etag: str
    csp: str
    shell: Row
    shell_paths: frozenset[str]
    rows: tuple[Row, ...]

    def row(self, path: str) -> Row | None:
        if path in self.shell_paths:
            return self.shell
        for row in self.rows:
            if row.path == path or (row.path[-1] == "*" and path.startswith(row.path[:-1])):
                return row
        return None


def _digest(text: object) -> bytes:
    if not isinstance(text, str):
        raise TypeError
    digest = base64.b64decode(text, validate=True)
    if len(digest) != hashlib.sha256().digest_size:
        raise ValueError
    return digest


def _row(item: object) -> Row:
    if not isinstance(item, list) or len(item) != 5:
        raise ValueError
    path, digest, length, content_type, gzip = cast("list[object]", item)
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or type(length) is not int
        or length < 0
        or not isinstance(content_type, str)
        or type(gzip) is not bool
    ):
        raise ValueError
    return Row(path, _digest(digest), length, content_type, gzip)


def parse_listing(data: bytes) -> Listing:
    """The controller's list; ValueError or TypeError for anything else, an answer swapped in by
    someone in the middle included."""
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError
    fields = cast("dict[str, object]", value)
    tag, etag, csp, shell = fields["tag"], fields["etag"], fields["csp"], fields["shell"]
    paths, rows = fields["shellPaths"], fields["assets"]
    if (
        fields["v"] != LIST_VERSION
        or not isinstance(tag, str)
        or not isinstance(etag, str)
        or not isinstance(csp, str)
        or not isinstance(shell, list)
        or len(shell) != 2
        or type(shell[1]) is not int
        or not isinstance(paths, list)
        or not isinstance(rows, list)
    ):
        raise ValueError
    shell_paths = cast("list[object]", paths)
    if not all(isinstance(path, str) for path in shell_paths):
        raise ValueError
    return Listing(
        tag,
        etag,
        csp,
        Row("/", _digest(shell[0]), shell[1], "text/html; charset=utf-8", True),
        frozenset(cast("list[str]", shell_paths)),
        tuple(_row(item) for item in cast("list[object]", rows)),
    )


def _matches(headers: Mapping[str, str], etag: str) -> bool:
    return etag in (tag.strip() for tag in headers.get("If-None-Match", "").split(","))


class Assets:
    def __init__(self, companion: Companion) -> None:
        self.companion = companion
        self.relay = companion.relay
        self.listing: Listing | None = None
        self.listed_under: bytes | None = None
        self.loading = asyncio.Lock()
        self.slots = asyncio.Semaphore(FETCHES)
        self.fetching: dict[bytes, asyncio.Task[bytes | None]] = {}
        self.verified = self.refused = 0
        self.last_refused: str | None = None
        self.warned = False

    def facts(self) -> dict[str, object]:
        """For Diagnostic: whether this screen's files were verified."""
        return {
            "verified": self.verified,
            "refused": self.refused,
            "lastPath": self.last_refused,
            "legacy": self.relay.features == 0,
        }

    # --- The list ------------------------------------------------------------------------
    async def _current(self) -> Listing | None:
        """The list of the running firmware. A relay session ends with the boot, so one read under
        this session stands for all of it; with no answer, the last one stands, and whatever it no
        longer describes fails its hash."""
        async with self.loading:
            key = self.relay.body_key
            if self.listing is not None and key is not None and self.listed_under is key:
                return self.listing
            try:
                reply = await self.relay.request(
                    "GET", LIST_PATH, {}, b"", NO_ADDRESS, self.relay.client_id, False
                )
                if reply is None:
                    return self.listing
                try:
                    if reply.status != 200 or reply.data is None:
                        return self.listing
                    self.listing = parse_listing(reply.data)
                    self.listed_under = self.relay.body_key
                finally:
                    reply.release()
            except aiohttp.ClientError, TimeoutError, OSError:
                return self.listing
            except KeyError, ValueError, TypeError, InvalidTag:
                log("the controller's list of Web UI files could not be read")
                return self.listing
            return self.listing

    # --- Fetching ------------------------------------------------------------------------
    async def _download(self, row: Row) -> bytes | None:
        path = "/" if row.path == "/" else row.path.removesuffix("*")
        async with self.slots:
            try:
                async with self.relay.session().get(
                    URL(self.companion.base_url() + path, encoded=True),
                    allow_redirects=False,
                    timeout=FETCH_TIMEOUT,
                ) as reply:
                    return await read_capped(reply, row.length) if reply.status == 200 else None
            except aiohttp.ClientError, TimeoutError, OSError:
                return None
            except ValueError:  # Longer than the list says: the hash could not match.
                return b""

    async def _fetch(self, row: Row) -> bytes | None:
        """One download per file, whoever asks; a screen that leaves does not end it for others."""
        task = self.fetching.get(row.digest)
        if task is None:
            task = asyncio.create_task(self._download(row))
            self.fetching[row.digest] = task
            task.add_done_callback(lambda _: self.fetching.pop(row.digest, None))
        return await asyncio.shield(task)

    # --- Answers -------------------------------------------------------------------------
    async def serve(self, request: web.Request) -> web.StreamResponse:
        path = request.path
        if path.startswith(("/__companion", "/api/")):
            raise web.HTTPNotFound
        if request.method not in ("GET", "HEAD"):
            raise web.HTTPMethodNotAllowed(request.method, ["GET", "HEAD"])
        required = self.companion.pairing_required()
        if request.headers.get("Service-Worker") == "script" and (required or path != "/sw.js"):
            return web.Response(
                body=UNREGISTER,
                content_type="text/javascript",
                headers={"Cache-Control": "no-store", "Service-Worker-Allowed": "/"},
            )
        if required:
            raise web.HTTPFound(PAIRING_PAGE, headers={"Cache-Control": "no-store"})
        if self.relay.mode == "disabled":
            return self._unavailable()
        if self.relay.features is None:
            await self.relay.renew()
        if self.relay.features == 0:
            return await self._plain(request)
        listing = await self._current()
        return self._unavailable() if listing is None else await self._verified(request, listing)

    @staticmethod
    def _unavailable() -> web.Response:
        """nginx answers this with its last verified copy, when it has one."""
        return web.Response(
            status=503,
            text="The controller is not answering.",
            headers={"Cache-Control": "no-store"},
        )

    async def _verified(self, request: web.Request, listing: Listing) -> web.StreamResponse:
        path = request.path
        row = listing.row(path)
        if row is None:
            raise web.HTTPFound("/")
        headers = self._headers(request, listing, row)
        etag = headers.get("ETag")
        if etag is not None and _matches(request.headers, etag):
            return web.Response(status=304, headers=headers)
        body = await self._fetch(row)
        if body is None:
            return self._unavailable()
        if hashlib.sha256(body).digest() != row.digest:
            # Perhaps an update changed it: a new session brings a new list, once.
            self.listed_under = None
            fresh = await self._current()
            again = fresh.row(path) if fresh is not None else None
            if fresh is None or again is None or again == row:
                return self._refuse(path)
            body = await self._fetch(again)
            if body is None or hashlib.sha256(body).digest() != again.digest:
                return self._refuse(path)
            listing, row = fresh, again
            headers = self._headers(request, listing, row)
        self.verified += 1
        return web.Response(body=body, headers=headers)

    def _refuse(self, path: str) -> web.Response:
        self.refused += 1
        self.last_refused = path
        log(f"refused {path}: it does not match the controller's list of Web UI files")
        return web.Response(status=502, text=NOT_VERIFIED, headers={"Cache-Control": "no-store"})

    @staticmethod
    def _headers(request: web.Request, listing: Listing, row: Row) -> CIMultiDict[str]:
        """Everything a browser acts on comes from the list, never from the wire. The cache rules
        are the firmware's: only the URL naming these exact bytes is immutable."""
        headers: CIMultiDict[str] = CIMultiDict(
            {
                "Content-Type": row.content_type,
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            }
        )
        if row.gzip:
            headers["Content-Encoding"] = "gzip"
            headers["Vary"] = "Accept-Encoding"
        if row is listing.shell or row.path == "/sw.js":
            # Checked on each load, at most every second or two.
            headers["X-Accel-Expires"] = "1"
            headers["ETag"] = listing.etag
            headers["Cache-Control"] = SHELL_CONTROL if row is listing.shell else "no-cache"
        elif request.query_string == f"v={listing.tag}":
            headers["ETag"] = f'"{listing.tag}"'
            headers["Cache-Control"] = IMMUTABLE_CONTROL
        else:
            headers["Cache-Control"] = "no-store"
        if row is listing.shell:
            headers["Content-Security-Policy"] = listing.csp
        return headers

    async def _plain(self, request: web.Request) -> web.StreamResponse:
        """A paired controller from before the list: only known headers pass."""
        if not self.warned:
            self.warned = True
            log("the Web UI's files are not verified: update the controller's firmware")
        forwarded = (
            {"If-None-Match": request.headers["If-None-Match"]}
            if "If-None-Match" in request.headers
            else {}
        )
        try:
            async with (
                self.slots,
                self.relay.session().get(
                    URL(self.companion.base_url() + request.raw_path, encoded=True),
                    headers=forwarded,
                    allow_redirects=False,
                    timeout=FETCH_TIMEOUT,
                ) as reply,
            ):
                body = await read_capped(reply, MAX_PLAIN_BYTES)
                status = reply.status
                kept = CIMultiDict(
                    (name, value)
                    for name, value in reply.headers.items()
                    if name.lower() in PLAIN_HEADERS
                )
                location = reply.headers.get("Location", "")
        except aiohttp.ClientError, TimeoutError, OSError, ValueError:
            return self._unavailable()
        if location.startswith("/") and not location.startswith("//"):
            kept["Location"] = location
        if kept.get("Content-Type", "").startswith("text/html") or request.path == "/sw.js":
            kept["X-Accel-Expires"] = "1"
        return web.Response(status=status, body=body, headers=kept)
