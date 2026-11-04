"""The companion's secrets: one JSON file each in <data>/secrets (0700), files 0600.

Nothing here is ever logged. The pairing key and id are independent of the
HTTPS gateway's certificate authority, so a hostname change keeps the pairing.
"""

import asyncio
import concurrent.futures
import functools
import json
import os
import uuid
from typing import TYPE_CHECKING, TypedDict, cast

from . import crypto

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from cryptography.hazmat.primitives.asymmetric import ec

# One disk thread for every secret-store call from the event loop: the loop
# never waits on the filesystem, and writes stay ordered because they share
# the single worker. It is never the loop's default executor, which aiohttp
# uses for name resolution.
_DISK = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="obbw-disk")


async def offload[*Ts, R](work: Callable[[*Ts], R], *args: *Ts) -> R:
    return await asyncio.get_running_loop().run_in_executor(_DISK, functools.partial(work, *args))


IDENTITY, PAIRING, CREDENTIALS, INSTALLATION = "identity", "pairing", "credentials", "lamarzocco"


# What each file holds, as the methods below write it.
class Identity(TypedDict):
    id: str
    key: str  # The P-256 scalar, hex.


class SavedPairing(TypedDict):
    secret: str  # base64
    controller: str


class Pairing(TypedDict):
    secret: bytes
    controller: str


class Account(TypedDict):
    email: str
    password: str
    serial: str


class Credentials(Account):
    gen: int


class Installation(TypedDict):
    key: str  # The P-256 scalar, hex.
    registered: bool


class Store:
    def __init__(self, data: Path) -> None:
        self.dir = data / "secrets"

    def _path(self, name: str) -> Path:
        return self.dir / f"{name}.json"

    def read(self, name: str) -> object:
        """The file's JSON value, or None when it is missing or unreadable."""
        try:
            return json.loads(self._path(name).read_text())
        except OSError, ValueError:
            return None

    def write(self, name: str, value: Mapping[str, object] | list[object]) -> None:
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.dir.chmod(0o700)
        temporary = self.dir / f".{name}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w") as file:
            json.dump(value, file)
            file.flush()
            os.fsync(file.fileno())
        temporary.replace(self._path(name))

    def delete(self, *names: str) -> None:
        for name in names:
            self._path(name).unlink(missing_ok=True)

    def identity(self) -> tuple[str, ec.EllipticCurvePrivateKey]:
        """The companion's id and long-lived P-256 pairing key, created once."""
        saved = cast("Identity | None", self.read(IDENTITY))
        if not saved:
            saved = {"id": str(uuid.uuid4()), "key": crypto.scalar(crypto.new_key()).hex()}
            self.write(IDENTITY, saved)
        return saved["id"], crypto.load_key(bytes.fromhex(saved["key"]))

    def pairing(self) -> Pairing | None:
        saved = cast("SavedPairing | None", self.read(PAIRING))
        return {**saved, "secret": crypto.unb64(saved["secret"], 32)} if saved else None

    def save_pairing(self, secret: bytes, controller: str) -> None:
        self.write(PAIRING, {"secret": crypto.b64(secret), "controller": controller})

    def credentials(self) -> Credentials | None:
        return cast("Credentials | None", self.read(CREDENTIALS))

    def save_credentials(self, generation: int, account: Account) -> None:
        self.write(CREDENTIALS, {"gen": generation, **account})

    def installation_key(self) -> tuple[ec.EllipticCurvePrivateKey, bool]:
        """The La Marzocco installation key, created once and kept until the pairing is erased."""
        saved = cast("Installation | None", self.read(INSTALLATION))
        if not saved:
            saved = {"key": crypto.scalar(crypto.new_key()).hex(), "registered": False}
            self.write(INSTALLATION, saved)
        return crypto.load_key(bytes.fromhex(saved["key"])), saved["registered"]

    def installation_registered(self) -> None:
        # Only after installation_key: the file is there.
        self.write(
            INSTALLATION, {**cast("Installation", self.read(INSTALLATION)), "registered": True}
        )

    def erase_account(self) -> None:
        """The account only: the installation stays, so turning La Marzocco on again adds none to
        the account."""
        self.delete(CREDENTIALS)

    def erase_pairing(self) -> None:
        self.delete(PAIRING, CREDENTIALS, INSTALLATION)
