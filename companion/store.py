"""The companion's secrets: one JSON file each in <data>/secrets (0700), files 0600.

Nothing here is ever logged. The pairing key and id are independent of the
HTTPS gateway's certificate authority, so a hostname change keeps the pairing.
"""

import json
import os
import uuid

from . import crypto

IDENTITY, PAIRING, CREDENTIALS, INSTALLATION = "identity", "pairing", "credentials", "lamarzocco"


class Store:
    def __init__(self, data):
        self.dir = data / "secrets"

    def _path(self, name):
        return self.dir / f"{name}.json"

    def read(self, name):
        try:
            return json.loads(self._path(name).read_text())
        except (OSError, ValueError):
            return None

    def write(self, name, value):
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.dir.chmod(0o700)
        temporary = self.dir / f".{name}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w") as file:
            json.dump(value, file)
            file.flush()
            os.fsync(file.fileno())
        temporary.replace(self._path(name))

    def delete(self, *names):
        for name in names:
            self._path(name).unlink(missing_ok=True)

    def identity(self):
        """The companion's id and long-lived P-256 pairing key, created once."""
        saved = self.read(IDENTITY)
        if not saved:
            saved = {"id": str(uuid.uuid4()), "key": crypto.scalar(crypto.new_key()).hex()}
            self.write(IDENTITY, saved)
        return saved["id"], crypto.load_key(bytes.fromhex(saved["key"]))

    def pairing(self):
        saved = self.read(PAIRING)
        return {**saved, "secret": crypto.unb64(saved["secret"], 32)} if saved else None

    def save_pairing(self, secret, controller):
        self.write(PAIRING, {"secret": crypto.b64(secret), "controller": controller})

    def credentials(self):
        return self.read(CREDENTIALS)

    def save_credentials(self, generation, account):
        self.write(CREDENTIALS, {"gen": generation, **account})

    def installation_key(self):
        """The La Marzocco installation key, created once and reused until the account is erased."""
        saved = self.read(INSTALLATION)
        if not saved:
            saved = {"key": crypto.scalar(crypto.new_key()).hex(), "registered": False}
            self.write(INSTALLATION, saved)
        return crypto.load_key(bytes.fromhex(saved["key"])), saved["registered"]

    def installation_registered(self):
        self.write(INSTALLATION, {**self.read(INSTALLATION), "registered": True})

    def erase_account(self):
        self.delete(CREDENTIALS, INSTALLATION)

    def erase_pairing(self):
        self.delete(PAIRING, CREDENTIALS, INSTALLATION)
