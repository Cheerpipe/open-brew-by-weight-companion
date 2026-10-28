"""Open Brew by Weight Companion: pairing, the controller link and the La Marzocco offload."""

import os
import re

RELEASE = "1.0.0"
# The image carries the commit it was built from (Docker build argument
# COMPANION_COMMIT, set by ./setup), shown as 1.0.0+<commit> like the firmware.
_COMMIT = re.sub(r"[^0-9a-z-]", "", os.environ.get("COMPANION_COMMIT", "").lower())[:16]
VERSION = RELEASE + ("+" + _COMMIT if _COMMIT else "")
PROTOCOL = 1


def log(message):
    print(f"companion: {message}", flush=True)
