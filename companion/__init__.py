"""Open Brew by Weight Companion: pairing, the controller link and the La Marzocco offload."""

import logging
import logging.handlers
import os
import queue
import re
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

RELEASE = "1.0.0"
# The image carries the commit it was built from (Docker build argument
# COMPANION_COMMIT, set by ./setup), shown as 1.0.0+<commit> like the firmware.
_COMMIT = re.sub(r"[^0-9a-z-]", "", os.environ.get("COMPANION_COMMIT", "").lower())[:16]
VERSION = RELEASE + ("+" + _COMMIT if _COMMIT else "")
# Pairing and the relay stay at 1, so a controller of another release still
# serves the Web UI through this companion (and its OTA); the link is 2.
PROTOCOL, LINK_PROTOCOL = 1, 2

# One logger for both processes' names, in the controller log's clock and
# shape so the two interleave. Until configure_logging runs, lines go straight
# to stdout; afterwards a listener thread owns stdout and the rotating file,
# so neither a full Docker pipe nor the disk can stall the event loop.
_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"
_ROOT = logging.getLogger("obbw")
_ROOT.setLevel(logging.INFO)
_ROOT.propagate = False
_stdout = logging.StreamHandler(sys.stdout)
_stdout.setFormatter(logging.Formatter(_FORMAT, _DATEFMT))
_ROOT.addHandler(_stdout)
# At most one: the running listener and the handler that feeds its queue.
_running: list[tuple[logging.handlers.QueueListener, logging.handlers.QueueHandler]] = []

logger = _ROOT.getChild("companion")


def configure_logging(data: Path, max_bytes: int = 512 * 1024, backups: int = 8) -> None:
    """Persist the log under <data>/log, written by a background thread.

    Called once on the supervisor, after the check/scan/mdns-check dispatch:
    the healthcheck process must not share the rotating file, and scan's
    stdout stays parseable by ./setup.
    """
    if _running:
        return
    handlers: list[logging.Handler] = [_stdout]
    try:
        (data / "log").mkdir(mode=0o700, parents=True, exist_ok=True)
        file = logging.handlers.RotatingFileHandler(
            data / "log" / "companion.log", maxBytes=max_bytes, backupCount=backups
        )
        file.setFormatter(logging.Formatter(_FORMAT, _DATEFMT))
        handlers.append(file)
    except OSError as error:
        _ROOT.warning("obbw.setup: no persistent log under %s (%s); stdout only", data, error)
        return
    listener = logging.handlers.QueueListener(queue.SimpleQueue(), *handlers)
    feed = logging.handlers.QueueHandler(listener.queue)
    _running.append((listener, feed))
    _ROOT.addHandler(feed)
    _ROOT.removeHandler(_stdout)
    listener.start()


def stop_logging() -> None:
    """Flush the queue, close the file and hand stdout back for the way down."""
    if _running:
        listener, feed = _running.pop()
        listener.stop()
        _ROOT.addHandler(_stdout)
        _ROOT.removeHandler(feed)
        for handler in listener.handlers:
            if handler is not _stdout:
                handler.close()


def log(message: str) -> None:
    logger.info("%s", message)


def clip(text: object, limit: int = 120) -> str:
    """A one-line, trimmed excerpt for log lines: exception messages and error bodies."""
    line = " ".join(str(text).split())
    return line[:limit] + "…" if len(line) > limit else line
