"""Open Brew by Weight Companion: pairing, the controller link and the La Marzocco offload."""

import logging
import logging.handlers
import os
import queue
import re
import sys

RELEASE = "1.0.0"
# The image carries the commit it was built from (Docker build argument
# COMPANION_COMMIT, set by ./setup), shown as 1.0.0+<commit> like the firmware.
_COMMIT = re.sub(r"[^0-9a-z-]", "", os.environ.get("COMPANION_COMMIT", "").lower())[:16]
VERSION = RELEASE + ("+" + _COMMIT if _COMMIT else "")
PROTOCOL = 1

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
_listener = None

logger = _ROOT.getChild("companion")
gateway_logger = _ROOT.getChild("gateway")


def configure_logging(data, max_bytes=512 * 1024, backups=8):
    """Persist the log under <data>/log, written by a background thread.

    Called once on the supervisor, after the check/scan/mdns-check dispatch:
    the healthcheck process must not share the rotating file, and scan's
    stdout stays parseable by ./setup.
    """
    global _listener
    if _listener is not None:
        return
    handlers = [_stdout]
    try:
        (data / "log").mkdir(mode=0o700, parents=True, exist_ok=True)
        file = logging.handlers.RotatingFileHandler(data / "log" / "companion.log",
                                                   maxBytes=max_bytes, backupCount=backups)
        file.setFormatter(logging.Formatter(_FORMAT, _DATEFMT))
        handlers.append(file)
    except OSError as error:
        _ROOT.warning("obbw.setup: no persistent log under %s (%s); stdout only", data, error)
        return
    _listener = logging.handlers.QueueListener(queue.SimpleQueue(), *handlers)
    _ROOT.addHandler(logging.handlers.QueueHandler(_listener.queue))
    _ROOT.removeHandler(_stdout)
    _listener.start()


def stop_logging():
    """Flush the queue and hand stdout back for the way down."""
    global _listener
    if _listener is not None:
        _listener.stop()
        _listener = None
        _ROOT.addHandler(_stdout)


def log(message):
    logger.info("%s", message)


def clip(text, limit=120):
    """A one-line, trimmed excerpt for log lines: exception messages and error bodies."""
    line = " ".join(str(text).split())
    return line[:limit] + "…" if len(line) > limit else line
