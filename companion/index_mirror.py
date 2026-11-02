"""The controller's record index as the archive last received it, rebuilt from deltas and checked by `sum`.

The controller's index answers to the link's `rx` (the firmware's
docs/COMPANION_LINK.md, "Record index") list `[id, revision]` pairs newest
first, ids descending, and every listed answer carries `sum`: the CRC-32 of
the whole index as little-endian u32 id, u32 revision pairs. Once the current
link session answered, a request from the epoch this mirror holds may ask
for a delta (`base`, `up`, `del`) instead
of the whole index. Anything this mirror cannot rebuild exactly clears it, so
the next ask is for the whole index.

One mirror per store; the controller keeps a baseline for each. The mirror
lives in memory only.
"""

import struct
import zlib

from . import log

U32 = 0xFFFFFFFF


def _values(values, width):
    if not isinstance(values, list) or len(values) % width or \
            not all(type(value) is int and 0 <= value <= U32 for value in values):
        raise ValueError("malformed")
    return values


def checksum(rows):
    """The controller's `sum` of a flat [id, revision, ...] index."""
    return zlib.crc32(struct.pack(f"<{len(rows)}I", *rows))


class IndexMirror:
    def __init__(self, name):
        self.name = name  # For the log: "archive's shots index".
        self.epoch, self.pairs, self.answered = 0, None, False

    def session(self):
        """A new upstream session: no delta until it answered with a listed index."""
        self.answered = False

    def delta(self, epoch):
        """Whether a request naming `epoch` may ask for a delta."""
        return self.answered and self.pairs is not None and epoch == self.epoch

    def clear(self, reason):
        log(f"the {self.name} did not match the controller's ({reason}); the whole index is asked next")
        self.epoch, self.pairs = 0, None

    def apply(self, frame):
        """The answer with the whole index in `rows`, an unchanged answer as it came, or None: the
        mirror could not rebuild a verified index and is cleared."""
        if "rows" not in frame and "base" not in frame:
            return frame
        total = frame.get("sum")
        try:
            if type(frame.get("epoch")) is not int or type(total) is not int:
                raise ValueError("malformed")
            if "base" in frame:
                if frame["base"] != self.epoch or self.pairs is None:
                    raise ValueError("another base")
                gone, up = set(_values(frame.get("del"), 1)), _values(frame.get("up"), 2)
                index = {rid: rev for rid, rev in self.pairs if rid not in gone}
                index.update(zip(up[0::2], up[1::2]))
                rows = [value for pair in sorted(index.items(), reverse=True) for value in pair]
            else:
                rows = _values(frame["rows"], 2)
            if checksum(rows) != total:
                raise ValueError("checksum")
        except ValueError as error:
            self.clear(error)
            return None
        self.epoch, self.pairs = frame["epoch"], list(zip(rows[0::2], rows[1::2]))
        self.answered = True
        return {**frame, "rows": rows}
