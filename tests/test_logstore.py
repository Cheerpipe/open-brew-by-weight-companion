#!/usr/bin/env python3
"""The log store on its own: paging across boots, retention, and the export chunks.

The link-level sync (subscribe, gaps, reset, adoption) is covered by
test_link.py; this checks what a session cannot reach. Offline, inside the
image (see the README).
"""

import asyncio
import sys
import tempfile
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from companion.logstore import LogStore  # noqa: E402

DEVICE = "AA:BB:CC:DD:EE:FF"


def event(sequence, wall=1789000000, level="i"):
    return [sequence, sequence * 100, wall, level, "state", f"event {sequence}"]


async def main():
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-logstore-") as temporary:
        store = LogStore(Path(temporary))
        await store.open()

        # Two boots; the page walks newest first with a boot marker between them.
        await store.apply(DEVICE, {"t": "log", "b": 7, "e": [event(1), event(2), event(3)]})
        await store.apply(DEVICE, {"t": "log", "b": 9, "e": [event(1), event(2)]})
        assert await store.cursor(DEVICE) == (9, 2)
        entries, following, more = await store.page(DEVICE, 2 ** 31, 2 ** 31, 10)
        kinds = [entry.get("s", entry.get("g")) for entry in entries]
        assert kinds == [2, 1, "boot", 3, 2, 1], kinds
        assert following is None and more is False
        # The boot marker survives a page boundary: page 2 continues mid-boot.
        entries, following, more = await store.page(DEVICE, 9, 1, 2)
        kinds = [entry.get("s", entry.get("g")) for entry in entries]
        assert kinds == ["boot", 3, 2], kinds
        assert following == (7, 2) and more is True

        # The export chunks oldest first, carrying each row's boot.
        first = await store.chunk(DEVICE, 0, 0)
        assert [row["s"] for row in first] == [1, 2, 3, 1, 2]
        assert [row["b"] for row in first] == [7, 7, 7, 9, 9]
        assert await store.chunk(DEVICE, 9, 2) == []

        # Age retention: the dated events of boots 7 and 9 are ~50 days old and
        # go; only events without a wall clock or from the future stay.
        await store.apply(DEVICE, {"t": "log", "b": 10, "e": [
            [1, 10, 0, "i", "state", "no clock yet"], [2, 20, 9999999999, "i", "state", "far future"]]})
        await store.prune(days=30, megabytes=50)
        entries, _, _ = await store.page(DEVICE, 2 ** 31, 2 ** 31, 100)
        assert [entry.get("s", entry.get("g")) for entry in entries if "s" in entry] == [2, 1], entries

        # Size retention: a 1 MB budget trims the oldest events away.
        sequence = 3
        for _ in range(130):
            await store.apply(DEVICE, {"t": "log", "b": 10, "e": [
                [batch + sequence, (batch + sequence) * 100, 9999999999, "d", "state",
                 "filler " * 8 + str(batch + sequence)] for batch in range(1, 101)]})
            sequence += 100
        assert (await store.stats())["bytes"] > 1048576, "the filler filled"
        deleted = await store.prune(days=3650, megabytes=1)
        assert deleted > 0
        stats = await store.stats()
        assert stats["bytes"] <= 1048576, stats
        cursor = await store.cursor(DEVICE)
        assert cursor is not None and cursor[0] == 10 and cursor[1] == sequence, \
            "the newest events survive the trim"

        await store.close()
    print("Companion log store: paging, boots, chunks and retention OK")


asyncio.run(main())
