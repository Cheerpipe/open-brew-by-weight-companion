#!/usr/bin/env python3
"""The log store on its own: migration, paging and markers, export chunks,
retention, erase, backup and access grants.

The link-level sync (subscribe after `dev`, resume across a restart, failure
isolation, access through the controller) is covered by test_link.py; this
checks what a session cannot reach. Offline, inside the image (see the README).
"""

import asyncio
import sqlite3
import sys
import tempfile
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from companion.logstore import FIRST_PAGE, LogStore  # noqa: E402
from companion.store import offload  # noqa: E402

DEVICE, OTHER = "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"


def event(sequence, wall=1789000000, level="i", text=None):
    return [sequence, sequence * 100, wall, level, "state", text or f"event {sequence}"]


def kinds(entries):
    return [entry.get("s", entry.get("g")) for entry in entries]


async def sql(store, statement, *args):
    return await offload(lambda: [tuple(row) for row in store.connection.execute(statement, args)])


def version_1(path):
    """A store as the first companion release left it: gap after an event, reset at 0, a duplicate index."""
    connection = sqlite3.connect(path, isolation_level=None)
    connection.executescript("""
        create table log_events (device_id text not null, boot_id integer not null,
            sequence integer not null, at_ms integer not null, wall_sec integer not null,
            level text not null, category text not null, message text not null,
            primary key (device_id, boot_id, sequence)) without rowid;
        create table log_marks (device_id text not null, boot_id integer not null,
            after_sequence integer not null, kind text not null, count integer not null,
            noted real not null, primary key (device_id, boot_id, after_sequence)) without rowid;
        create index log_events_page on log_events (device_id, boot_id, sequence);
        pragma user_version = 1;
    """)
    for sequence in (1, 2, 3, 8):
        connection.execute("insert into log_events values (?, 7, ?, 0, 0, 'i', 'state', 'x')", (DEVICE, sequence))
    connection.execute("insert into log_marks values (?, 7, 3, 'gap', 4, 0)", (DEVICE,))
    connection.execute("insert into log_marks values (?, 7, 0, 'reset', 0, 0)", (DEVICE,))
    connection.execute("insert into log_marks values (?, 6, 9, 'gap', 2, 0)", (DEVICE,))  # Hidden in v1: dropped.
    connection.close()


async def main():
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-logstore-") as temporary:
        data = Path(temporary)

        # --- Version 1 migrates: marks re-anchored, the duplicate index gone --------
        version_1(data / "companion.db")
        store = LogStore(data)
        await store.open()
        assert await sql(store, "pragma user_version") == [(2,)]
        assert not await sql(store, "select name from sqlite_master where name = 'log_events_page'")
        entries, _, _ = await store.page(DEVICE, FIRST_PAGE, FIRST_PAGE, 10)
        assert kinds(entries) == [8, "gap", 3, 2, 1, "reset"], entries
        await store.erase()
        assert await store.device() is None
        await store.close()

        # --- A newer schema is refused, never relabeled -----------------------------
        newer = data / "newer"
        newer.mkdir()
        sqlite3.connect(newer / "companion.db").execute("pragma user_version = 9").connection.close()
        try:
            await LogStore(newer).open()
            raise AssertionError("a newer schema opened")
        except sqlite3.DatabaseError as error:
            assert "newer" in str(error)
        assert sqlite3.connect(newer / "companion.db").execute("pragma user_version").fetchone()[0] == 9

        store = LogStore(data)
        await store.open()
        await store.set_device(DEVICE)
        assert await store.device() == DEVICE

        # --- Two boots: a restart marker between them names the newer boot ----------
        await store.apply(DEVICE, {"b": 7, "e": [event(1), event(2), event(3)]})
        await store.apply(DEVICE, {"b": 9, "e": [event(1), event(2)]})
        assert await store.cursor(DEVICE) == (9, 2)
        entries, following, more = await store.page(DEVICE, FIRST_PAGE, FIRST_PAGE, 10)
        assert kinds(entries) == [2, 1, "boot", 3, 2, 1], entries
        assert entries[2]["boot"] == 9 and following is None and more is False
        # The marker survives a page boundary: page 2 starts with it.
        entries, following, more = await store.page(DEVICE, 9, 1, 2)
        assert kinds(entries) == ["boot", 3, 2] and entries[0]["boot"] == 9, entries
        assert following == (7, 2) and more is True

        # --- A gap after a reboot shows inside the new boot -------------------------
        await store.apply(DEVICE, {"b": 10, "miss": 7, "e": [event(8), event(9)]})
        entries, _, _ = await store.page(DEVICE, FIRST_PAGE, FIRST_PAGE, 3)
        assert kinds(entries) == [9, 8, "gap", "boot", 2], entries
        assert entries[2]["count"] == 7 and entries[3]["boot"] == 10

        # --- A reset keeps the stored rows and marks where it happened --------------
        await store.apply(DEVICE, {"b": 10, "reset": True, "e": [event(10), event(11)]})
        entries, _, _ = await store.page(DEVICE, FIRST_PAGE, FIRST_PAGE, 4)
        assert kinds(entries) == [11, 10, "reset", 9, 8, "gap"], entries

        # --- The export walks oldest first, every marker before its event -----------
        exported, cursor = [], (0, 0)
        while cursor is not None:
            chunk, cursor = await store.chunk(DEVICE, *cursor, limit=3)
            exported += chunk
        assert kinds(exported) == [1, 2, 3, "boot", 1, 2, "boot", "gap", 8, 9, "reset", 10, 11], exported
        assert [entry["boot"] for entry in exported if entry.get("g") == "boot"] == [9, 10]

        # --- Size retention: another controller's rows go first, by their own key ---
        filler = "filler " * 30
        for batch in range(20):
            await store.apply(OTHER, {"b": 3, "e": [event(batch * 100 + n, text=filler) for n in range(1, 101)]})
            await store.apply(DEVICE, {"b": 12, "e": [event(batch * 100 + n, text=filler) for n in range(1, 101)]})
        mine_before = (await store.stats(DEVICE))["rows"]
        assert (await store.stats(DEVICE))["bytes"] > 1048576, "the filler filled"
        assert await store.prune(days=3650, megabytes=1, device=DEVICE) > 0
        assert (await store.stats(DEVICE))["bytes"] <= 1048576
        others, mine = (await store.stats(OTHER))["rows"], (await store.stats(DEVICE))["rows"]
        assert others == 0 or mine == mine_before, (others, mine, mine_before)
        assert (await store.cursor(DEVICE))[0] == 12, "the newest events survive the trim"
        assert not await sql(store, "select * from log_marks where not exists (select 1 from log_events e "
                                    "where e.device_id = log_marks.device_id and e.boot_id = log_marks.boot_id "
                                    "and e.sequence = log_marks.sequence)"), "marks go with their events"

        # --- Age retention: dated events go; events without a clock stay ------------
        await store.apply(DEVICE, {"b": 13, "e": [[1, 10, 0, "i", "state", "no clock yet"],
                                                  [2, 20, 1000, "i", "state", "1970"]]})
        await store.prune(days=30, megabytes=50, device=DEVICE)
        rows = await sql(store, "select sequence from log_events where device_id = ? and boot_id = 13", DEVICE)
        assert rows == [(1,)], rows

        # --- Access grants persist until refused ------------------------------------
        await store.grant("abc", True)
        assert "abc" in await store.grants()
        await store.grant("abc", False)
        assert "abc" not in await store.grants()

        # --- A backup is a consistent store of its own ------------------------------
        await store.backup()
        copy = sqlite3.connect(data / "companion.db.backup")
        assert copy.execute("select count(*) from log_events").fetchone()[0] == \
            (await sql(store, "select count(*) from log_events"))[0][0]
        copy.close()
        assert not (data / "companion.db.backup.partial").exists()

        # --- Delete history keeps who may read it; Forget takes everything ----------
        await store.grant("abc", True)
        await store.erase(history_only=True)
        assert (await store.stats(DEVICE))["rows"] == 0 and await store.device() == DEVICE
        assert "abc" in await store.grants()
        await store.erase()
        assert await store.device() is None and not await store.grants()
        assert not (data / "companion.db.backup").exists()
        await store.close()
    print("Companion log store: migration, markers, export, retention, erase, backup and access OK")


asyncio.run(main())
