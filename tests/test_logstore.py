"""The log store on its own: migration, paging and markers, export chunks,
retention, erase, backup and access grants; the archive's tables it migrates
and erases (their queries are test_archive.py's).

The link-level sync (subscribe after `dev`, resume across a restart, failure
isolation, access through the controller) is covered by test_link.py; this
checks what a session cannot reach. Offline, inside the image (see the README).
"""

import asyncio
import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING

import pytest

from companion.logstore import FIRST_PAGE, RENAME, TABLES, LogStore
from companion.store import offload

if TYPE_CHECKING:
    from pathlib import Path

    from companion.logstore import Cursor, Entry

DEVICE, OTHER = "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"
FILTERED = "FF:FF:FF:FF:FF:01"  # The controller the filters and moments are paged on.


def event(
    sequence: int, wall: int = 1789000000, level: str = "i", text: str | None = None
) -> list[int | str]:
    return [sequence, sequence * 100, wall, level, "state", text or f"event {sequence}"]


def kinds(entries: list[Entry]) -> list[int | str | None]:
    return [entry.get("s", entry.get("g")) for entry in entries]


async def sql(store: LogStore, statement: str, *args: str | int) -> list[tuple[object, ...]]:
    return await offload(lambda: [tuple(row) for row in store.db.execute(statement, args)])


def version_1(path: Path) -> None:
    """A store as the first companion release left it: gap after an event, reset at 0, a
    duplicate index."""
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
        connection.execute(
            "insert into log_events values (?, 7, ?, 0, 0, 'i', 'state', 'x')", (DEVICE, sequence)
        )
    connection.execute("insert into log_marks values (?, 7, 3, 'gap', 4, 0)", (DEVICE,))
    connection.execute("insert into log_marks values (?, 7, 0, 'reset', 0, 0)", (DEVICE,))
    connection.execute(
        "insert into log_marks values (?, 6, 9, 'gap', 2, 0)", (DEVICE,)
    )  # Hidden in v1: dropped.
    connection.close()


# The archive's tables as schema 3 made them: records kept after a deletion and exclusions.
ARCHIVE_V3 = """
    create table archive_records (device_id text not null, store text not null,
        generation integer not null, id integer not null, ident text not null, rev integer not null,
        kind text not null, bad integer not null, kept integer not null, ended_at integer not null,
        body text not null, unique (device_id, store, generation, id));
    create table archive_traces (device_id text not null, generation integer not null,
        id integer not null, boot_id integer not null, ended_ms integer not null, data blob,
        unique (device_id, generation, id, boot_id, ended_ms));
    create table archive_sync (device_id text not null, store text not null,
        generation integer not null, epoch integer not null, oldest integer,
        listed text not null, restarted real, counters text, unique (device_id, store, generation));
    create table archive_holes (device_id text not null, store text not null,
        generation integer not null, below integer not null, above integer not null,
        count integer not null, noted real not null,
        primary key (device_id, store, generation, below)) without rowid;
    create table archive_exclusions (device_id text not null, store text not null,
        generation integer not null, id integer not null, body text,
        primary key (device_id, store, generation, id));
"""


def version_3(path: Path) -> None:
    """A store with the archive as schema 3 kept it: generation 2 open (synced oldest 10), a kept
    record the controller may still list (12, with its trace) and one below the oldest (5), a kept
    record of the closed generation 1 (12 too), and an exclusion."""
    connection = sqlite3.connect(path, isolation_level=None)
    connection.executescript(TABLES + RENAME + ARCHIVE_V3 + "pragma user_version = 3;")
    connection.execute(
        "insert into archive_sync values (?, 'shots', 1, 5, 1, '[]', null, null)", (DEVICE,)
    )
    connection.execute(
        "insert into archive_sync values (?, 'shots', 2, 9, 10, '[]', 1789000000, null)", (DEVICE,)
    )
    for generation, rid, kept in ((1, 12, 1), (2, 5, 1), (2, 12, 1), (2, 13, 0)):
        connection.execute(
            "insert into archive_records values (?, 'shots', ?, ?, '', 0, 'good', 0, ?, 0, '{}')",
            (DEVICE, generation, rid, kept),
        )
    connection.execute("insert into archive_traces values (?, 2, 12, 7, 12017, x'01')", (DEVICE,))
    connection.execute("insert into archive_exclusions values (?, 'shots', 2, 14, null)", (DEVICE,))
    connection.execute("insert into meta values ('archiveKeepDeleted', '1')")
    connection.close()


def version_2(path: Path) -> None:
    """A store as the persistent-log release left it, with one event."""
    connection = sqlite3.connect(path, isolation_level=None)
    connection.executescript(TABLES + RENAME + "pragma user_version = 2;")
    connection.execute("insert into log_boots values (?, 1, 7)", (DEVICE,))
    connection.execute(
        "insert into log_events values (?, 1, 1, 7, 0, 0, 'i', 'state', 'kept')", (DEVICE,)
    )
    connection.close()


async def second_version(data: Path) -> None:
    second = data / "second"
    second.mkdir()
    version_2(second / "companion.db")
    store = LogStore(second)
    await store.open()
    assert await sql(store, "pragma user_version") == [(4,)]
    assert await sql(store, "select message from log_events") == [("kept",)]
    tables = {
        name for (name,) in await sql(store, "select name from sqlite_master where type = 'table'")
    }
    assert tables >= {"archive_records", "archive_traces", "archive_sync", "archive_holes"}
    assert "archive_exclusions" not in tables
    assert {
        name for (name,) in await sql(store, "select name from sqlite_master where type = 'index'")
    } >= {"log_events_wall", "log_events_category"}
    await store.close()


def test_version_2_gains_the_archive(tmp_path: Path) -> None:
    """Version 2 gains the archive's tables and keeps its log."""
    asyncio.run(second_version(tmp_path))


async def third_version(data: Path) -> None:
    third = data / "third"
    third.mkdir()
    version_3(third / "companion.db")
    store = LogStore(third)
    await store.open()
    assert await sql(store, "pragma user_version") == [(4,)]
    assert await sql(
        store, "select generation, id from archive_records order by generation, id"
    ) == [(0, 12), (1, 12), (2, 5), (2, 13)], (
        "the open kept record the controller may list is set aside"
    )
    assert await sql(store, "select generation, id from archive_traces") == [(0, 12)], (
        "with its trace"
    )
    assert "kept" not in [row[1] for row in await sql(store, "pragma table_info(archive_records)")]
    assert not await sql(store, "select name from sqlite_master where name = 'archive_exclusions'")
    assert await store.meta("archiveKeepDeleted") is None, "the retired switch goes too"
    await store.close()


def test_version_3_keeps_records_as_archive_only(tmp_path: Path) -> None:
    """Version 3: kept records become ordinary archive-only rows (D7)."""
    asyncio.run(third_version(tmp_path))


async def newer_version(data: Path) -> None:
    newer = data / "newer"
    newer.mkdir()
    sqlite3.connect(newer / "companion.db").execute("pragma user_version = 9").connection.close()
    with pytest.raises(sqlite3.DatabaseError) as refused:
        await LogStore(newer).open()
    assert "newer" in str(refused.value)
    with closing(sqlite3.connect(newer / "companion.db")) as connection:
        assert connection.execute("pragma user_version").fetchone()[0] == 9


def test_newer_schema_is_refused(tmp_path: Path) -> None:
    """A newer schema is refused, never relabeled."""
    asyncio.run(newer_version(tmp_path))


async def history(data: Path) -> None:
    # --- Version 1 migrates: marks re-anchored, the duplicate index gone --------
    version_1(data / "companion.db")
    store = LogStore(data)
    await store.open()
    assert await sql(store, "pragma user_version") == [(4,)]
    assert not await sql(store, "select name from sqlite_master where name = 'log_events_page'")
    entries, _, _ = await store.page(DEVICE, FIRST_PAGE, FIRST_PAGE, 10)
    assert kinds(entries) == [8, "gap", 3, 2, 1, "reset"], entries
    await store.erase()
    assert await store.meta("device") is None
    await store.close()

    # The rest runs on that migrated, erased store.
    store = LogStore(data)
    await store.open()
    await store.set_meta("device", DEVICE)
    assert await store.meta("device") == DEVICE

    # --- Two boots: a restart marker between them names the newer boot ----------
    await store.apply(DEVICE, {"b": 7, "e": [event(1), event(2), event(3)]})
    await store.apply(DEVICE, {"b": 9, "e": [event(1), event(2)]})
    assert await store.cursor(DEVICE) == (9, 2)
    entries, following, more = await store.page(DEVICE, FIRST_PAGE, FIRST_PAGE, 10)
    assert kinds(entries) == [2, 1, "boot", 3, 2, 1], entries
    assert entries[2]["boot"] == 9
    assert following is None
    assert more is False
    # The marker survives a page boundary: page 2 (after the opaque cursor
    # of boot 9's oldest event, the second boot to arrive) starts with it.
    entries, following, more = await store.page(DEVICE, 2, 1, 2)
    assert kinds(entries) == ["boot", 3, 2], entries
    assert entries[0]["boot"] == 9, entries
    assert following == (1, 2)
    assert more is True

    # --- A gap after a reboot shows inside the new boot -------------------------
    await store.apply(DEVICE, {"b": 10, "miss": 7, "e": [event(8), event(9)]})
    entries, _, _ = await store.page(DEVICE, FIRST_PAGE, FIRST_PAGE, 3)
    assert kinds(entries) == [9, 8, "gap", "boot", 2], entries
    assert entries[2]["count"] == 7
    assert entries[3]["boot"] == 10

    # --- A reused boot id is a new boot: nothing stored is overwritten ---------
    # `reset` (the controller could not resume the cursor) only comes from
    # an id it reused; the rows stay and the boundary is marked.
    await store.apply(DEVICE, {"b": 10, "reset": True, "e": [event(8, text="reused"), event(11)]})
    entries, _, _ = await store.page(DEVICE, FIRST_PAGE, FIRST_PAGE, 4)
    assert kinds(entries) == [11, 8, "reset", "boot", 9, 8, "gap"], entries
    assert entries[1]["m"] == "reused"
    assert entries[5]["m"] == "event 8", "the earlier boot's 8 is kept"
    assert await store.cursor(DEVICE) == (10, 11)
    # A boot id that comes back later (a counter a flash erase restarted) is new too.
    await store.apply(DEVICE, {"b": 7, "e": [event(1, text="again")]})
    assert await store.cursor(DEVICE) == (7, 1)
    entries, _, _ = await store.page(DEVICE, FIRST_PAGE, FIRST_PAGE, 2)
    assert kinds(entries) == [1, "boot", 11]
    assert entries[0]["m"] == "again"
    assert entries[1]["boot"] == 7

    # --- The export walks oldest first, every marker before its event -----------
    exported: list[Entry] = []
    cursor: Cursor | None = (0, 0)
    while cursor is not None:
        chunk, cursor = await store.chunk(DEVICE, *cursor, limit=3)
        exported += chunk
    assert kinds(exported) == [
        1,
        2,
        3,
        "boot",
        1,
        2,
        "boot",
        "gap",
        8,
        9,
        "boot",
        "reset",
        8,
        11,
        "boot",
        1,
    ], exported
    assert [entry["boot"] for entry in exported if entry.get("g") == "boot"] == [9, 10, 10, 7]

    # --- Filters and a moment (D16): every page holds matching events only, the
    # markers stay where they belong, and a page can start at a wall time ------
    wall = 1790000000
    await store.apply(
        FILTERED,
        {
            "b": 1,
            "e": [
                [1, 0, wall, "i", "state", "a"],
                [2, 0, wall + 10, "e", "ble", "b"],
                [3, 0, 0, "i", "ble", "unsynced"],
                [4, 0, wall + 30, "w", "state", "c"],
            ],
        },
    )
    await store.apply(
        FILTERED,
        {
            "b": 1,
            "miss": 2,
            "e": [
                [7, 0, wall + 60, "d", "state", "after gap"],
                [8, 0, wall + 70, "e", "ble", "d"],
            ],
        },
    )
    await store.apply(FILTERED, {"b": 2, "e": [[1, 0, wall + 100, "i", "state", "boot 2"]]})
    entries, _, _ = await store.page(FILTERED, FIRST_PAGE, FIRST_PAGE, 10, ("c", "e"))
    assert [e.get("m", e.get("g")) for e in entries] == ["boot", "d", "gap", "b"], entries
    entries, following, more = await store.page(FILTERED, FIRST_PAGE, FIRST_PAGE, 1, None, "ble")
    assert [e.get("m", e.get("g")) for e in entries] == ["boot", "d"], (
        "a page of one matching event"
    )
    assert more, "a page of one matching event"
    assert following is not None
    entries, _, _ = await store.page(FILTERED, *following, 10, None, "ble")
    assert [e.get("m", e.get("g")) for e in entries] == ["gap", "unsynced", "b"], (
        "the gap stays by time though its event is filtered out; an unsynced event keeps its place"
    )
    entries, _, _ = await store.page(FILTERED, FIRST_PAGE, FIRST_PAGE, 10, None, None, wall + 35)
    assert [e.get("m", e.get("g")) for e in entries] == ["c", "unsynced", "b", "a"], (
        "starts at that moment"
    )
    assert await store.page(FILTERED, FIRST_PAGE, FIRST_PAGE, 10, None, None, wall - 1) == (
        [],
        None,
        False,
    )
    # A reader steps boot to boot: each stored boot with its clock span, and a cursor whose
    # page ends at that boot's newest event without naming the newer restart.
    spans = await store.boots(FILTERED)
    assert [(s["boot"], s["since"], s["until"]) for s in spans] == [
        (1, wall, wall + 70),
        (2, wall + 100, wall + 100),
    ], spans
    entries, _, _ = await store.page(FILTERED, *spans[0]["end"], 10)
    assert [e.get("m", e.get("g")) for e in entries] == [
        "d",
        "after gap",
        "gap",
        "c",
        "unsynced",
        "b",
        "a",
    ], entries
    span = await store.bounds(FILTERED, wall + 5, wall + 65)
    assert span is not None
    chunk, _ = await store.chunk(FILTERED, *span[0], through=span[1])
    assert [e.get("m", e.get("g")) for e in chunk] == [
        "b",
        "unsynced",
        "c",
        "gap",
        "after gap",
    ], chunk
    assert await store.bounds(FILTERED, wall + 200, None) is None

    # --- Size retention: another controller's rows go first, by their own key ---
    filler = "filler " * 30
    for batch in range(20):
        await store.apply(
            OTHER, {"b": 3, "e": [event(batch * 100 + n, text=filler) for n in range(1, 101)]}
        )
        await store.apply(
            DEVICE, {"b": 12, "e": [event(batch * 100 + n, text=filler) for n in range(1, 101)]}
        )
    mine_before = (await store.stats(DEVICE))["rows"]
    assert (await store.stats(DEVICE))["bytes"] > 1048576, "the filler filled"
    assert await store.prune(days=3650, megabytes=1, device=DEVICE) > 0
    assert (await store.stats(DEVICE))["bytes"] <= 1048576
    others, mine = (await store.stats(OTHER))["rows"], (await store.stats(DEVICE))["rows"]
    assert others == 0 or mine == mine_before, (others, mine, mine_before)
    newest = await store.cursor(DEVICE)
    assert newest is not None
    assert newest[0] == 12, "the newest events survive the trim"
    assert not await sql(
        store,
        "select * from log_marks where not exists (select 1 from log_events e "
        "where e.device_id = log_marks.device_id and e.ordinal = log_marks.ordinal "
        "and e.sequence = log_marks.sequence)",
    ), "marks go with their events"
    assert await sql(store, "select count(*) from log_boots where device_id = ?", OTHER) == [
        (1,)
    ], "an emptied boot goes, except a controller's newest"

    # --- The archive beside it is not the log's: its size never prunes the log --
    log_rows = (await store.stats(DEVICE))["rows"]
    await offload(
        lambda: store.db.executemany(
            "insert into archive_records values (?, 'shots', 1, ?, '', 0, 'good', 0, 0, ?)",
            [(DEVICE, n, "x" * 4000) for n in range(1, 600)],
        )
    )
    assert await store.prune(days=3650, megabytes=1, device=DEVICE) == 0
    assert (await store.stats(DEVICE))["rows"] == log_rows
    assert (await store.stats(DEVICE))["bytes"] <= 1048576

    # --- Age retention: dated events go; events without a clock stay ------------
    await store.apply(
        DEVICE,
        {
            "b": 13,
            "e": [
                [1, 10, 0, "i", "state", "no clock yet"],
                [2, 20, 1000, "i", "state", "1970"],
            ],
        },
    )
    await store.prune(days=30, megabytes=50, device=DEVICE)
    rows = await sql(
        store, "select sequence from log_events where device_id = ? and boot_id = 13", DEVICE
    )
    assert rows == [(1,)], rows

    # --- Access grants persist until refused ------------------------------------
    await store.grant("abc", True)
    assert "abc" in await store.grants()
    await store.grant("abc", False)
    assert "abc" not in await store.grants()

    # --- A backup is a consistent store of its own ------------------------------
    await store.backup()
    copy = sqlite3.connect(data / "companion.db.backup")
    assert (
        copy.execute("select count(*) from log_events").fetchone()[0]
        == (await sql(store, "select count(*) from log_events"))[0][0]
    )
    copy.close()
    assert not (data / "companion.db.backup.partial").exists()

    # --- Delete history keeps who may read it; Forget takes everything ----------
    await store.grant("abc", True)
    await store.erase(history_only=True)
    assert (await store.stats(DEVICE))["rows"] == 0
    assert await store.boots(DEVICE) == [], "a boot without events is not listed"
    assert await store.meta("device") == DEVICE
    assert "abc" in await store.grants()
    assert await sql(store, "select count(*) from archive_records") == [(599,)], (
        "Delete history is the log's"
    )
    await store.erase()
    assert await store.meta("device") is None
    assert not await store.grants()
    assert await sql(store, "select count(*) from archive_records") == [(0,)], (
        "Forget takes the archive too"
    )
    assert not (data / "companion.db.backup").exists()
    await store.close()


def test_history(tmp_path: Path) -> None:
    """Version 1 migrates, then on that store: markers, export, filters, retention, erase, backup
    and access."""
    asyncio.run(history(tmp_path))
