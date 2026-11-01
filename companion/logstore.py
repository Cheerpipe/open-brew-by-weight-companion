"""The controller's diagnostic log, persisted: SQLite under <data>/companion.db.

WAL, `user_version` migrations, and every call on the secrets store's single
disk thread, so the event loop never waits on the filesystem and writes stay
ordered. Boots are numbered here in the order they arrive (`ordinal`), and
events are keyed by it: the controller streams only its current boot, so
arrival is chronological, and a boot id it reuses (one it could not save, or
a counter a full flash erase restarted) becomes a new boot instead of
overwriting an old one. The sync cursor is the newest boot's id and its last
stored sequence, never separate state. Holes are mark rows anchored to the
first event after them (a gap the ring overwrote, a cursor the controller
could not resume), so the history names them; nothing the controller sent is
deleted except by retention or an erase. Retention prunes by age and then to
the size budget, other controllers' rows first; freed pages are reused, so
the file settles near the budget without a vacuum; the budget counts the
log's own tables, never the archive's beside them.

This module owns the database: it opens it, migrates it, backs it up, erases
it and closes it. Schema 3 adds the shot and activation archive's tables,
whose queries live in archive.py on this same connection and disk thread.
"""

import asyncio
import sqlite3
import time

from .store import offload

SCHEMA = 3
PRUNE_ROUNDS = 3  # Proportional trims to the size budget, each measured once (dbstat walks the tables).
GRANT_DAYS = 90  # A Web UI session the controller accepted stays usable this long unseen.
FORMAT, EXPORT_VERSION = "openbrewbyweight-companion-log", 2
FIRST_PAGE = 2 ** 32  # The page cursor before the newest event: past every ordinal and sequence.

TABLES = """
    create table meta (key text primary key, value text not null) without rowid;
    create table log_access (session text primary key, checked real not null) without rowid;
    create table log_boots_v2 (
        device_id text not null, ordinal integer not null, boot_id integer not null,
        primary key (device_id, ordinal)) without rowid;
    create table log_events_v2 (
        device_id text not null, ordinal integer not null, sequence integer not null,
        boot_id integer not null, at_ms integer not null, wall_sec integer not null,
        level text not null, category text not null, message text not null,
        primary key (device_id, ordinal, sequence)) without rowid;
    create table log_marks_v2 (
        device_id text not null, ordinal integer not null, sequence integer not null,
        kind text not null, count integer not null, noted real not null,
        primary key (device_id, ordinal, sequence, kind)) without rowid;
"""
# Version 1 keyed events by boot id, anchored a gap to the event before it and
# a reset to sequence 0, and kept an index that repeated the primary key. Its
# boots are ordered by id, the best it recorded.
V1_TO_V2 = """
    insert into log_boots_v2 select device_id, row_number() over
        (partition by device_id order by boot_id), boot_id
        from (select distinct device_id, boot_id from log_events);
    insert into log_events_v2 select e.device_id, b.ordinal, e.sequence, e.boot_id, e.at_ms,
        e.wall_sec, e.level, e.category, e.message
        from log_events e join log_boots_v2 b on b.device_id = e.device_id and b.boot_id = e.boot_id;
    insert or ignore into log_marks_v2 select m.device_id, b.ordinal,
        (select min(e.sequence) from log_events e where e.device_id = m.device_id
            and e.boot_id = m.boot_id and e.sequence > m.after_sequence), m.kind, m.count, m.noted
        from log_marks m join log_boots_v2 b on b.device_id = m.device_id and b.boot_id = m.boot_id
        where exists (select 1 from log_events e where e.device_id = m.device_id
            and e.boot_id = m.boot_id and e.sequence > m.after_sequence);
    drop index if exists log_events_page;
    drop table log_events;
    drop table log_marks;
"""
LOG_TABLES = ("log_boots", "log_events", "log_marks")
RENAME = "".join(f"alter table {table}_v2 rename to {table};" for table in LOG_TABLES)
# Version 3: the archive. Rows are keyed by generation: a restarted
# controller history (Clear, a factory reset) closes one and opens the next,
# so nothing it held is ever deleted by inference; generations 0 and below
# hold records set aside when a replacement was ambiguous. Records keep the
# row the Web UI rebuilds (`body`), whether the user kept it (`kept`) and
# their wall-clock end (`ended_at`, 0 without one); a trace row without data
# says the shot has none; `listed` is the last complete index's ids and
# `counters` the controller's store generation and next record id it named;
# an exclusion stops a record removed from the archive alone from being
# copied again while the controller may hold it, and keeps the fields the
# whole-history Stats header still counts it by (`body`).
ARCHIVE = """
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
ARCHIVE_TABLES = ("archive_records", "archive_traces", "archive_sync", "archive_holes", "archive_exclusions")


def table_bytes(connection, tables):
    """The pages these tables and their indexes use, whatever else shares the file."""
    names = list(tables) + [f"sqlite_autoindex_{table}_1" for table in tables]
    return connection.execute(f"select coalesce(sum(pgsize), 0) from dbstat where aggregate = 1 and name in "
                              f"({','.join('?' * len(names))})", names).fetchone()[0]


def _entry(row):
    return {"b": row["boot_id"], "s": row["sequence"], "ms": row["at_ms"], "w": row["wall_sec"],
            "l": row["level"], "c": row["category"], "m": row["message"]}


class LogStore:
    def __init__(self, data):
        self.path = data / "companion.db"
        self.backup_path = data / "companion.db.backup"
        self.connection = None

    # --- Lifecycle -----------------------------------------------------------
    async def open(self):
        await offload(self._open)

    def _open(self):
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("pragma journal_mode=wal")
        connection.execute("pragma synchronous=normal")
        version = connection.execute("pragma user_version").fetchone()[0]
        if version > SCHEMA:
            connection.close()
            raise sqlite3.DatabaseError(f"its schema {version} is newer than this companion's {SCHEMA}")
        if version < SCHEMA:
            log = TABLES + (V1_TO_V2 if version == 1 else "") + RENAME if version < 2 else ""
            connection.executescript(f"begin;{log}{ARCHIVE}pragma user_version = {SCHEMA}; commit;")
        self.connection = connection

    async def close(self):
        await offload(self._close)

    def _close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    # --- The controller's id -------------------------------------------------
    async def device(self):
        """The id of the controller the history belongs to, kept across restarts."""
        return await offload(self._device)

    def _device(self):
        row = self.connection.execute("select value from meta where key = 'device'").fetchone()
        return row["value"] if row else None

    async def set_device(self, device):
        await offload(self.connection.execute, "insert or replace into meta values ('device', ?)", (device,))

    # --- Sync ----------------------------------------------------------------
    def _latest(self, device):
        return self.connection.execute("select ordinal, boot_id from log_boots where device_id = ? "
                                       "order by ordinal desc limit 1", (device,)).fetchone()

    async def apply(self, device, frame):
        """One controller `log` frame: its events, and the hole a `miss` or `reset` names before them."""
        return await offload(self._apply, device, frame)

    def _apply(self, device, frame):
        boot, first, now = frame["b"], frame["e"][0][0], time.time()
        reset = frame.get("reset") is True
        marks = [("reset", 0)] if reset else []
        if frame.get("miss"):
            marks.append(("gap", frame["miss"]))
        with self.connection:
            latest = self._latest(device)
            ordinal = latest["ordinal"] if latest else 0
            # Another boot id, or the same one the controller could not resume
            # (`reset`: only a reused id does that), is a new boot.
            if latest is None or latest["boot_id"] != boot or reset:
                ordinal += 1
                self.connection.execute("insert into log_boots values (?, ?, ?)", (device, ordinal, boot))
            self.connection.executemany("insert or replace into log_marks values (?, ?, ?, ?, ?, ?)",
                                        ((device, ordinal, first, kind, count, now) for kind, count in marks))
            self.connection.executemany(
                "insert or replace into log_events values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ((device, ordinal, entry[0], boot, *entry[1:]) for entry in frame["e"]))

    async def cursor(self, device):
        """The newest boot's id and its last stored sequence: the resume point for `logsub`."""
        return await offload(self._cursor, device)

    def _cursor(self, device):
        latest = self._latest(device)
        if latest is None:
            return None
        row = self.connection.execute("select max(sequence) as sequence from log_events "
                                      "where device_id = ? and ordinal = ?", (device, latest["ordinal"])).fetchone()
        return (latest["boot_id"], row["sequence"]) if row["sequence"] is not None else None

    # --- Reading -------------------------------------------------------------
    def _boots(self, device):
        return {row["ordinal"]: row["boot_id"] for row in
                self.connection.execute("select ordinal, boot_id from log_boots where device_id = ?", (device,))}

    def _marks(self, device, rows):
        """The markers anchored to these rows, keyed by (ordinal, sequence)."""
        if not rows:
            return {}
        keys = [(row["ordinal"], row["sequence"]) for row in rows]
        marks = {}
        for mark in self.connection.execute(
                "select * from log_marks where device_id = ? and (ordinal, sequence) between (?, ?) and (?, ?) "
                "order by kind", (device, *min(keys), *max(keys))):
            marks.setdefault((mark["ordinal"], mark["sequence"]), []).append(
                {"g": "gap", "count": mark["count"]} if mark["kind"] == "gap" else {"g": "reset"})
        return marks

    async def page(self, device, before_ordinal, before_sequence, limit):
        """One page of the history, newest first, with its markers.

        Returns (entries, next, has_more): `next` is the opaque (ordinal,
        sequence) the following page continues from, None at the end. Each
        marker sits where it belongs in time: a gap or reset right below
        (older than) the event that follows it, and a restart between two
        boots, naming the newer.
        """
        return await offload(self._page, device, before_ordinal, before_sequence, limit)

    def _page(self, device, before_ordinal, before_sequence, limit):
        rows = self.connection.execute(
            "select * from log_events where device_id = ? and (ordinal, sequence) < (?, ?) "
            "order by ordinal desc, sequence desc limit ?",
            (device, before_ordinal, before_sequence, limit + 1)).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        marks, boots = self._marks(device, rows), self._boots(device)
        entries, newer = [], None if before_sequence >= FIRST_PAGE else before_ordinal
        for row in rows:
            if newer is not None and row["ordinal"] != newer:
                entries.append({"g": "boot", "boot": boots.get(newer)})
            entries.append(_entry(row))
            entries.extend(marks.get((row["ordinal"], row["sequence"]), ()))
            newer = row["ordinal"]
        following = (rows[-1]["ordinal"], rows[-1]["sequence"]) if rows else None
        return entries, (following if has_more else None), has_more

    async def chunk(self, device, after_ordinal, after_sequence, limit=1000):
        """The next oldest-first chunk of a streaming export, markers in place.

        Returns (entries, cursor): the cursor continues the next chunk, None at the end.
        """
        return await offload(self._chunk, device, after_ordinal, after_sequence, limit)

    def _chunk(self, device, after_ordinal, after_sequence, limit):
        rows = self.connection.execute(
            "select * from log_events where device_id = ? and (ordinal, sequence) > (?, ?) "
            "order by ordinal asc, sequence asc limit ?",
            (device, after_ordinal, after_sequence, limit)).fetchall()
        marks, entries, older = self._marks(device, rows), [], after_ordinal if after_sequence else None
        for row in rows:
            if older is not None and row["ordinal"] != older:
                entries.append({"g": "boot", "boot": row["boot_id"]})
            entries.extend(marks.get((row["ordinal"], row["sequence"]), ()))
            entries.append(_entry(row))
            older = row["ordinal"]
        return entries, ((rows[-1]["ordinal"], rows[-1]["sequence"]) if rows else None)

    # --- Access --------------------------------------------------------------
    async def grants(self):
        """The Web UI sessions (their sha256) the controller accepted, with when it last said so."""
        return await offload(lambda: {row["session"]: row["checked"] for row in
                                      self.connection.execute("select * from log_access")})

    async def grant(self, session, allowed):
        if allowed:
            await offload(self.connection.execute, "insert or replace into log_access values (?, ?)",
                          (session, time.time()))
        else:
            await offload(self.connection.execute, "delete from log_access where session = ?", (session,))

    # --- Retention and erase -------------------------------------------------
    async def prune(self, days, megabytes, device):
        """By age first, then to the size budget: other ids first, then `device`'s oldest; returns rows deleted."""
        return await offload(self._prune, days, megabytes, device)

    def _used_bytes(self):
        return table_bytes(self.connection, LOG_TABLES)

    def _prune(self, days, megabytes, device):
        deleted = 0
        with self.connection:
            deleted += self.connection.execute(
                "delete from log_events where wall_sec != 0 and wall_sec < ?",
                (time.time() - days * 86400,)).rowcount
            budget, used = megabytes * 1024 * 1024, self._used_bytes()
            for _ in range(PRUNE_ROUNDS):
                if used <= budget:
                    break
                # The excess's share of the rows, oldest first (other controllers' first), and a little more.
                rows = self.connection.execute("select count(*) from log_events").fetchone()[0]
                gone = self.connection.execute(
                    "delete from log_events where (device_id, ordinal, sequence) in "
                    "(select device_id, ordinal, sequence from log_events "
                    "order by device_id = ?, ordinal, sequence limit ?)",
                    (device, -(-rows * (used - budget) * 101 // (used * 100)))).rowcount
                deleted += gone
                used = self._used_bytes()
                if gone == 0:
                    break
            # A mark goes with the event it is anchored to, and an emptied boot
            # with its events, except each controller's newest (the cursor's).
            self.connection.execute(
                "delete from log_marks where not exists (select 1 from log_events e "
                "where e.device_id = log_marks.device_id and e.ordinal = log_marks.ordinal "
                "and e.sequence = log_marks.sequence)")
            self.connection.execute(
                "delete from log_boots where not exists (select 1 from log_events e "
                "where e.device_id = log_boots.device_id and e.ordinal = log_boots.ordinal) "
                "and ordinal < (select max(b.ordinal) from log_boots b where b.device_id = log_boots.device_id)")
            self.connection.execute("delete from log_access where checked < ?",
                                    (time.time() - GRANT_DAYS * 86400,))
        self.connection.execute("pragma wal_checkpoint(truncate)")
        return deleted

    async def erase(self, history_only=False):
        """Everything the controller sent and who could read it, the archive included (Forget), or the log
        history alone (Delete history)."""
        await offload(self._erase, history_only)

    def _erase(self, history_only):
        with self.connection:
            for table in ("log_events", "log_marks") + (() if history_only else (
                    "log_boots", "log_access", "meta") + ARCHIVE_TABLES):
                self.connection.execute(f"delete from {table}")
        # Deleted rows linger in free pages until reused: an erase rewrites the file.
        self.connection.execute("vacuum")
        self.connection.execute("pragma wal_checkpoint(truncate)")
        self.backup_path.unlink(missing_ok=True)

    async def backup(self):
        """A consistent copy beside the store, which a copy of the data folder can always take.

        Its own connections on a worker thread (WAL lets them read alongside),
        so the disk thread keeps serving the link meanwhile.
        """
        await asyncio.to_thread(self._backup)

    def _backup(self):
        partial = self.backup_path.with_name(self.backup_path.name + ".partial")
        source, copy = sqlite3.connect(self.path), sqlite3.connect(partial)
        try:
            source.backup(copy)
        finally:
            copy.close()
            source.close()
        partial.replace(self.backup_path)

    async def stats(self, device):
        return await offload(self._stats, device)

    def _stats(self, device):
        events = self.connection.execute(
            "select count(*) as rows, min(ordinal) as oldest, max(ordinal) as newest "
            "from log_events where device_id = ?", (device,)).fetchone()
        boots = self._boots(device)
        gaps = self.connection.execute(
            "select count(*) as marks, coalesce(sum(count), 0) as missed "
            "from log_marks where kind = 'gap' and device_id = ?", (device,)).fetchone()
        return {"rows": events["rows"], "bytes": self._used_bytes(), "oldestBoot": boots.get(events["oldest"]),
                "newestBoot": boots.get(events["newest"]), "marks": gaps["marks"], "missed": gaps["missed"]}
