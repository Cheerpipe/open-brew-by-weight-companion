"""The controller's diagnostic log, persisted: SQLite under <data>/companion.db.

WAL, `user_version` migrations, and every call on the secrets store's single
disk thread, so the event loop never waits on the filesystem and writes stay
ordered. The sync cursor is the newest stored row of the controller's id,
never separate state. Holes are mark rows anchored to the first event after
them (a gap the ring overwrote, a cursor the controller could not resume), so
the history names them instead of hiding them; nothing the controller sent is
deleted except by retention or an erase. Retention prunes by age and then to
the size budget, other controllers' rows first; freed pages are reused, so
the file settles near the budget without a vacuum. This is the SQLite
foundation the archive's record tables will migrate onto.
"""

import asyncio
import sqlite3
import time

from .store import offload

SCHEMA = 2
PRUNE_STEP = 500  # Rows per delete round while trimming to the size budget.
GRANT_DAYS = 90  # A Web UI session the controller accepted stays usable this long unseen.
FORMAT, EXPORT_VERSION = "openbrewbyweight-companion-log", 2
FIRST_PAGE = 2 ** 31  # The page cursor before the newest event: no boot follows it.

EVENTS = """
    create table log_events (
        device_id text not null, boot_id integer not null,
        sequence integer not null, at_ms integer not null,
        wall_sec integer not null, level text not null,
        category text not null, message text not null,
        primary key (device_id, boot_id, sequence)) without rowid;
"""
V2 = """
    create table meta (key text primary key, value text not null) without rowid;
    create table log_access (session text primary key, checked real not null) without rowid;
    create table log_marks_v2 (
        device_id text not null, boot_id integer not null, sequence integer not null,
        kind text not null, count integer not null, noted real not null,
        primary key (device_id, boot_id, sequence, kind)) without rowid;
"""
# Version 1 anchored a gap to the event before it, a reset to sequence 0, and
# kept an index that repeated the primary key.
V1_TO_V2 = """
    drop index if exists log_events_page;
    insert or ignore into log_marks_v2
        select m.device_id, m.boot_id, (select min(e.sequence) from log_events e
            where e.device_id = m.device_id and e.boot_id = m.boot_id
            and e.sequence > m.after_sequence), m.kind, m.count, m.noted
        from log_marks m where exists (select 1 from log_events e
            where e.device_id = m.device_id and e.boot_id = m.boot_id
            and e.sequence > m.after_sequence);
    drop table log_marks;
"""


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
            connection.executescript(
                "begin;" + (EVENTS if version == 0 else "") + V2 + (V1_TO_V2 if version == 1 else "") +
                f"alter table log_marks_v2 rename to log_marks; pragma user_version = {SCHEMA}; commit;")
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
    async def apply(self, device, frame):
        """One controller `log` frame: its events, and the hole a `miss` or `reset` names before them."""
        return await offload(self._apply, device, frame)

    def _apply(self, device, frame):
        boot, first, now = frame["b"], frame["e"][0][0], time.time()
        # `reset`: the controller could not resume the cursor. The rows already
        # stored stay; only the boundary is marked.
        marks = [("reset", 0)] if frame.get("reset") is True else []
        if frame.get("miss"):
            marks.append(("gap", frame["miss"]))
        with self.connection:
            self.connection.executemany("insert or replace into log_marks values (?, ?, ?, ?, ?, ?)",
                                        ((device, boot, first, kind, count, now) for kind, count in marks))
            self.connection.executemany("insert or replace into log_events values (?, ?, ?, ?, ?, ?, ?, ?)",
                                        ((device, boot, *entry) for entry in frame["e"]))

    async def cursor(self, device):
        """The newest stored (boot, sequence): the resume point for `logsub`."""
        return await offload(self._cursor, device)

    def _cursor(self, device):
        row = self.connection.execute(
            "select boot_id, sequence from log_events where device_id = ? "
            "order by boot_id desc, sequence desc limit 1", (device,)).fetchone()
        return (row["boot_id"], row["sequence"]) if row else None

    # --- Reading -------------------------------------------------------------
    def _marks(self, device, rows):
        """The markers anchored to these rows, keyed by (boot, sequence)."""
        if not rows:
            return {}
        keys = [(row["boot_id"], row["sequence"]) for row in rows]
        marks = {}
        for mark in self.connection.execute(
                "select * from log_marks where device_id = ? and (boot_id, sequence) between (?, ?) and (?, ?) "
                "order by kind", (device, *min(keys), *max(keys))):
            marks.setdefault((mark["boot_id"], mark["sequence"]), []).append(
                {"g": "gap", "count": mark["count"]} if mark["kind"] == "gap" else {"g": "reset"})
        return marks

    async def page(self, device, before_boot, before_sequence, limit):
        """One page of the history, newest first, with its markers.

        Returns (entries, next, has_more): `next` is the (boot, sequence) the
        following page continues from, None at the end. Each marker sits where
        it belongs in time: a gap or reset right below (older than) the event
        that follows it, and a restart between two boots, naming the newer.
        """
        return await offload(self._page, device, before_boot, before_sequence, limit)

    def _page(self, device, before_boot, before_sequence, limit):
        rows = self.connection.execute(
            "select * from log_events where device_id = ? and (boot_id, sequence) < (?, ?) "
            "order by boot_id desc, sequence desc limit ?",
            (device, before_boot, before_sequence, limit + 1)).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        marks = self._marks(device, rows)
        entries, newer = [], None if before_sequence >= FIRST_PAGE else before_boot
        for row in rows:
            if newer is not None and row["boot_id"] != newer:
                entries.append({"g": "boot", "boot": newer})
            entries.append(_entry(row))
            entries.extend(marks.get((row["boot_id"], row["sequence"]), ()))
            newer = row["boot_id"]
        following = (rows[-1]["boot_id"], rows[-1]["sequence"]) if rows else None
        return entries, (following if has_more else None), has_more

    async def chunk(self, device, after_boot, after_sequence, limit=1000):
        """The next oldest-first chunk of a streaming export, markers in place.

        Returns (entries, cursor): the cursor continues the next chunk, None at the end.
        """
        return await offload(self._chunk, device, after_boot, after_sequence, limit)

    def _chunk(self, device, after_boot, after_sequence, limit):
        rows = self.connection.execute(
            "select * from log_events where device_id = ? and (boot_id, sequence) > (?, ?) "
            "order by boot_id asc, sequence asc limit ?",
            (device, after_boot, after_sequence, limit)).fetchall()
        marks, entries, older = self._marks(device, rows), [], after_boot if after_sequence else None
        for row in rows:
            if older is not None and row["boot_id"] != older:
                entries.append({"g": "boot", "boot": row["boot_id"]})
            entries.extend(marks.get((row["boot_id"], row["sequence"]), ()))
            entries.append(_entry(row))
            older = row["boot_id"]
        return entries, ((rows[-1]["boot_id"], rows[-1]["sequence"]) if rows else None)

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
        count = self.connection.execute("pragma page_count").fetchone()[0]
        free = self.connection.execute("pragma freelist_count").fetchone()[0]
        return (count - free) * self.connection.execute("pragma page_size").fetchone()[0]

    def _prune(self, days, megabytes, device):
        deleted = 0
        with self.connection:
            deleted += self.connection.execute(
                "delete from log_events where wall_sec != 0 and wall_sec < ?",
                (time.time() - days * 86400,)).rowcount
            while self._used_bytes() > megabytes * 1024 * 1024:
                gone = self.connection.execute(
                    "delete from log_events where (device_id, boot_id, sequence) in "
                    "(select device_id, boot_id, sequence from log_events "
                    "order by device_id = ?, boot_id, sequence limit ?)", (device, PRUNE_STEP)).rowcount
                deleted += gone
                if gone == 0:
                    break
            # A mark goes with the event it is anchored to.
            self.connection.execute(
                "delete from log_marks where not exists (select 1 from log_events e "
                "where e.device_id = log_marks.device_id and e.boot_id = log_marks.boot_id "
                "and e.sequence = log_marks.sequence)")
            self.connection.execute("delete from log_access where checked < ?",
                                    (time.time() - GRANT_DAYS * 86400,))
        self.connection.execute("pragma wal_checkpoint(truncate)")
        return deleted

    async def erase(self, history_only=False):
        """Everything the controller sent and who could read it (Forget), or the history alone (Delete history)."""
        await offload(self._erase, history_only)

    def _erase(self, history_only):
        with self.connection:
            for table in ("log_events", "log_marks") + (() if history_only else ("log_access", "meta")):
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
            "select count(*) as rows, min(boot_id) as oldest, max(boot_id) as newest "
            "from log_events where device_id = ?", (device,)).fetchone()
        gaps = self.connection.execute(
            "select count(*) as marks, coalesce(sum(count), 0) as missed "
            "from log_marks where kind = 'gap' and device_id = ?", (device,)).fetchone()
        return {"rows": events["rows"], "bytes": self._used_bytes(), "oldestBoot": events["oldest"],
                "newestBoot": events["newest"], "marks": gaps["marks"], "missed": gaps["missed"]}
