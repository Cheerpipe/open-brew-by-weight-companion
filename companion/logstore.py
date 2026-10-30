"""The controller's diagnostic log, persisted: SQLite under <data>/companion.db.

WAL, `user_version` migrations, and every call on the secrets store's single
disk thread, so the event loop never waits on the filesystem and writes stay
ordered. The sync cursor is the newest stored row, never separate state; gaps
the ring overwrote and rings cleared below the cursor are stored as mark rows,
so the history names its holes instead of hiding them. Retention prunes by age
and size, oldest first, on start and daily (docs/plans/2026-10-27-companion.md,
G and 12.3). This is the SQLite foundation step 3.2 planned for the archive;
its record tables arrive as later migrations.
"""

import sqlite3
import time

from .store import offload

SCHEMA = 1
PRUNE_STEP = 500  # Rows per delete round while trimming to the size budget.


def _entry(row):
    return {"s": row["sequence"], "ms": row["at_ms"], "w": row["wall_sec"],
            "l": row["level"], "c": row["category"], "m": row["message"]}


class LogStore:
    def __init__(self, data):
        self.path = data / "companion.db"
        self.connection = None

    # --- Lifecycle -----------------------------------------------------------
    async def open(self):
        await offload(self._open)

    def _open(self):
        self.connection = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("pragma journal_mode=wal")
        self.connection.execute("pragma synchronous=normal")
        if self.connection.execute("pragma user_version").fetchone()[0] != SCHEMA:
            self.connection.executescript(f"""
                begin;
                create table if not exists log_events (
                    device_id text not null, boot_id integer not null,
                    sequence integer not null, at_ms integer not null,
                    wall_sec integer not null, level text not null,
                    category text not null, message text not null,
                    primary key (device_id, boot_id, sequence)) without rowid;
                create table if not exists log_marks (
                    device_id text not null, boot_id integer not null,
                    after_sequence integer not null, kind text not null,
                    count integer not null, noted real not null,
                    primary key (device_id, boot_id, after_sequence)) without rowid;
                create index if not exists log_events_page
                    on log_events (device_id, boot_id, sequence);
                pragma user_version = {SCHEMA};
                commit;
            """)

    async def close(self):
        await offload(self._close)

    def _close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    # --- Sync ----------------------------------------------------------------
    async def adopt(self, device):
        """Move rows gathered under the fallback key to the controller's real id.

        The first frames of a first pairing can arrive before its `dev` frame
        named the id; this runs once when the id appears.
        """
        await offload(self._adopt, device)

    def _adopt(self, device):
        with self.connection:
            for table in ("log_events", "log_marks"):
                self.connection.execute(f"update {table} set device_id = ? where device_id = 'controller'",
                                        (device,))

    async def apply(self, device, frame):
        """One controller `log` frame: its events, and any gap or reset it names."""
        return await offload(self._apply, device, frame)

    def _apply(self, device, frame):
        boot = frame["b"]
        with self.connection:
            if frame.get("reset") is True:
                # A cleared ring restarts its sequences: the earlier rows of
                # this boot are gone by the user's own hand, like a Clear
                # history clears the archive.
                self.connection.execute("delete from log_events where device_id = ? and boot_id = ?",
                                        (device, boot))
                self.connection.execute("delete from log_marks where device_id = ? and boot_id = ?",
                                        (device, boot))
                self.connection.execute(
                    "insert or replace into log_marks values (?, ?, 0, 'reset', 0, ?)",
                    (device, boot, time.time()))
            if frame.get("miss"):
                cursor = self._cursor(device)
                if cursor is not None:
                    self.connection.execute(
                        "insert or replace into log_marks values (?, ?, ?, 'gap', ?, ?)",
                        (device, cursor[0], cursor[1], int(frame["miss"]), time.time()))
            self.connection.executemany(
                "insert or replace into log_events values (?, ?, ?, ?, ?, ?, ?, ?)",
                ((device, boot, entry[0], entry[1], entry[2], entry[3], entry[4], entry[5])
                 for entry in frame["e"]))

    async def cursor(self, device):
        """The newest stored (boot, sequence): the resume point for `logsub`."""
        return await offload(self._cursor, device)

    def _cursor(self, device):
        row = self.connection.execute(
            "select boot_id, sequence from log_events where device_id = ? "
            "order by boot_id desc, sequence desc limit 1", (device,)).fetchone()
        return (row["boot_id"], row["sequence"]) if row else None

    # --- Reading -------------------------------------------------------------
    async def page(self, device, before_boot, before_sequence, limit):
        """One page of the merged history, newest first, with its markers.

        Returns (entries, next, has_more): `next` is the (boot, sequence) the
        following page continues from, None at the end. A boot marker precedes
        each older boot's first event; a gap marker sits between the events its
        `after_sequence` separates.
        """
        return await offload(self._page, device, before_boot, before_sequence, limit)

    def _page(self, device, before_boot, before_sequence, limit):
        rows = self.connection.execute(
            "select * from log_events where device_id = ? and (boot_id < ? or "
            "(boot_id = ? and sequence < ?)) order by boot_id desc, sequence desc limit ?",
            (device, before_boot, before_boot, before_sequence, limit + 1)).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        marks = {(row["boot_id"], row["after_sequence"]): row for row in self.connection.execute(
            "select * from log_marks where device_id = ?", (device,))}
        cleared = {row["boot_id"] for row in marks.values() if row["kind"] == "reset"}
        entries, previous, emitted = [], (before_boot, before_sequence), False
        for row in rows:
            marker = None
            if row["boot_id"] != previous[0]:
                marker = {"g": "boot", "boot": row["boot_id"]}
            else:
                # A gap names the last event before it: walking newest first,
                # its marker lands right above that event.
                mark = marks.get((row["boot_id"], row["sequence"]))
                if mark is not None and mark["kind"] == "gap" and mark["count"] > 0:
                    marker = {"g": "gap", "after": row["sequence"], "count": mark["count"]}
            # The first page's sentinel cursor names no real boundary.
            if marker is not None and (emitted or before_boot < 2 ** 31):
                entries.append(marker)
            if row["sequence"] == 1 and row["boot_id"] in cleared:
                entries.append({"g": "reset"})
            entries.append({"b": row["boot_id"], **_entry(row)})
            emitted = True
            previous = (row["boot_id"], row["sequence"])
        following = (rows[-1]["boot_id"], rows[-1]["sequence"]) if rows else None
        return entries, (following if has_more else None), has_more

    async def chunk(self, device, after_boot, after_sequence, limit=1000):
        """The next oldest-first chunk for a streaming export; empty at the end."""
        return await offload(self._chunk, device, after_boot, after_sequence, limit)

    def _chunk(self, device, after_boot, after_sequence, limit):
        rows = self.connection.execute(
            "select * from log_events where device_id = ? and (boot_id > ? or "
            "(boot_id = ? and sequence > ?)) order by boot_id asc, sequence asc limit ?",
            (device, after_boot, after_boot, after_sequence, limit)).fetchall()
        return [{"b": row["boot_id"], **_entry(row)} for row in rows]

    # --- Retention -----------------------------------------------------------
    async def prune(self, days, megabytes):
        """By age first, then to the size budget, oldest first; returns rows deleted."""
        return await offload(self._prune, days, megabytes)

    def _used_bytes(self):
        count = self.connection.execute("pragma page_count").fetchone()[0]
        free = self.connection.execute("pragma freelist_count").fetchone()[0]
        return (count - free) * self.connection.execute("pragma page_size").fetchone()[0]

    def _prune(self, days, megabytes):
        deleted = 0
        cutoff = time.time() - days * 86400
        budget = megabytes * 1024 * 1024
        with self.connection:
            deleted += self.connection.execute(
                "delete from log_events where wall_sec != 0 and wall_sec < ?",
                (cutoff,)).rowcount
            while self._used_bytes() > budget:
                gone = self.connection.execute(
                    "delete from log_events where (boot_id, sequence) in "
                    "(select boot_id, sequence from log_events "
                    "order by boot_id asc, sequence asc limit ?)", (PRUNE_STEP,)).rowcount
                deleted += gone
                if gone == 0:
                    break
            # A boot whose events aged out takes its marks with it.
            self.connection.execute(
                "delete from log_marks where not exists "
                "(select 1 from log_events e where e.device_id = log_marks.device_id "
                "and e.boot_id = log_marks.boot_id) and after_sequence != 0")
        if deleted > 0:
            # Deleting the oldest events frees pages in the middle of the file,
            # where incremental vacuum cannot reach: a full vacuum is the only
            # way the size budget becomes real bytes on disk.
            self.connection.execute("vacuum")
        self.connection.execute("pragma wal_checkpoint(truncate)")
        return deleted

    async def stats(self):
        return await offload(self._stats)

    def _stats(self):
        events = self.connection.execute(
            "select count(*) as rows, min(boot_id) as oldest, max(boot_id) as newest "
            "from log_events").fetchone()
        gaps = self.connection.execute(
            "select count(*) as marks, coalesce(sum(count), 0) as missed "
            "from log_marks where kind = 'gap'").fetchone()
        bytes_ = self.connection.execute("pragma page_count").fetchone()[0] * \
            self.connection.execute("pragma page_size").fetchone()[0]
        return {"rows": events["rows"], "bytes": bytes_, "oldestBoot": events["oldest"],
                "newestBoot": events["newest"], "marks": gaps["marks"], "missed": gaps["missed"]}
