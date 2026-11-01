"""The shot and activation archive: the controller's records, copied to the companion (plan 2A).

The controller keeps its newest 1000 shots and 1000 activations; the archive
keeps everything it has seen, including what rotated out since, and the user
decides what goes. It follows the controller through the link's record
frames (`docs/COMPANION_LINK.md` in the firmware repository): the store index
(`[id, revision]` pairs with the store's generation and next record id),
fetch windows newest first, and each shot's trace once. Its queries run on
the log store's connection and disk thread (logstore.py owns the database).

Rows are keyed by generation. A restarted controller history (Clear, a
factory reset: ids start again) never deletes anything: it closes the
generation, whose rows all stay as archive-only, and opens the next. The
controller's store generation and next record id only grow and fall back
only on a restart, so a decrease of either is one, decided from the index
before any page is written. When both may have overtaken their old values
(a long absence) or the controller does not name them (older firmware), the
fallback compares identities of fetched records (a shot is
`bootId:endedAtMs`, an activation every immutable field): the index's newest
id below the last sync's oldest, or every id it shares with the archive
another record, is a restart; one shared id that differs sets the old record
aside instead of overwriting it, and that pass mirrors no deletion
(ambiguity may duplicate, never lose).

Within the open generation a record is unchanged (same revision), updated
(same identity: a rating; a non-empty curve is never replaced by an empty
one), deleted (missing, `id >= O`, not kept; marked kept instead with Keep
records deleted on the controller) or kept (missing below `O`: rotation, or
a deleted oldest record). The epoch is adopted only once every listed record
is stored, so an interrupted sync resumes with nothing lost or doubled; a
change the user makes meanwhile restarts the pass from the index.
"""

import asyncio
import base64
import binascii
import json
import sqlite3
import time

from . import log, stats
from .index_mirror import IndexMirror
from .logstore import ARCHIVE_TABLES, table_bytes
from .store import offload

STORES = ("history", "shots")  # The sync order: the small store first.
FETCH_MAX = {"shots": 50, "history": 120}
FRESH_S = 8  # How long a Stats header waits for the mirror to reach the controller's epoch.
HEADERS = 16  # Stats headers kept, per window, preset, filters and archive state.
REQUEST_S = 300  # A request unanswered this long is asked again (a long hold only delays it).
TRACE_RETRY_S = 60
RUN_GAP = 3  # Unwanted rows a fetch window may span to join two runs of wanted ones.
NAMES = {"shots": "shot", "history": "activation"}
HISTORY_IDENT = ("type", "durationS", "hasWallTime", "noWeight", "endedAtUnixSec", "endedAtLocalSec")
# Archive-only: a closed generation, below the open one's oldest, or kept (the user removed it from the
# controller; while its delete is still on the way the browser shows the controller's row instead).
ONLY = "(r.generation < :open or r.kept = 1 or (s.oldest is not null and r.id < s.oldest))"
JOIN = ("archive_records r left join archive_sync s on s.device_id = r.device_id and s.store = r.store "
        "and s.generation = r.generation")
COLUMNS = "(device_id, store, generation, id, ident, rev, kind, bad, kept, ended_at, body)"
# Only what the Stats header reads, never the curve.
HEADER_FIELDS = "json_object(" + ", ".join(f"'{name}', json_extract(body, '$.{name}')" for name in stats.FIELDS) + ")"


class Gone(Exception):
    """The link closed: the sync stops and resumes with the next session."""


class Changed(Exception):
    """The user changed the archive during a pass: it starts again from the index."""


class Unavailable(Exception):
    """The Stats header cannot be built now; the browser keeps the controller's."""


def ident(store, fields):
    if store == "shots":
        return f"{fields.get('bootId')}:{fields.get('endedAtMs')}"
    return ":".join(str(fields.get(key, False if key == "noWeight" else None)) for key in HISTORY_IDENT)


def windows(positions, most):
    """Fetch windows (offset, count) covering the wanted index positions, runs joined across small gaps."""
    runs = []
    for position in sorted(positions):
        if runs and position - runs[-1][0] < most and position - (runs[-1][0] + runs[-1][1]) < RUN_GAP:
            runs[-1][1] = position - runs[-1][0] + 1
        else:
            runs.append([position, 1])
    return [tuple(run) for run in runs]


class ArchiveStore:
    """The archive's rows, on the log store's connection (every call on its disk thread).

    `revision` moves with every change the user makes; `synced` with every
    sync that completes or restarts a generation. Caches key on both."""

    def __init__(self, db):
        self.db = db
        self.revision = self.synced = 0
        self.changed = []  # Callbacks run when the user changed something.

    @property
    def connection(self):
        return self.db.connection

    def _call(self, work, *args):
        return offload(work, *args)

    async def _user(self, work):
        """A change the user made: any sync pass in flight starts over, cached answers go."""
        self.revision += 1  # Before the work is queued: a pass's next write sees it (the disk thread is serial).
        result = await self._call(work)
        for callback in self.changed:
            callback()
        return result

    def _open(self, device, store):
        row = self.connection.execute("select max(generation) from archive_sync where device_id = ? and store = ?",
                                      (device, store)).fetchone()
        return row[0] or 1

    def _sync_row(self, device, store, generation):
        return self.connection.execute(
            "select epoch, oldest, listed, restarted, counters from archive_sync where device_id = ? "
            "and store = ? and generation = ?", (device, store, generation)).fetchone()

    def _write(self, statement, args):
        with self.connection:
            return self.connection.execute(statement, args).rowcount

    # --- Sync ------------------------------------------------------------------
    async def sync_state(self, device, store):
        """(open generation, epoch, oldest, last listed ids, last counters) of one store; the open
        generation always has its sync row, so rows never land in one without it."""
        def read():
            generation = self._open(device, store)
            row = self._sync_row(device, store, generation)
            if row is None:
                with self.connection:
                    self.connection.execute("insert into archive_sync values (?, ?, ?, 0, null, '[]', null, null)",
                                            (device, store, generation))
                return generation, 0, None, [], None
            return (generation, row["epoch"], row["oldest"], json.loads(row["listed"]),
                    json.loads(row["counters"]) if row["counters"] else None)
        return await self._call(read)

    async def records(self, device, store, generation):
        """{id: (ident, rev, kept)} of one generation, and its excluded ids."""
        def read():
            rows = {row["id"]: (row["ident"], row["rev"], row["kept"]) for row in self.connection.execute(
                "select id, ident, rev, kept from archive_records where device_id = ? and store = ? "
                "and generation = ?", (device, store, generation))}
            excluded = {row[0] for row in self.connection.execute(
                "select id from archive_exclusions where device_id = ? and store = ? and generation = ?",
                (device, store, generation))}
            return rows, excluded
        return await self._call(read)

    def _aside(self, device, store, generation, record_id):
        """Set a record aside (generation 0 or below, archive-only) instead of overwriting it."""
        lowest = self.connection.execute("select min(generation) from archive_records where device_id = ? "
                                         "and store = ? and id = ?", (device, store, record_id)).fetchone()[0]
        target = min(lowest, 1) - 1
        for table in ("archive_records", "archive_traces"):
            if table == "archive_traces" and store != "shots":
                continue
            self.connection.execute(
                f"update {table} set generation = ? where device_id = ? and generation = ? and id = ?"
                + (" and store = ?" if table == "archive_records" else ""),
                (target, device, generation, record_id) + ((store,) if table == "archive_records" else ()))

    async def put(self, device, store, generation, rows):
        """Rows as (id, ident, rev, fields, curve). A stored record with another identity is never
        overwritten: it is set aside first, with its trace."""
        def write():
            with self.connection:
                for record_id, identity, rev, fields, curve in rows:
                    old = self.connection.execute(
                        "select ident, body, kept from archive_records where device_id = ? and store = ? "
                        "and generation = ? and id = ?", (device, store, generation, record_id)).fetchone()
                    body, kept = {**fields, **curve}, 0
                    if old and old["ident"] == identity:
                        kept, before = old["kept"], json.loads(old["body"])
                        if not curve.get("wD") and before.get("wD"):  # A recycled curve: keep the copy.
                            body = {**before, **fields}
                    elif old:
                        self._aside(device, store, generation, record_id)
                    kind = (fields.get("badReason") or "good") if store == "shots" else str(fields.get("type"))
                    ended = fields.get("endedAtUnixSec") if fields.get("hasWallTime") else 0
                    self.connection.execute(
                        f"insert or replace into archive_records {COLUMNS} values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (device, store, generation, record_id, identity, rev, kind,
                         int(store == "shots" and bool(fields.get("badReason"))), kept,
                         ended if isinstance(ended, int) else 0, json.dumps(body, separators=(",", ":"))))
        await self._call(write)

    def _drop_traces(self, device, generation, ids):
        self.connection.executemany("delete from archive_traces where device_id = ? and generation = ? and id = ?",
                                    ((device, generation, record_id) for record_id in ids))

    async def forget_deleted(self, device, store, generation, ids, keep):
        """Records the controller deleted: gone from the archive, or marked kept (`keep`)."""
        def write():
            with self.connection:
                keys = [(device, store, generation, rid) for rid in ids]
                if keep:
                    self.connection.executemany("update archive_records set kept = 1 where device_id = ? "
                                                "and store = ? and generation = ? and id = ?", keys)
                    return
                self.connection.executemany("delete from archive_records where device_id = ? and store = ? "
                                            "and generation = ? and id = ?", keys)
                if store == "shots":
                    self._drop_traces(device, generation, ids)
        await self._call(write)

    async def restart(self, device, store, generation, counters):
        """Close `generation` and open the next, which starts from the controller's `counters`.
        Returns how many records the closed generation keeps."""
        def write():
            with self.connection:
                self.connection.execute("insert into archive_sync values (?, ?, ?, 0, null, '[]', ?, ?)",
                                        (device, store, generation + 1, time.time(),
                                         json.dumps(counters) if counters else None))
                self.connection.execute("delete from archive_exclusions where device_id = ? and store = ?",
                                        (device, store))
                return self.connection.execute(
                    "select count(*) from archive_records where device_id = ? and store = ? and generation = ?",
                    (device, store, generation)).fetchone()[0]
        kept = await self._call(write)
        self.synced += 1
        return kept

    async def adopt(self, device, store, generation, epoch, oldest, listed, counters):
        """A complete sync: its epoch, the controller's oldest id, the ids it listed and its counters;
        exclusions of ids it no longer lists go."""
        def write():
            with self.connection:
                row = self._sync_row(device, store, generation)
                self.connection.execute("insert or replace into archive_sync values (?, ?, ?, ?, ?, ?, ?, ?)",
                                        (device, store, generation, epoch, oldest, json.dumps(listed),
                                         row["restarted"] if row else None,
                                         json.dumps(counters) if counters else row["counters"] if row else None))
                keep = set(listed)
                stale = [(device, store, generation, rid) for (rid,) in self.connection.execute(
                    "select id from archive_exclusions where device_id = ? and store = ? and generation = ?",
                    (device, store, generation)).fetchall() if rid not in keep]
                self.connection.executemany("delete from archive_exclusions where device_id = ? and store = ? "
                                            "and generation = ? and id = ?", stale)
        await self._call(write)
        self.synced += 1

    async def hole(self, device, store, generation, below, above):
        await self._call(self._write, "insert or ignore into archive_holes values (?, ?, ?, ?, ?, ?, ?)",
                         (device, store, generation, below, above, above - below - 1, time.time()))

    async def missing_traces(self, device, limit=20):
        """The open generation's shots (id, bootId, endedAtMs) without a trace row, newest first."""
        def read():
            rows = self.connection.execute(
                "select r.id, r.ident from archive_records r where r.device_id = ? and r.store = 'shots' "
                "and r.generation = ? and r.ident glob '[0-9]*:[0-9]*' and r.ident not glob '*[^0-9:]*' "
                "and not exists (select 1 from archive_traces t where t.device_id = r.device_id "
                "and t.generation = r.generation and t.id = r.id) order by r.id desc limit ?",
                (device, self._open(device, "shots"), limit)).fetchall()
            return [(row["id"], *map(int, row["ident"].split(":"))) for row in rows]
        return await self._call(read)

    async def put_trace(self, device, record_id, boot, end, data):
        await self._call(lambda: self._write("insert or replace into archive_traces values (?, ?, ?, ?, ?, ?)",
                                             (device, self._open(device, "shots"), record_id, boot, end, data)))

    # --- Reading ---------------------------------------------------------------
    def _generations(self, device, store):
        opened = self._open(device, store)
        restarted = dict(self.connection.execute(
            "select generation, restarted from archive_sync where device_id = ? and store = ?", (device, store)))
        counts = dict(self.connection.execute(
            "select generation, count(*) from archive_records where device_id = ? and store = ? "
            "group by generation", (device, store)))
        return [{"generation": generation, "count": counts.get(generation, 0),
                 "restartedAt": int(restarted[generation]) if restarted.get(generation) else None,
                 "current": generation == opened}
                for generation in sorted(set(restarted) | set(counts) | {opened}, reverse=True)]

    def _order(self, store, sort, direction):
        """The sort key as SQL expressions, compared ascending: the controller's date order is its id
        order within a generation; its rating order puts unrated shots last whatever the direction, then
        the rating, then the newest first (shotLogCompareRatingOrder)."""
        if sort == "rating":
            rating = "coalesce(json_extract(r.body, '$.rating'), 0)"
            return [f"({rating} = 0)", rating if direction == "asc" else f"-{rating}", "-r.generation", "-r.id"]
        return ["r.generation", "r.id"] if direction == "asc" else ["-r.generation", "-r.id"]

    async def tail(self, device, store, query, limit):
        """Archive-only rows filtered and ordered exactly as the controller filters and orders its own
        (shotListFilterMatches, History types), so the browser can merge both streams; `query` holds
        sort, dir, cursor (the previous page's last sort key) and the filters. Returns the rows, the next
        cursor, the holes, the generations and, for shots, the presets found among these rows."""
        def read():
            self.connection.create_function("obbw_scale_key", 1, stats.scale_key, deterministic=True)
            order = self._order(store, query["sort"], query["dir"])
            args = {"device": device, "store": store, "open": self._open(device, store), "limit": limit + 1}
            where = f"r.device_id = :device and r.store = :store and {ONLY}"

            def among(name, expression, values):
                nonlocal where
                where += f" and {expression} in (" + ",".join(f":{name}{n}" for n in range(len(values))) + ")"
                args.update({f"{name}{n}": value for n, value in enumerate(values)})
            if store == "shots":
                if not query["bad"]:
                    where += " and r.bad = 0"
                if query["result"]:
                    where += " and coalesce(json_extract(r.body, '$.arrivalS'), 0) != 0"
                    among("v", "json_extract(r.body, '$.verdict')", query["result"])
                if query["preset"]:
                    among("p", "json_extract(r.body, '$.presetId')", query["preset"])
                if query["scale"]:
                    among("k", "obbw_scale_key(json_extract(r.body, '$.scaleName'))", query["scale"])
            elif query["types"]:
                among("t", "r.kind", query["types"])
            if query["cursor"] is not None:
                where += f" and ({', '.join(order)}) > ({', '.join(f':c{n}' for n in range(len(order)))})"
                args.update({f"c{n}": value for n, value in enumerate(query["cursor"])})
            keys = ", ".join(f"{expression} as k{n}" for n, expression in enumerate(order))
            rows = self.connection.execute(
                f"select r.generation, r.id, r.body, {keys} from {JOIN} where {where} "
                f"order by {', '.join(f'k{n}' for n in range(len(order)))} limit :limit", args).fetchall()
            bodies = []
            for row in rows[:limit]:
                body = {**json.loads(row["body"]), "archiveGeneration": row["generation"]}
                if store == "shots":
                    body["archiveTrace"] = self.connection.execute(
                        "select 1 from archive_traces where device_id = ? and generation = ? and id = ? "
                        "and data is not null", (device, row["generation"], row["id"])).fetchone() is not None
                bodies.append(body)
            last = rows[limit - 1] if len(rows) > limit else None
            following = ":".join(str(last[f"k{n}"]) for n in range(len(order))) if last else None
            holes = [dict(row) for row in self.connection.execute(
                "select generation, below, above, count from archive_holes where device_id = ? and store = ? "
                "order by generation desc, below desc", (device, store))]
            presets = None
            if store == "shots":
                presets, seen = [], set()
                for preset, name in self.connection.execute(
                        f"select json_extract(r.body, '$.presetId'), json_extract(r.body, '$.presetName') "
                        f"from {JOIN} where r.device_id = :device and r.store = 'shots' and r.bad = 0 and {ONLY} "
                        "order by r.generation desc, r.id desc", args):
                    if preset is not None and preset not in seen and len(presets) < 8:
                        seen.add(preset)
                        presets.append([preset, name])
            return bodies, following, holes, self._generations(device, store), presets
        return await self._call(read)

    async def trace(self, device, record_id, boot, end):
        row = await self._call(lambda: self.connection.execute(
            "select data from archive_traces where device_id = ? and id = ? and boot_id = ? and ended_ms = ? "
            "order by generation desc limit 1", (device, record_id, boot, end)).fetchone())
        return row["data"] if row else None

    async def merged(self, device):
        """The whole history the Stats header counts, newest first by (generation, id): every stored shot
        and every one removed from the archive alone that the controller still holds, with only the
        fields the header reads."""
        def read():
            rows = self.connection.execute(
                f"select generation, id, {HEADER_FIELDS} from archive_records where device_id = ? "
                "and store = 'shots' union all select generation, id, body from archive_exclusions "
                "where device_id = ? and store = 'shots' and body is not null "
                "order by 1 desc, 2 desc", (device, device))
            return [json.loads(row[2]) for row in rows]
        return await self._call(read)

    # --- The user's changes ------------------------------------------------------
    async def rate(self, device, generation, record_id, rating):
        """Rate an archive-only shot (the controller rates the ones it holds); False when there is none."""
        def write():
            opened = self._open(device, "shots")
            key = {"device": device, "g": opened if generation is None else generation, "i": record_id,
                   "open": opened}
            if self.connection.execute(f"select 1 from {JOIN} where r.device_id = :device and r.store = 'shots' "
                                       f"and r.generation = :g and r.id = :i and {ONLY}", key).fetchone() is None:
                return False
            self._write("update archive_records set body = json_set(body, '$.rating', ?) where device_id = ? "
                        "and store = 'shots' and generation = ? and id = ?", (rating, device, key["g"], record_id))
            return True
        return await self._user(write)

    async def keep(self, device, store, record_id, kept=True):
        """Mark an open-generation record kept before the controller deletes it, or unmark it when the
        controller refused the delete; False when the archive has not copied it (yet)."""
        return await self._user(lambda: self._write(
            "update archive_records set kept = ? where device_id = ? and store = ? and generation = ? and id = ?",
            (int(kept), device, store, self._open(device, store), record_id)) > 0)

    def _remove(self, device, store, keys):
        """Delete these (generation, id) rows with their traces. An open-generation id the controller may
        still hold (at or above the synced oldest, or any before the first complete sync; not a kept row
        its last index no longer lists) gets an exclusion, so it is not copied again, with the fields the
        whole-history Stats header counts; one not copied yet gets it too, without them. Returns how
        many records went, the excluded ones included."""
        opened = self._open(device, store)
        row = self._sync_row(device, store, opened)
        oldest, gone = row["oldest"] if row else None, 0
        listed = set(json.loads(row["listed"])) if row else set()
        for generation, record_id in keys:
            key = (device, store, generation, record_id)
            held = self.connection.execute("select kept from archive_records where device_id = ? and store = ? "
                                           "and generation = ? and id = ?", key).fetchone()
            excluded = generation == opened and (oldest is None or record_id >= oldest) and not (
                held and held["kept"] and record_id not in listed)
            if excluded:
                self.connection.execute(
                    "insert or replace into archive_exclusions values (?, ?, ?, ?, (select "
                    + (HEADER_FIELDS if store == "shots" else "null")
                    + " from archive_records where device_id = ? and store = ? and generation = ? and id = ?))",
                    key + key)
            deleted = self.connection.execute(
                "delete from archive_records where device_id = ? and store = ? and generation = ? and id = ?",
                key).rowcount
            gone += deleted or excluded
            if store == "shots":
                self._drop_traces(device, generation, (record_id,))
        return gone

    async def remove(self, device, store, generation, record_id):
        """Delete one record from the archive; False when there is none."""
        def write():
            with self.connection:
                return self._remove(device, store, [(self._open(device, store) if generation is None
                                                     else generation, record_id)]) > 0
        return await self._user(write)

    async def erase(self, device, store=None, generation=None, current=False, since=None, until=None):
        """Bulk delete. With no scope, everything: the file is rewritten and what the controller still keeps
        is copied again. A scope keeps the removed records from coming back while the controller holds
        them. Returns how many records went."""
        def everything():
            gone = self.connection.execute("select count(*) from archive_records").fetchone()[0]
            with self.connection:
                for table in ARCHIVE_TABLES:
                    self.connection.execute(f"delete from {table}")
            try:  # The delete stands; a backup reading the file meanwhile only leaves free pages behind.
                self.connection.execute("vacuum")
                self.connection.execute("pragma wal_checkpoint(truncate)")
            except sqlite3.OperationalError as error:
                log(f"the archive's space could not be given back yet ({error}); the next erase does it")
            return gone

        def scoped():
            gone = 0
            with self.connection:
                for name in (store,) if store else STORES:
                    opened = self._open(device, name)
                    where, args = "device_id = ? and store = ?", [device, name]
                    if current or generation is not None:
                        where += " and generation = ?"
                        args.append(opened if current else generation)
                    if since is not None or until is not None:  # Only records with a wall clock have a date.
                        where += " and ended_at > 0 and ended_at between ? and ?"
                        args += [since or 0, 2 ** 32 if until is None else until]
                    keys = self.connection.execute(f"select generation, id from archive_records where {where}",
                                                   args).fetchall()
                    gone += self._remove(device, name, [tuple(key) for key in keys])
                    for table in ("archive_sync", "archive_holes"):  # A closed generation left empty goes.
                        self.connection.execute(
                            f"delete from {table} where device_id = ? and store = ? and generation < ? and not "
                            f"exists (select 1 from archive_records r where r.device_id = {table}.device_id and "
                            f"r.store = {table}.store and r.generation = {table}.generation)", (device, name, opened))
            return gone
        unscoped = store is None and generation is None and not current and since is None and until is None
        return await self._user(everything if unscoped else scoped)

    async def keep_deleted(self):
        row = await self._call(lambda: self.connection.execute(
            "select value from meta where key = 'archiveKeepDeleted'").fetchone())
        return bool(row and row[0] == "1")

    async def set_keep_deleted(self, on):
        await self._user(lambda: self._write("insert or replace into meta values ('archiveKeepDeleted', ?)",
                                             ("1" if on else "0",)))

    # --- Facts and export ----------------------------------------------------------
    async def stats(self, device):
        def read():
            facts = {"bytes": table_bytes(self.connection, ARCHIVE_TABLES), "generations": {}}
            for store in STORES:
                row = self.connection.execute(
                    f"select count(*) as total, coalesce(sum({ONLY}), 0) as only, "
                    "min(nullif(r.ended_at, 0)) as first, max(nullif(r.ended_at, 0)) as last "
                    f"from {JOIN} where r.device_id = :device and r.store = :store",
                    {"device": device, "store": store, "open": self._open(device, store)}).fetchone()
                facts[store], facts[store + "Total"] = row["only"], row["total"]
                facts[store + "First"], facts[store + "Last"] = row["first"], row["last"]
                facts["generations"][store] = self._generations(device, store)
            facts["traces"] = self.connection.execute(
                "select count(*) from archive_traces where device_id = ? and data is not null",
                (device,)).fetchone()[0]
            facts["holes"] = self.connection.execute(
                "select coalesce(sum(count), 0) from archive_holes where device_id = ?", (device,)).fetchone()[0]
            return facts
        return await self._call(read)

    async def chunk(self, device, store, after, limit=200):
        """The next rows of an export, oldest first by (generation, id): (bodies, cursor), cursor None at the end."""
        rows = await self._call(lambda: self.connection.execute(
            "select generation, id, kept, body from archive_records where device_id = ? and store = ? "
            "and (generation, id) > (?, ?) order by generation, id limit ?",
            (device, store, *after, limit)).fetchall())
        return ([{**json.loads(row["body"]), "archiveGeneration": row["generation"], "archiveKept": bool(row["kept"])}
                 for row in rows], (rows[-1]["generation"], rows[-1]["id"]) if rows else None)

    async def trace_chunk(self, device, after, limit=50):
        rows = await self._call(lambda: self.connection.execute(
            "select generation, id, boot_id, ended_ms, data from archive_traces where device_id = ? "
            "and data is not null and (generation, id) > (?, ?) order by generation, id limit ?",
            (device, *after, limit)).fetchall())
        return ([{"generation": row["generation"], "id": row["id"], "boot": row["boot_id"], "end": row["ended_ms"],
                  "data": base64.b64encode(row["data"]).decode()} for row in rows],
                (rows[-1]["generation"], rows[-1]["id"]) if rows else None)

    async def holes(self, device):
        return await self._call(lambda: [dict(row) for row in self.connection.execute(
            "select store, generation, below, above, count from archive_holes where device_id = ? "
            "order by store, generation, below", (device,))])


class Archive:
    """The sync: one store at a time over the link, activations first, then shots, then traces."""

    def __init__(self, companion):
        self.companion = companion
        self.store = ArchiveStore(companion.logs)
        self.store.changed.append(self._user_changed)
        self.available = False  # The controller's firmware has the archive (its cfg names the switch).
        self.on = False  # ...and the switch is on.
        self.notified = {}  # The epochs of the controller's last `rs`, per store.
        self.subscribed = False  # This session's rx went out.
        self.mirrors = {store: IndexMirror(f"archive's {store} index") for store in STORES}
        self.wanted = set()
        self.wake = asyncio.Event()
        self.task = self.retry = None
        self.waiters, self.pages, self.request = {}, {}, 0
        self.syncing, self.synced_at, self.error = None, None, None
        self.trace_wait, self.busy_until = {}, 0.0  # Traces not given yet: asked again after these.
        self.headers, self.complete = {}, {}  # Stats headers: by full key, and the last whole one per view.
        self.facts_cache, self.unavailable_at = None, None

    def usable(self):
        return self.companion._log_usable() and self.companion.device_id is not None

    def _user_changed(self):
        self.headers.clear()
        self.complete.clear()
        self.wake.set()  # A pass in flight sees the change and starts again from the index.

    # --- Session -----------------------------------------------------------------
    def configure(self, cfg):
        """`cfg`: the switch. Off stops the sync and keeps everything stored."""
        self.available, self.on = "archive" in cfg, cfg.get("archive") is True
        if self.on:
            self.start()
        else:
            self.stop()

    def start(self):
        """Once per session, after `cfg` turned it on and `dev` named the controller: both stores' index."""
        if not self.on or self.subscribed or not self.usable() or self.companion.outbox is None:
            return
        self.subscribed, self.notified = True, {}
        self.wanted = set(STORES)
        for mirror in self.mirrors.values():
            mirror.session()
        if self.task is None or self.task.done():
            self.task = self.companion.spawn(self._run())
        self.wake.set()

    def stop(self):
        """The session ended or the switch went off: what is in flight is asked again next time."""
        self.subscribed = False
        for task in (self.task, self.retry):
            if task is not None:
                task.cancel()
        self.task = self.retry = None
        for waiter in self.waiters.values():
            waiter.cancel()
        self.waiters, self.pages, self.syncing = {}, {}, None

    # --- Frames from the controller ------------------------------------------------
    def on_rs(self, frame):
        if not self.subscribed:
            return
        for store, key in (("shots", "sh"), ("history", "hi")):
            if type(frame.get(key)) is int:
                self.notified[store] = frame[key]
                self.wanted.add(store)
        self.trace_wait, self.busy_until = {}, 0.0  # A notice is when a trace not given yet is asked again.
        self.wake.set()

    def refresh(self, store, epoch):
        """The controller's store is at `epoch` (a screen's live Stats frames, a Stats header asked for
        it): sync now instead of at the next notice. The request leaves with the next clear frame."""
        if self.subscribed and type(epoch) is int:
            self.notified[store] = epoch
            self.wanted.add(store)
            self.wake.set()

    def on_rec(self, frame):
        inner = frame.get("f")
        if not isinstance(inner, dict):
            return
        kind = inner.get("type")
        if kind == "records":
            self._resolve(("records", inner.get("store")), inner)
        elif kind == "history":
            if isinstance(inner.get("records"), list):
                self._resolve(("page", inner.get("request")), [r for r in inner["records"] if isinstance(r, dict)])
        elif kind == "stats":
            self._stats_frame(inner)

    def on_trc(self, frame):
        self._resolve(("trace", frame.get("id"), frame.get("b"), frame.get("e")), frame)

    def _resolve(self, key, value):
        waiter = self.waiters.pop(key, None)
        if waiter is not None and not waiter.done():
            waiter.set_result(value)

    def _stats_frame(self, frame):
        """A fetch page arrives in frames sharing `seq`; a new seq at rowBase 0 restarts it."""
        request, rows = frame.get("request"), frame.get("rows")
        if not isinstance(rows, list):
            return
        page = self.pages.get(request)
        if frame.get("rowBase") == 0 and isinstance(frame.get("cols"), str):
            page = self.pages[request] = {"seq": frame.get("seq"), "cols": frame["cols"].split(","), "rows": []}
        elif page is None or page["seq"] != frame.get("seq"):
            return
        for values in rows:
            if isinstance(values, list) and len(values) == len(page["cols"]) + 1 and isinstance(values[-1], dict):
                page["rows"].append((dict(zip(page["cols"], values[:-1])), values[-1]))
        if frame.get("more") is not True:
            self._resolve(("page", request), self.pages.pop(request)["rows"])

    async def _ask(self, frame, key):
        """Send a request and wait for its answer, asking again after REQUEST_S."""
        while True:
            waiter = asyncio.get_running_loop().create_future()
            self.waiters[key] = waiter
            if not self.companion.post_sync(frame, "archive"):
                raise Gone()
            try:
                return await asyncio.wait_for(waiter, REQUEST_S)
            except asyncio.TimeoutError:
                log(f"the controller did not answer the archive's {frame['t']} request; asking again")

    # --- The sync ------------------------------------------------------------------
    async def _run(self):
        try:
            while True:
                await self.wake.wait()
                self.wake.clear()
                try:
                    for store in STORES:
                        if store in self.wanted:
                            self.wanted.discard(store)
                            self.syncing = store
                            try:
                                await self._sync(store)
                            except Changed:
                                self.wanted.add(store)
                                self.wake.set()
                    self.syncing = "traces"
                    await self._traces()
                    self.synced_at, self.error = time.time(), None
                except Exception as error:  # A disk error or a bad answer: the next notice retries.
                    if isinstance(error, Gone):
                        raise
                    self.error = str(error)
                    log(f"the archive sync stopped ({error}); it resumes at the controller's next notice")
                finally:
                    self.syncing = None
        except Gone:
            pass

    def _steady(self, revision):
        """The user has not changed the archive since this pass started."""
        if self.store.revision != revision:
            raise Changed()

    async def _restart(self, store, generation, counters, revision):
        self._steady(revision)
        kept = await self.store.restart(self.companion.device_id, store, generation, counters)
        log(f"the controller's {NAMES[store]} history restarted; the archive keeps its {kept} earlier record(s)")
        return generation + 1

    async def _fetch(self, store, order, listed, ids, sink=None):
        """The records `ids` (positions in `order`), as (id, ident, rev, fields, curve), by fetch windows;
        with a `sink`, each page goes there as it arrives instead (so a broken-off pass keeps it)."""
        wanted, found = set(ids), []
        for offset, count in windows([i for i, rid in enumerate(order) if rid in wanted], FETCH_MAX[store]):
            self.request = (self.request + 1) % 2 ** 32 or 1
            page = await self._ask({"t": "rf", "s": store, "o": offset, "n": count, "r": self.request},
                                   ("page", self.request))
            rows = []
            for fields, curve in (page if store == "shots" else ((record, {}) for record in page)):
                rid = fields.get("id")
                if rid in wanted:
                    wanted.discard(rid)
                    rows.append((rid, ident(store, fields), listed[rid], fields, curve))
            if sink is None:
                found += rows
            else:
                await sink(rows)
        return found, wanted

    async def _sync(self, store):
        device, revision = self.companion.device_id, self.store.revision
        generation, epoch, oldest, previous, counters = await self.store.sync_state(device, store)
        if epoch and self.notified.get(store) == epoch:
            return  # The notice names the epoch this archive already holds.
        # A delta only against the index this mirror holds for that same epoch; one it cannot rebuild
        # asks the whole index once.
        mirror, ask = self.mirrors[store], {"t": "rx", "s": store, "ep": epoch or 0}
        delta = mirror.delta(ask["ep"])
        index = mirror.apply(await self._ask({**ask, "d": 1} if delta else ask, ("records", store)))
        if index is None and delta:
            index = mirror.apply(await self._ask({**ask, "ep": 0}, ("records", store)))
        if index is None:
            raise ValueError("a malformed record index")
        rows, new_epoch = index.get("rows"), index.get("epoch")
        if rows is None or type(new_epoch) is not int:
            return  # Unchanged since the epoch this archive holds.
        named = [index.get("gen"), index.get("next")]
        named = named if all(type(value) is int for value in named) else None
        listed, order = dict(zip(rows[0::2], rows[1::2])), rows[0::2]
        # Exact, and decided before anything is written (an empty index included, so the counters
        # stored never fall back): either counter fell back.
        restarted = bool(named and counters and (named[0] < counters[0] or named[1] < counters[1]))
        if not listed:  # Nothing to compare ids with: everything stays until the store records again.
            if restarted:
                generation, oldest, previous = await self._restart(store, generation, named, revision), None, []
            self._steady(revision)
            await self.store.adopt(device, store, generation, new_epoch, oldest, previous, named)
            return
        low, high = min(listed), max(listed)
        # Fallback: ids that cannot come after the last sync's oldest.
        if not restarted and oldest is not None and high < oldest:
            restarted = True
        if restarted:
            generation = await self._restart(store, generation, named, revision)
        archived, excluded = await self.store.records(device, store, generation)
        newest = max(archived) if archived else None
        shared = [rid for rid in order if rid in archived]
        # Shared records first, decided before anything new is written: a changed revision is a rating,
        # or another record under a reused id. One that differs needs every shared one to decide.
        found, missing = await self._fetch(store, order, listed,
                                           [rid for rid in shared if archived[rid][1] != listed[rid]])
        replaced = [row for row in found if archived[row[0]][0] != row[1]]
        if replaced:
            more, still = await self._fetch(store, order, listed, [rid for rid in shared if archived[rid][1] == listed[rid]])
            found, missing = found + more, missing | still
            replaced = [row for row in found if archived[row[0]][0] != row[1]]
        if missing:
            return  # A record arrived or went meanwhile: the next notice finishes the sync.
        ambiguous = bool(replaced) and len(replaced) < len(shared)
        if replaced and not ambiguous:
            restarted = True  # Every shared id is another record.
            generation = await self._restart(store, generation, named, revision)
            archived, excluded = {}, set()
        for row in replaced if ambiguous else ():
            log(f"the controller's {NAMES[store]} {row[0]} may be a different record now; the archive keeps "
                "both")
        self._steady(revision)
        await self.store.put(device, store, generation, found)  # An ambiguous old record is set aside.
        fetched = {row[0] for row in found}

        async def page(rows):
            self._steady(revision)
            await self.store.put(device, store, generation, rows)
        _, missing = await self._fetch(store, order, listed, [rid for rid in order if rid not in archived
                                                              and rid not in excluded and rid not in fetched], page)
        if missing:
            return
        if not restarted and not ambiguous:  # A pass that could not tell records apart mirrors no deletion.
            gone = [rid for rid, (_, _, kept) in archived.items() if rid not in listed and rid >= low and not kept]
            await self.store.forget_deleted(device, store, generation, gone, await self.store.keep_deleted())
        if not restarted and newest is not None and newest < low - 1:
            await self.store.hole(device, store, generation, newest, low)
            log(f"up to {low - newest - 1} {NAMES[store]} record(s) rotated out of the controller before they "
                "could be copied")
        self._steady(revision)
        await self.store.adopt(device, store, generation, new_epoch, low, order, named)

    async def _traces(self):
        """Each shot's trace once, newest first. One still being saved, or a controller too busy to read
        its storage, is asked again only after the next notice or TRACE_RETRY_S."""
        device, now = self.companion.device_id, time.monotonic()
        if now < self.busy_until:
            return
        while True:
            missing = [entry for entry in await self.store.missing_traces(device, len(self.trace_wait) + 20)
                       if self.trace_wait.get(entry, 0) <= now]
            if not missing:
                break
            for entry in missing:
                record_id, boot, end = entry
                answer = await self._ask({"t": "rt", "id": record_id, "b": boot, "e": end},
                                         ("trace", record_id, boot, end))
                result = answer.get("r")
                if result == "ok":
                    try:
                        data = base64.b64decode(answer.get("d") or "", validate=True)
                    except (binascii.Error, ValueError):
                        data = b""
                    if data:
                        self.trace_wait.pop(entry, None)
                        await self.store.put_trace(device, record_id, boot, end, data)
                        continue
                elif result == "none":
                    self.trace_wait.pop(entry, None)
                    await self.store.put_trace(device, record_id, boot, end, None)
                    continue
                elif result == "saving":
                    self.trace_wait[entry] = now + TRACE_RETRY_S
                    continue
                self.busy_until = now + TRACE_RETRY_S  # Busy, or an answer it could not use.
                break
            if self.busy_until > now:
                break
        if (self.trace_wait or self.busy_until > now) and (self.retry is None or self.retry.done()):
            self.retry = self.companion.spawn(self._later())

    async def _later(self):
        await asyncio.sleep(TRACE_RETRY_S)
        self.wake.set()

    # --- Stats over the whole history ------------------------------------------------
    async def header(self, window, active, epoch, filters):
        """The Stats header the firmware would build over the merged history, and how many good shots
        the filters keep, once the mirror is at the controller's `epoch`. While the controller holds sync
        (or a request waits for it), the newest complete header answers at once, with its own epoch."""
        if not self.on or not self.usable():
            raise Unavailable("the archive is off or its store is closed")
        device, view = self.companion.device_id, (window, active, filters)
        synced = (await self.store.sync_state(device, "shots"))[1]
        if synced != epoch:
            self.refresh("shots", epoch)
            deadline = time.monotonic() + FRESH_S
            while synced != epoch and not self.companion.sync_blocked() and time.monotonic() < deadline:
                await asyncio.sleep(0.1)
                synced = (await self.store.sync_state(device, "shots"))[1]
            if synced != epoch:
                if not self.companion.sync_blocked():
                    raise Unavailable(f"the copy is at shot epoch {synced}, the controller at {epoch}")
                if view in self.complete:
                    return self.complete[view]
        key = view + (self.store.revision, synced)
        if key not in self.headers:
            rows = await self.store.merged(device)
            built = await asyncio.to_thread(lambda: (stats.header(rows, window, active), stats.good(rows, *filters)))
            if len(self.headers) >= HEADERS:
                self.headers.pop(next(iter(self.headers)))
            self.headers[key] = (*built, synced)
        if synced == epoch:
            if view not in self.complete and len(self.complete) >= HEADERS:
                self.complete.pop(next(iter(self.complete)))
            self.complete[view] = self.headers[key]
        return self.headers[key]

    def note_unavailable(self, error):
        """One log line per cause at most every five minutes: screens fall back without a word."""
        if self.unavailable_at is None or time.monotonic() - self.unavailable_at >= 300:
            self.unavailable_at = time.monotonic()
            log(f"the Stats header over the whole history is unavailable ({error}); screens show the "
                "controller's")

    # --- Facts -----------------------------------------------------------------------
    async def facts(self):
        facts = {"on": self.on, "available": self.available,
                 "syncing": self.syncing, "syncedAt": self.synced_at, "error": self.error}
        if self.usable():
            key = (self.companion.device_id, self.store.revision, self.store.synced)
            if self.facts_cache is None or self.facts_cache[0] != key:
                self.facts_cache = (key, {**await self.store.stats(self.companion.device_id),
                                          "keepDeleted": await self.store.keep_deleted()})
            facts.update(self.facts_cache[1])
        return facts
