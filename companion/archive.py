"""The shot and activation archive: the controller's records, copied to the companion (plan 2A).

The controller keeps its newest 1000 shots and 1000 activations; the archive
keeps everything it has seen, including what rotated out since, and the user
decides what goes. It follows the controller through the link's record
frames (`docs/COMPANION_LINK.md` in the firmware repository): the store index
(`[id, revision]` pairs), fetch windows newest first, and each shot's trace
once. Its queries run on the log store's connection and disk thread
(logstore.py owns the database).

Rows are keyed by generation. Identity: a shot is `bootId:endedAtMs`, an
activation every immutable field of its record. From an index `I` with
oldest id `O`, a record of the open generation is unchanged (same revision),
updated (same identity: a rating; a non-empty curve is never replaced by an
empty one), replaced (another identity: that record alone), deleted
(missing, `id >= O`, not kept; marked kept instead with Keep records deleted
on the controller) or kept (missing below `O`: rotation, or a deleted oldest
record). A restarted controller history (Clear, a factory reset: ids start
again) never deletes anything: it closes the generation, whose rows all stay
as archive-only, and opens the next. It needs more than one record of
evidence: the index's newest id below the last complete sync's oldest, every
id it shares with the archive replaced, or more than half of the last index's
records missing at or above `O`. An empty index changes nothing. The epoch is
adopted only once every listed record is stored, so an interrupted sync
resumes with nothing lost or doubled.
"""

import asyncio
import base64
import binascii
import json
import time
import zlib

from . import log, stats
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
# Archive-only: a closed generation, below the open one's oldest, or kept and no longer listed.
ONLY = ("(r.generation < :open or (s.oldest is not null and (r.id < s.oldest or (r.kept = 1 and not exists "
        "(select 1 from json_each(s.listed) j where j.value = r.id)))))")
JOIN = ("archive_records r left join archive_sync s on s.device_id = r.device_id and s.store = r.store "
        "and s.generation = r.generation")


class Gone(Exception):
    """The link closed: the sync stops and resumes with the next session."""


class Unavailable(Exception):
    """The Stats header cannot be built now; the browser keeps the controller's."""


def ident(store, fields):
    if store == "shots":
        return f"{fields.get('bootId')}:{fields.get('endedAtMs')}"
    return ":".join(str(fields.get(key, False if key == "noWeight" else None)) for key in HISTORY_IDENT)


def windows(positions, most):
    """Fetch windows (offset, count) covering the wanted index positions, runs joined across small gaps."""
    runs = []
    for position in positions:
        if runs and position - runs[-1][0] < most and position - (runs[-1][0] + runs[-1][1]) < RUN_GAP:
            runs[-1][1] = position - runs[-1][0] + 1
        else:
            runs.append([position, 1])
    return [tuple(run) for run in runs]


class ArchiveStore:
    """The archive's rows, on the log store's connection (every call on its disk thread)."""

    def __init__(self, db):
        self.db = db

    @property
    def connection(self):
        return self.db.connection

    def _call(self, work, *args):
        return offload(work, *args)

    def _open(self, device, store):
        row = self.connection.execute("select max(generation) from archive_sync where device_id = ? and store = ?",
                                      (device, store)).fetchone()
        return row[0] or 1

    def _sync_row(self, device, store, generation):
        return self.connection.execute(
            "select epoch, oldest, listed, restarted from archive_sync where device_id = ? and store = ? "
            "and generation = ?", (device, store, generation)).fetchone()

    def _write(self, statement, args):
        with self.connection:
            return self.connection.execute(statement, args).rowcount

    # --- Sync ------------------------------------------------------------------
    async def sync_state(self, device, store):
        """(open generation, epoch, oldest, last listed ids) of one store."""
        def read():
            generation = self._open(device, store)
            row = self._sync_row(device, store, generation)
            return (generation, row["epoch"], row["oldest"], json.loads(row["listed"])) if row else \
                (generation, None, None, [])
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

    async def put(self, device, store, generation, rows):
        """Rows as (id, ident, rev, fields, curve); a record with another identity is replaced with its trace."""
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
                    elif old and store == "shots":
                        self._drop_traces(device, generation, (record_id,))
                    kind = (fields.get("badReason") or "good") if store == "shots" else str(fields.get("type"))
                    self.connection.execute(
                        "insert or replace into archive_records values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (device, store, generation, record_id, identity, rev, kind,
                         int(store == "shots" and bool(fields.get("badReason"))), kept,
                         json.dumps(body, separators=(",", ":"))))
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

    async def restart(self, device, store, generation, moved=()):
        """Close `generation` and open the next; `moved` rows (already the new history's) go with it.
        Returns how many records the closed generation keeps."""
        def write():
            with self.connection:
                self.connection.execute("insert into archive_sync values (?, ?, ?, 0, null, '[]', ?)",
                                        (device, store, generation + 1, time.time()))
                for rid in moved:
                    self.connection.execute("update archive_records set generation = ? where device_id = ? "
                                            "and store = ? and generation = ? and id = ?",
                                            (generation + 1, device, store, generation, rid))
                    if store == "shots":
                        self.connection.execute("update archive_traces set generation = ? where device_id = ? "
                                                "and generation = ? and id = ?",
                                                (generation + 1, device, generation, rid))
                self.connection.execute("delete from archive_exclusions where device_id = ? and store = ?",
                                        (device, store))
                return self.connection.execute(
                    "select count(*) from archive_records where device_id = ? and store = ? and generation = ?",
                    (device, store, generation)).fetchone()[0]
        return await self._call(write)

    async def adopt(self, device, store, generation, epoch, oldest, listed):
        """A complete sync: its epoch, the controller's oldest id and the ids it listed; exclusions of ids
        it no longer lists go."""
        def write():
            with self.connection:
                row = self._sync_row(device, store, generation)
                self.connection.execute("insert or replace into archive_sync values (?, ?, ?, ?, ?, ?, ?)",
                                        (device, store, generation, epoch, oldest, json.dumps(listed),
                                         row["restarted"] if row else None))
                keep = set(listed)
                stale = [(device, store, generation, rid) for (rid,) in self.connection.execute(
                    "select id from archive_exclusions where device_id = ? and store = ? and generation = ?",
                    (device, store, generation)).fetchall() if rid not in keep]
                self.connection.executemany("delete from archive_exclusions where device_id = ? and store = ? "
                                            "and generation = ? and id = ?", stale)
        await self._call(write)

    async def hole(self, device, store, generation, below, above):
        await self._call(self.connection.execute,
                         "insert or ignore into archive_holes values (?, ?, ?, ?, ?, ?, ?)",
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
            self.connection.create_function("obbw_scale_key", 1, lambda name: zlib.crc32(
                str(name or "").encode()) ^ 0xFFFFFFFF, deterministic=True)
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
        return await self._call(write)

    async def keep(self, device, store, record_id):
        """Mark an open-generation record kept before the controller deletes it; False when there is none."""
        return await self._call(lambda: self._write(
            "update archive_records set kept = 1 where device_id = ? and store = ? and generation = ? and id = ?",
            (device, store, self._open(device, store), record_id)) > 0)

    def _remove(self, device, store, keys):
        """Delete these (generation, id) rows with their traces; an id the controller still lists in the open
        generation gets an exclusion, so it is not copied again. Returns how many went."""
        opened = self._open(device, store)
        row = self._sync_row(device, store, opened)
        listed, gone = set(json.loads(row["listed"])) if row else set(), 0
        for generation, record_id in keys:
            gone += self.connection.execute(
                "delete from archive_records where device_id = ? and store = ? and generation = ? and id = ?",
                (device, store, generation, record_id)).rowcount
            if store == "shots":
                self._drop_traces(device, generation, (record_id,))
            if generation == opened and record_id in listed:
                self.connection.execute("insert or ignore into archive_exclusions values (?, ?, ?, ?)",
                                        (device, store, generation, record_id))
        return gone

    async def remove(self, device, store, generation, record_id):
        """Delete one record from the archive; False when there is none."""
        def write():
            with self.connection:
                return self._remove(device, store, [(self._open(device, store) if generation is None
                                                     else generation, record_id)]) > 0
        return await self._call(write)

    async def erase(self, device, store=None, generation=None, current=False, since=None, until=None):
        """Bulk delete. With no scope, everything: the file is rewritten and what the controller still keeps
        is copied again. A scope keeps the removed records from coming back while the controller holds
        them. Returns how many records went."""
        def everything():
            gone = self.connection.execute("select count(*) from archive_records").fetchone()[0]
            with self.connection:
                for table in ARCHIVE_TABLES:
                    self.connection.execute(f"delete from {table}")
            self.connection.execute("vacuum")
            self.connection.execute("pragma wal_checkpoint(truncate)")
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
                        where += (" and json_extract(body, '$.hasWallTime') and "
                                  "json_extract(body, '$.endedAtUnixSec') between ? and ?")
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
        return await self._call(everything if unscoped else scoped)

    # --- Settings ----------------------------------------------------------------
    async def keep_deleted(self):
        row = await self._call(lambda: self.connection.execute(
            "select value from meta where key = 'archiveKeepDeleted'").fetchone())
        return bool(row and row[0] == "1")

    async def set_keep_deleted(self, on):
        await self._call(self._write, "insert or replace into meta values ('archiveKeepDeleted', ?)",
                         ("1" if on else "0",))

    async def merged(self, device):
        """Every stored shot, newest first by (generation, id) — the controller's own rows and every
        archive-only one — with the store's revision (this connection's change counter)."""
        def read():
            rows = self.connection.execute("select body from archive_records where device_id = ? and "
                                           "store = 'shots' order by generation desc, id desc", (device,))
            return [json.loads(row[0]) for row in rows], self.connection.total_changes
        return await self._call(read)

    async def revision(self):
        return await self._call(lambda: self.connection.total_changes)

    # --- Facts and export ----------------------------------------------------------
    async def stats(self, device):
        def read():
            facts = {"bytes": table_bytes(self.connection, ARCHIVE_TABLES), "generations": {}}
            for store in STORES:
                row = self.connection.execute(
                    f"select count(*) as total, coalesce(sum({ONLY}), 0) as only, "
                    "min(nullif(json_extract(r.body, '$.endedAtUnixSec'), 0)) as first, "
                    "max(nullif(json_extract(r.body, '$.endedAtUnixSec'), 0)) as last "
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
        self.available = False  # The controller's firmware has the archive (its cfg names the switch).
        self.on = False  # ...and the switch is on.
        self.notified = {}  # The epochs of the controller's last `rs`, per store.
        self.subscribed = False  # This session's rx went out.
        self.wanted = set()
        self.wake = asyncio.Event()
        self.task = self.retry = None
        self.waiters, self.pages, self.request = {}, {}, 0
        self.syncing, self.synced_at, self.error = None, None, None
        self.headers = {}  # (window, active, filters, revision, epoch) -> (header, good)

    def usable(self):
        return self.companion._log_usable() and self.companion.device_id is not None

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
        self.wake.set()  # Also a trace the controller was too busy to give.

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
                            await self._sync(store)
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

    async def _restart(self, store, generation, moved=()):
        kept = await self.store.restart(self.companion.device_id, store, generation, moved)
        log(f"the controller's {NAMES[store]} history restarted; the archive keeps its {kept} earlier record(s)")
        return generation + 1

    async def _sync(self, store):
        device = self.companion.device_id
        generation, epoch, oldest, previous = await self.store.sync_state(device, store)
        if epoch is not None and self.notified.get(store) == epoch:
            return  # The notice names the epoch this archive already holds.
        index = await self._ask({"t": "rx", "s": store, "ep": epoch or 0}, ("records", store))
        rows, new_epoch = index.get("rows"), index.get("epoch")
        if rows is None or type(new_epoch) is not int:
            return  # Unchanged since the epoch this archive holds.
        if len(rows) % 2 or not all(type(value) is int for value in rows):
            raise ValueError("a malformed record index")
        listed, order = dict(zip(rows[0::2], rows[1::2])), rows[0::2]
        if not listed:  # Nothing to compare with (a cleared store): keep everything until it records again.
            await self.store.adopt(device, store, generation, new_epoch, oldest, previous)
            return
        low, high = min(listed), max(listed)
        missing = [rid for rid in previous if rid >= low and rid not in listed]
        restarted = (oldest is not None and high < oldest) or 2 * len(missing) > len(previous)
        if restarted:
            generation = await self._restart(store, generation)
        archived, excluded = await self.store.records(device, store, generation)
        newest = max(archived) if archived else None
        wanted = {rid for rid in order
                  if rid not in excluded and (rid not in archived or archived[rid][1] != listed[rid])}
        written, replaced = [], []
        for offset, count in windows([i for i, rid in enumerate(order) if rid in wanted], FETCH_MAX[store]):
            self.request = (self.request + 1) % 2 ** 32 or 1
            page = await self._ask({"t": "rf", "s": store, "o": offset, "n": count, "r": self.request},
                                   ("page", self.request))
            batch = []
            for fields, curve in (page if store == "shots" else ((record, {}) for record in page)):
                rid = fields.get("id")
                if rid not in wanted:
                    continue
                wanted.discard(rid)
                row = (rid, ident(store, fields), listed[rid], fields, curve)
                if rid in archived and archived[rid][0] != row[1]:
                    replaced.append(row)  # Decided once every shared record is known.
                else:
                    batch.append(row)
                    written.append(rid)
            await self.store.put(device, store, generation, batch)
        if wanted:
            return  # A record arrived or went meanwhile: the next notice finishes the sync.
        shared = [rid for rid in listed if rid in archived]
        if replaced and len(replaced) == len(shared):
            restarted = True  # Every shared id is another record: the new history's rows move along.
            generation = await self._restart(store, generation, written)
        else:
            for row in replaced:
                log(f"the controller's {NAMES[store]} {row[0]} is a different record now; the archive keeps "
                    "the new one")
            gone = [rid for rid, (_, _, kept) in archived.items() if rid not in listed and rid >= low and not kept]
            await self.store.forget_deleted(device, store, generation, gone, await self.store.keep_deleted())
        await self.store.put(device, store, generation, replaced)
        if not restarted and newest is not None and newest < low - 1:
            await self.store.hole(device, store, generation, newest, low)
            log(f"up to {low - newest - 1} {NAMES[store]} record(s) rotated out of the controller before they "
                "could be copied")
        await self.store.adopt(device, store, generation, new_epoch, low, order)

    async def _traces(self):
        """Each shot's trace once, newest first. One still being saved is skipped for now; a busy
        controller (its storage gate is closed) ends the pass. Either is asked again after TRACE_RETRY_S."""
        device, skipped = self.companion.device_id, set()
        while True:
            missing = [entry for entry in await self.store.missing_traces(device, len(skipped) + 20)
                       if entry[0] not in skipped]
            if not missing:
                break
            for record_id, boot, end in missing:
                answer = await self._ask({"t": "rt", "id": record_id, "b": boot, "e": end},
                                         ("trace", record_id, boot, end))
                result = answer.get("r")
                if result == "ok":
                    try:
                        data = base64.b64decode(answer.get("d") or "", validate=True)
                    except (binascii.Error, ValueError):
                        data = b""
                    if data:
                        await self.store.put_trace(device, record_id, boot, end, data)
                        continue
                elif result == "none":
                    await self.store.put_trace(device, record_id, boot, end, None)
                    continue
                elif result == "saving":
                    skipped.add(record_id)
                    continue
                skipped.add(None)  # Busy, or an answer it could not use: the pass ends here.
                break
            if None in skipped:
                break
        if skipped and (self.retry is None or self.retry.done()):
            self.retry = self.companion.spawn(self._later())

    async def _later(self):
        await asyncio.sleep(TRACE_RETRY_S)
        self.wake.set()

    # --- Stats over the whole history ------------------------------------------------
    async def header(self, window, active, epoch, filters):
        """The Stats header the firmware would build over the merged history, and how many good shots
        the filters keep, once the mirror is at the controller's `epoch`."""
        if not self.on or not self.usable():
            raise Unavailable("the archive is off or its store is closed")
        device, deadline = self.companion.device_id, time.monotonic() + FRESH_S
        while (synced := (await self.store.sync_state(device, "shots"))[1]) != epoch:
            if time.monotonic() >= deadline:
                raise Unavailable(f"the copy is at shot epoch {synced}, the controller at {epoch}")
            self.refresh("shots", epoch)
            await asyncio.sleep(0.1)
        key = (window, active, filters, await self.store.revision(), synced)
        if key not in self.headers:
            rows, revision = await self.store.merged(device)
            built = await asyncio.to_thread(lambda: (stats.header(rows, window, active),
                                                     stats.good(rows, *filters)))
            if len(self.headers) >= HEADERS:
                self.headers.pop(next(iter(self.headers)))
            self.headers[key[:3] + (revision, synced)] = built
            key = key[:3] + (revision, synced)
        return (*self.headers[key], synced)

    # --- Facts -----------------------------------------------------------------------
    async def facts(self):
        facts = {"on": self.on, "available": self.available,
                 "syncing": self.syncing, "syncedAt": self.synced_at, "error": self.error}
        if self.usable():
            facts.update(await self.store.stats(self.companion.device_id))
            facts["keepDeleted"] = await self.store.keep_deleted()
        return facts
