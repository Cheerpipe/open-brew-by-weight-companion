"""The shot and activation archive: a copy that follows the controller's records (plan 2A).

The controller keeps its newest 1000 shots and 1000 activations; the archive
keeps everything it has seen, including what rotated out since, and deletes
what the user deleted: the controller's records are always a subset of the
archive's. It follows the controller through the link's record frames
(`docs/COMPANION_LINK.md` in the firmware repository): the store index
(`[id, revision]` pairs with the store's generation, next record id, Clear
count `clr` and the ids the user deleted last, `gone`), fetch windows newest
first, and each shot's trace once. The only change it makes on its own is
deleting a record it alone holds, when a screen with Admin unlocked asks.
Its queries run on the log store's connection and disk thread (logstore.py
owns the database).

Rows are keyed by generation. A Clear count above the one stored is a Clear
the user made: every generation of that store is deleted and the next one
opens. Any other restarted controller history (a factory reset: ids start
again) deletes nothing: it closes the
generation, whose rows all stay as archive-only, and opens the next. The
store generation and next record id only grow and fall back only on a
restart, so a decrease of either is one, decided from the index before any
page is written. When both may have overtaken their old values (a long
absence), the fallback compares identities of fetched records (a shot is
`bootId:endedAtMs`, an activation every immutable field): the index's newest
id below the last sync's oldest, or every id it shares with the archive
another record, is a restart; one shared id that differs sets the old record
aside instead of overwriting it, and that pass mirrors no deletion
(ambiguity may duplicate, never lose).

Within the open generation a record is unchanged (same revision), updated
(same identity: a rating; a non-empty curve is never replaced by an empty
one), deleted (missing and `id >= O`, or listed in `gone`) or kept (missing
below `O` and not in `gone`: rotation). A record deleted before it was
copied is never listed again, so it is never copied. The epoch is adopted
only once every listed record is stored, so an interrupted sync resumes with
nothing lost or doubled; a change the user makes meanwhile restarts the pass
from the index.
"""

import asyncio
import base64
import binascii
import json
import time

from . import log, pages, stats
from .index_mirror import IndexMirror
from .logstore import ARCHIVE_TABLES, table_bytes
from .store import offload

STORES = ("history", "shots")  # The sync order: the small store first.
FETCH_MAX = {"shots": 50, "history": 120}
# How long a page waits for the replica to catch up before it comes whole from the controller.
CATCH_UP_S = 3
FRESH_S = 8  # How long a Stats header waits for the mirror to reach the controller's epoch.
HEADERS = 16  # Stats headers kept, per window, preset, filters and archive state.
REQUEST_S = 300  # A request unanswered this long is asked again (a long hold only delays it).
TRACE_RETRY_S = 60
RUN_GAP = 3  # Unwanted rows a fetch window may span to join two runs of wanted ones.
NAMES = {"shots": "shot", "history": "activation"}
HISTORY_IDENT = (
    "type",
    "durationS",
    "hasWallTime",
    "noWeight",
    "endedAtUnixSec",
    "endedAtLocalSec",
)
# Archive-only: a closed generation, or below the open one's oldest (rotated out of the controller).
ONLY = "(r.generation < :open or (s.oldest is not null and r.id < s.oldest))"
JOIN = (
    "archive_records r left join archive_sync s on s.device_id = r.device_id and s.store = r.store "
    "and s.generation = r.generation"
)
COLUMNS = "(device_id, store, generation, id, ident, rev, kind, bad, ended_at, body)"
# Only what the Stats header reads, never the curve.
HEADER_FIELDS = (
    "json_object("
    + ", ".join(f"'{name}', json_extract(body, '$.{name}')" for name in stats.FIELDS)
    + ")"
)


class Gone(Exception):
    """The link closed: the sync stops and resumes with the next session."""


class Changed(Exception):
    """The user changed the archive during a pass: it starts again from the index."""


class Unavailable(Exception):
    """The Stats header cannot be built now; the browser keeps the controller's."""


def ident(store, fields):
    if store == "shots":
        return f"{fields.get('bootId')}:{fields.get('endedAtMs')}"
    return ":".join(
        str(fields.get(key, False if key == "noWeight" else None)) for key in HISTORY_IDENT
    )


def windows(positions, most):
    """Fetch windows (offset, count) covering the wanted index positions, runs joined across small gaps."""
    runs = []
    for position in sorted(positions):
        if (
            runs
            and position - runs[-1][0] < most
            and position - (runs[-1][0] + runs[-1][1]) < RUN_GAP
        ):
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
        self.revision += (
            1  # Before the work is queued: a pass's next write sees it (the disk thread is serial).
        )
        result = await self._call(work)
        for callback in self.changed:
            callback()
        return result

    def _open(self, device, store):
        row = self.connection.execute(
            "select max(generation) from archive_sync where device_id = ? and store = ?",
            (device, store),
        ).fetchone()
        return row[0] or 1

    def _sync_row(self, device, store, generation):
        return self.connection.execute(
            "select epoch, oldest, listed, restarted, counters from archive_sync where device_id = ? "
            "and store = ? and generation = ?",
            (device, store, generation),
        ).fetchone()

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
                    self.connection.execute(
                        "insert into archive_sync values (?, ?, ?, 0, null, '[]', null, null)",
                        (device, store, generation),
                    )
                return generation, 0, None, [], None
            return (
                generation,
                row["epoch"],
                row["oldest"],
                json.loads(row["listed"]),
                json.loads(row["counters"]) if row["counters"] else None,
            )

        return await self._call(read)

    async def records(self, device, store, generation):
        """{id: (ident, rev)} of one generation."""
        return await self._call(
            lambda: {
                row["id"]: (row["ident"], row["rev"])
                for row in self.connection.execute(
                    "select id, ident, rev from archive_records where device_id = ? and store = ? and generation = ?",
                    (device, store, generation),
                )
            }
        )

    def _aside(self, device, store, generation, record_id):
        """Set a record aside (generation 0 or below, archive-only) instead of overwriting it."""
        lowest = self.connection.execute(
            "select min(generation) from archive_records where device_id = ? "
            "and store = ? and id = ?",
            (device, store, record_id),
        ).fetchone()[0]
        target = min(lowest, 1) - 1
        for table in ("archive_records", "archive_traces"):
            if table == "archive_traces" and store != "shots":
                continue
            self.connection.execute(
                f"update {table} set generation = ? where device_id = ? and generation = ? and id = ?"
                + (" and store = ?" if table == "archive_records" else ""),
                (target, device, generation, record_id)
                + ((store,) if table == "archive_records" else ()),
            )

    async def put(self, device, store, generation, rows):
        """Rows as (id, ident, rev, fields, curve). A stored record with another identity is never
        overwritten: it is set aside first, with its trace."""

        def write():
            with self.connection:
                for record_id, identity, rev, fields, curve in rows:
                    old = self.connection.execute(
                        "select ident, body from archive_records where device_id = ? and store = ? "
                        "and generation = ? and id = ?",
                        (device, store, generation, record_id),
                    ).fetchone()
                    body = {**fields, **curve}
                    if old and old["ident"] == identity:
                        before = json.loads(old["body"])
                        if not curve.get("wD") and before.get(
                            "wD"
                        ):  # A recycled curve: keep the copy.
                            body = {**before, **fields}
                    elif old:
                        self._aside(device, store, generation, record_id)
                    kind = (
                        (fields.get("badReason") or "good")
                        if store == "shots"
                        else str(fields.get("type"))
                    )
                    ended = fields.get("endedAtUnixSec") if fields.get("hasWallTime") else 0
                    self.connection.execute(
                        f"insert or replace into archive_records {COLUMNS} values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            device,
                            store,
                            generation,
                            record_id,
                            identity,
                            rev,
                            kind,
                            int(store == "shots" and bool(fields.get("badReason"))),
                            ended if isinstance(ended, int) else 0,
                            json.dumps(body, separators=(",", ":")),
                        ),
                    )

        await self._call(write)

    def _drop_traces(self, device, generation, ids):
        self.connection.executemany(
            "delete from archive_traces where device_id = ? and generation = ? and id = ?",
            ((device, generation, record_id) for record_id in ids),
        )

    async def forget_deleted(self, device, store, generation, ids):
        """Records the user deleted on the controller: gone from the archive too."""

        def write():
            with self.connection:
                self.connection.executemany(
                    "delete from archive_records where device_id = ? and store = ? "
                    "and generation = ? and id = ?",
                    [(device, store, generation, rid) for rid in ids],
                )
                if store == "shots":
                    self._drop_traces(device, generation, ids)

        await self._call(write)

    async def restart(self, device, store, generation, counters, cleared=False):
        """Close `generation` and open the next, which starts from the controller's `counters`; after a
        Clear the user made (`cleared`), every generation of the store goes first. Returns how many records
        the closed generation keeps, or how many a Clear deleted."""

        def write():
            with self.connection:
                count = self.connection.execute(
                    "select count(*) from archive_records where device_id = ? and store = ?"
                    + ("" if cleared else " and generation = ?"),
                    (device, store) + (() if cleared else (generation,)),
                ).fetchone()[0]
                if cleared:
                    if store == "shots":
                        self.connection.execute(
                            "delete from archive_traces where device_id = ?", (device,)
                        )
                    for table in ("archive_records", "archive_holes", "archive_sync"):
                        self.connection.execute(
                            f"delete from {table} where device_id = ? and store = ?",
                            (device, store),
                        )
                self.connection.execute(
                    "insert into archive_sync values (?, ?, ?, 0, null, '[]', ?, ?)",
                    (
                        device,
                        store,
                        generation + 1,
                        time.time(),
                        json.dumps(counters) if counters else None,
                    ),
                )
                return count

        count = await self._call(write)
        self.synced += 1
        return count

    async def adopt(self, device, store, generation, epoch, oldest, listed, counters):
        """A complete sync: its epoch, the controller's oldest id, the ids it listed and its counters."""

        def write():
            row = self._sync_row(device, store, generation)
            self._write(
                "insert or replace into archive_sync values (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    device,
                    store,
                    generation,
                    epoch,
                    oldest,
                    json.dumps(listed),
                    row["restarted"] if row else None,
                    json.dumps(counters) if counters else row["counters"] if row else None,
                ),
            )

        await self._call(write)
        self.synced += 1

    async def hole(self, device, store, generation, below, above):
        await self._call(
            self._write,
            "insert or ignore into archive_holes values (?, ?, ?, ?, ?, ?, ?)",
            (device, store, generation, below, above, above - below - 1, time.time()),
        )

    async def missing_traces(self, device, limit=20):
        """The open generation's shots (id, bootId, endedAtMs) without a trace row, newest first."""

        def read():
            rows = self.connection.execute(
                "select r.id, r.ident from archive_records r where r.device_id = ? and r.store = 'shots' "
                "and r.generation = ? and r.ident glob '[0-9]*:[0-9]*' and r.ident not glob '*[^0-9:]*' "
                "and not exists (select 1 from archive_traces t where t.device_id = r.device_id "
                "and t.generation = r.generation and t.id = r.id) order by r.id desc limit ?",
                (device, self._open(device, "shots"), limit),
            ).fetchall()
            return [(row["id"], *map(int, row["ident"].split(":"))) for row in rows]

        return await self._call(read)

    async def put_trace(self, device, record_id, boot, end, data):
        await self._call(
            lambda: self._write(
                "insert or replace into archive_traces values (?, ?, ?, ?, ?, ?)",
                (device, self._open(device, "shots"), record_id, boot, end, data),
            )
        )

    # --- Reading ---------------------------------------------------------------
    def _generations(self, device, store):
        opened = self._open(device, store)
        restarted = dict(
            self.connection.execute(
                "select generation, restarted from archive_sync where device_id = ? and store = ?",
                (device, store),
            )
        )
        counts = dict(
            self.connection.execute(
                "select generation, count(*) from archive_records where device_id = ? and store = ? "
                "group by generation",
                (device, store),
            )
        )
        return [
            {
                "generation": generation,
                "count": counts.get(generation, 0),
                "restartedAt": int(restarted[generation]) if restarted.get(generation) else None,
                "current": generation == opened,
            }
            for generation in sorted(set(restarted) | set(counts) | {opened}, reverse=True)
        ]

    def _order(self, store, sort, direction):
        """The sort key as SQL expressions, compared ascending: the controller's date order is its id
        order within a generation; its rating order puts unrated shots last whatever the direction, then
        the rating, then the newest first (shotLogCompareRatingOrder)."""
        if sort == "rating":
            rating = "coalesce(json_extract(r.body, '$.rating'), 0)"
            return [
                f"({rating} = 0)",
                rating if direction == "asc" else f"-{rating}",
                "-r.generation",
                "-r.id",
            ]
        return ["r.generation", "r.id"] if direction == "asc" else ["-r.generation", "-r.id"]

    def _filter(self, device, store, query, args):
        """The WHERE clause of the controller's own filter (shotListFilterMatches, History types)."""
        self.connection.create_function("obbw_scale_key", 1, stats.scale_key, deterministic=True)
        args.update(device=device, store=store, open=self._open(device, store))
        where = "r.device_id = :device and r.store = :store" + (
            "" if query.get("all", True) else f" and {ONLY}"
        )

        def among(name, expression, values):
            nonlocal where
            where += (
                f" and {expression} in ("
                + ",".join(f":{name}{n}" for n in range(len(values)))
                + ")"
            )
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
        return where

    def _trace_held(self, device, generation, record_id):
        return (
            self.connection.execute(
                "select 1 from archive_traces where device_id = ? and generation = ? and id = ? and data is not null",
                (device, generation, record_id),
            ).fetchone()
            is not None
        )

    async def page(self, device, store, query, offset, limit):
        """One page of the whole history, controller-held and archive-only rows alike, filtered, ordered and
        sliced as the controller pages its own (shotLogPageSlice): (total, good, rows), each row (generation,
        id, body, archive-only, trace held). `good` counts the matches the Stats header calls good."""

        def read():
            args = {}
            where = self._filter(device, store, query, args)
            order = ", ".join(self._order(store, query.get("sort", "date"), query["dir"]))
            total, good = self.connection.execute(
                f"select count(*), coalesce(sum(r.bad = 0), 0) from {JOIN} where {where}", args
            ).fetchone()
            start = min(offset, total)
            rows = self.connection.execute(
                f"select r.generation, r.id, r.body, {ONLY} as only from {JOIN} where {where} order by {order} "
                "limit :limit offset :offset",
                {**args, "limit": limit, "offset": start},
            ).fetchall()
            listed = [
                (
                    row["generation"],
                    row["id"],
                    json.loads(row["body"]),
                    bool(row["only"]),
                    store == "shots" and self._trace_held(device, row["generation"], row["id"]),
                )
                for row in rows
            ]
            meta = None
            if any(row[3] for row in listed):  # Markers need the histories and the copy's gaps.
                meta = {
                    "generations": self._generations(device, store),
                    "holes": [
                        dict(row)
                        for row in (
                            self.connection.execute(
                                "select generation, below, above, count from archive_holes where "
                                "device_id = ? and store = ? order by generation desc, below desc",
                                (device, store),
                            )
                        )
                    ],
                }
            return total, good, start, listed, meta

        return await self._call(read)

    async def tail(self, device, store, query, limit):
        """Archive-only rows filtered and ordered exactly as the controller filters and orders its own
        (shotListFilterMatches, History types), so the browser can merge both streams; `query` holds
        sort, dir, cursor (the previous page's last sort key), the filters and `all`: every copied row,
        each marked `archiveOnly`, for a browser reading with the controller off. Returns the rows, the
        next cursor, the holes, the generations and, for shots, the presets found among these rows."""

        def read():
            order = self._order(store, query["sort"], query["dir"])
            args = {"limit": limit + 1}
            where = self._filter(device, store, query, args)
            if query["cursor"] is not None:
                where += f" and ({', '.join(order)}) > ({', '.join(f':c{n}' for n in range(len(order)))})"
                args.update({f"c{n}": value for n, value in enumerate(query["cursor"])})
            keys = ", ".join(f"{expression} as k{n}" for n, expression in enumerate(order))
            rows = self.connection.execute(
                f"select r.generation, r.id, r.body, {ONLY} as only, {keys} from {JOIN} where {where} "
                f"order by {', '.join(f'k{n}' for n in range(len(order)))} limit :limit",
                args,
            ).fetchall()
            bodies = []
            for row in rows[:limit]:
                body = {**json.loads(row["body"]), "archiveGeneration": row["generation"]}
                if query["all"]:
                    body["archiveOnly"] = bool(row["only"])
                if store == "shots":
                    body["archiveTrace"] = self._trace_held(device, row["generation"], row["id"])
                bodies.append(body)
            last = rows[limit - 1] if len(rows) > limit else None
            following = ":".join(str(last[f"k{n}"]) for n in range(len(order))) if last else None
            holes = [
                dict(row)
                for row in self.connection.execute(
                    "select generation, below, above, count from archive_holes where device_id = ? and store = ? "
                    "order by generation desc, below desc",
                    (device, store),
                )
            ]
            presets = None
            if store == "shots":
                presets, seen = [], set()
                for preset, name in self.connection.execute(
                    f"select json_extract(r.body, '$.presetId'), json_extract(r.body, '$.presetName') "
                    f"from {JOIN} where r.device_id = :device and r.store = 'shots' and r.bad = 0 and {ONLY} "
                    "order by r.generation desc, r.id desc",
                    args,
                ):
                    if preset is not None and preset not in seen and len(presets) < 8:
                        seen.add(preset)
                        presets.append([preset, name])
            return bodies, following, holes, self._generations(device, store), presets

        return await self._call(read)

    async def trace(self, device, record_id, boot, end):
        row = await self._call(
            lambda: self.connection.execute(
                "select data from archive_traces where device_id = ? and id = ? and boot_id = ? and ended_ms = ? "
                "order by generation desc limit 1",
                (device, record_id, boot, end),
            ).fetchone()
        )
        return row["data"] if row else None

    async def merged(self, device):
        """The whole history the Stats header counts, newest first by (generation, id): every stored shot,
        with only the fields the header reads."""
        return await self._call(
            lambda: [
                json.loads(row[0])
                for row in self.connection.execute(
                    f"select {HEADER_FIELDS} from archive_records where device_id = ? and store = 'shots' "
                    "order by generation desc, id desc",
                    (device,),
                )
            ]
        )

    # --- The user's changes ------------------------------------------------------
    async def rate(self, device, generation, record_id, rating):
        """Rate an archive-only shot (the controller rates the ones it holds); False when there is none."""

        def write():
            opened = self._open(device, "shots")
            key = {
                "device": device,
                "g": opened if generation is None else generation,
                "i": record_id,
                "open": opened,
            }
            if (
                self.connection.execute(
                    f"select 1 from {JOIN} where r.device_id = :device and r.store = 'shots' "
                    f"and r.generation = :g and r.id = :i and {ONLY}",
                    key,
                ).fetchone()
                is None
            ):
                return False
            self._write(
                "update archive_records set body = json_set(body, '$.rating', ?) where device_id = ? "
                "and store = 'shots' and generation = ? and id = ?",
                (rating, device, key["g"], record_id),
            )
            return True

        return await self._user(write)

    async def remove(self, device, store, generation, record_id):
        """Delete one record the archive alone holds, with its trace; False when there is none (the
        controller deletes its own, and the archive follows)."""

        def write():
            opened = self._open(device, store)
            key = {
                "device": device,
                "store": store,
                "g": opened if generation is None else generation,
                "i": record_id,
                "open": opened,
            }
            if (
                self.connection.execute(
                    f"select 1 from {JOIN} where r.device_id = :device and r.store = :store "
                    f"and r.generation = :g and r.id = :i and {ONLY}",
                    key,
                ).fetchone()
                is None
            ):
                return False
            with self.connection:
                self.connection.execute(
                    "delete from archive_records where device_id = ? and store = ? "
                    "and generation = ? and id = ?",
                    (device, store, key["g"], record_id),
                )
                if store == "shots":
                    self._drop_traces(device, key["g"], (record_id,))
            return True

        return await self._user(write)

    # --- Facts and export ----------------------------------------------------------
    async def stats(self, device):
        def read():
            facts = {"bytes": table_bytes(self.connection, ARCHIVE_TABLES), "generations": {}}
            for store in STORES:
                row = self.connection.execute(
                    f"select count(*) as total, coalesce(sum({ONLY}), 0) as only, "
                    "min(nullif(r.ended_at, 0)) as first, max(nullif(r.ended_at, 0)) as last "
                    f"from {JOIN} where r.device_id = :device and r.store = :store",
                    {"device": device, "store": store, "open": self._open(device, store)},
                ).fetchone()
                facts[store], facts[store + "Total"] = row["only"], row["total"]
                facts[store + "First"], facts[store + "Last"] = row["first"], row["last"]
                facts["generations"][store] = self._generations(device, store)
            facts["traces"] = self.connection.execute(
                "select count(*) from archive_traces where device_id = ? and data is not null",
                (device,),
            ).fetchone()[0]
            facts["holes"] = self.connection.execute(
                "select coalesce(sum(count), 0) from archive_holes where device_id = ?", (device,)
            ).fetchone()[0]
            return facts

        return await self._call(read)

    async def chunk(self, device, store, after, limit=200):
        """The next rows of an export, oldest first by (generation, id): (bodies, cursor), cursor None at the end."""
        rows = await self._call(
            lambda: self.connection.execute(
                "select generation, id, body from archive_records where device_id = ? and store = ? "
                "and (generation, id) > (?, ?) order by generation, id limit ?",
                (device, store, *after, limit),
            ).fetchall()
        )
        return (
            [{**json.loads(row["body"]), "archiveGeneration": row["generation"]} for row in rows],
            (rows[-1]["generation"], rows[-1]["id"]) if rows else None,
        )

    async def trace_chunk(self, device, after, limit=50):
        rows = await self._call(
            lambda: self.connection.execute(
                "select generation, id, boot_id, ended_ms, data from archive_traces where device_id = ? "
                "and data is not null and (generation, id) > (?, ?) order by generation, id limit ?",
                (device, *after, limit),
            ).fetchall()
        )
        return (
            [
                {
                    "generation": row["generation"],
                    "id": row["id"],
                    "boot": row["boot_id"],
                    "end": row["ended_ms"],
                    "data": base64.b64encode(row["data"]).decode(),
                }
                for row in rows
            ],
            (rows[-1]["generation"], rows[-1]["id"]) if rows else None,
        )

    async def holes(self, device):
        return await self._call(
            lambda: [
                dict(row)
                for row in self.connection.execute(
                    "select store, generation, below, above, count from archive_holes where device_id = ? "
                    "order by store, generation, below",
                    (device,),
                )
            ]
        )


class Archive:
    """The sync: one store at a time over the link, activations first, then shots, then traces.

    It is also the replica the mux serves Shots and History from: a store is current once a pass ended
    at the epoch the controller last named (its `rs` notice, the epochs in its ping answer, an index
    answer) with nothing changed since; a notice of another epoch, or a rating, deletion or Clear the
    relay forwards, makes it not current and starts a catch-up at once, paused only by a sync hold."""

    def __init__(self, companion):
        self.companion = companion
        self.store = ArchiveStore(companion.logs)
        self.store.changed.append(self._user_changed)
        self.available = (
            False  # The archive switch is known: from a cfg, or remembered from the last.
        )
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
        self.headers, self.complete = (
            {},
            {},
        )  # Stats headers: by full key, and the last whole one per view.
        self.facts_cache, self.unavailable_at = None, None
        self.epochs = {}  # The epoch each store's copy is at, as the controller named it last.
        self.current = dict.fromkeys(STORES, False)
        self.ready_at = {store: asyncio.Event() for store in STORES}
        self.marks = dict.fromkeys(
            STORES, 0
        )  # Moves on every reason a pass in flight may be stale.
        # Pages the replica served, pages that went to the controller instead, and requests sent to catch up.
        self.counters = {"served": 0, "fallbacks": 0, "catchUpFetches": 0}

    def usable(self):
        return self.companion._log_usable() and self.companion.device_id is not None

    def _user_changed(self):
        self.headers.clear()
        self.complete.clear()
        self.wake.set()  # A pass in flight sees the change and starts again from the index.
        self.companion.screens.mux.replica_changed()

    # --- Replica ---------------------------------------------------------------------
    def serving(self):
        """The replica may serve pages: the switch is on and this link session follows the controller."""
        return self.on and self.subscribed and self.usable() and self.companion.outbox is not None

    def state(self, store):
        return "off" if not self.serving() else "current" if self.current[store] else "catchingUp"

    def _stale(self, store):
        self.marks[store] += 1
        self.current[store] = False
        self.ready_at[store].clear()

    def invalidate(self, store, done=False):
        """A rating, deletion or Clear the relay forwards: the store is not current from the moment it
        leaves, and once the controller answered (`done`) the copy catches up."""
        if not self.subscribed:
            return
        self._stale(store)
        if done:
            self.notified.pop(store, None)
            self.wanted.add(store)
            self.wake.set()

    async def ready(self, store):
        """Whether a page of `store` may come from the replica now: it is current, or catches up within
        CATCH_UP_S. During a sync hold the copy serves as it is: nothing goes upstream during a shot."""
        if not self.serving():
            return False
        if self.current[store] or self.companion.sync_hold:
            return True
        self.wanted.add(store)
        self.wake.set()
        try:
            await asyncio.wait_for(self.ready_at[store].wait(), CATCH_UP_S)
        except asyncio.TimeoutError:
            return bool(self.companion.sync_hold) and self.serving()
        return self.current[store] and self.serving()

    def _synced(self, store, mark, epoch):
        """A pass ended with the copy at the controller's `epoch`: current unless anything moved since."""
        moved, self.epochs[store] = self.epochs.get(store) != epoch, epoch
        self.notified.setdefault(store, epoch)
        if self.marks[store] == mark and self.notified[store] == epoch:
            self.current[store] = True
            self.ready_at[store].set()
        else:
            self.wanted.add(store)
            self.wake.set()
        if moved:
            self.companion.screens.mux.replica_changed(store)

    async def page(self, store, query, offset, limit, boot):
        """One page from the copy, as pages.py frames it: boot, epoch, good, total, offset, limit, hasMore,
        the row texts with their ids and, when the page holds rows only the archive keeps, `archive`."""
        total, good, start, rows, meta = await self.store.page(
            self.companion.device_id, store, query, offset, limit
        )
        shots = store == "shots"
        texts = [
            (
                rid,
                (pages.stats_row if shots else pages.history_row)(
                    body, pages.marks(only, generation, trace if shots else None)
                ),
                only,
            )
            for generation, rid, body, only, trace in rows
        ]
        return {
            "boot": boot,
            "epoch": self.epochs.get(store, 0),
            "good": good,
            "total": total,
            "offset": start,
            "limit": limit,
            "hasMore": start + len(rows) < total,
            "rows": texts,
            "archive": meta,
        }

    async def held_trace(self, query):
        """A shot's trace as the controller's trace route answers it, when the replica holds it."""
        try:
            identity = [int(query[name]) for name in ("id", "boot", "end")]
        except KeyError, ValueError:
            return None
        if not self.serving():
            return None
        return await self.store.trace(self.companion.device_id, *identity)

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
        for store in STORES:
            self._stale(store)
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
        for store in STORES:
            self._stale(store)
        self.companion.screens.mux.replica_changed()  # Their pages go to the controller again.

    # --- Frames from the controller ------------------------------------------------
    def on_rs(self, frame):
        """A store changed and its change is saved: catch up now."""
        if self.subscribed:
            self.on_heartbeat(frame)
            self.trace_wait, self.busy_until = (
                {},
                0.0,
            )  # A notice is when a trace not given yet is asked again.

    def on_heartbeat(self, frame):
        """The epochs the controller names (`rs`, its ping answer): one the copy is not at starts a catch-up."""
        if not self.subscribed:
            return
        for store, key in (("shots", "sh"), ("history", "hi")):
            if type(frame.get(key)) is int:
                self.notified[store] = frame[key]
                if frame[key] != self.epochs.get(store):
                    self._stale(store)
                    self.wanted.add(store)
        self.wake.set()

    def refresh(self, store, epoch):
        """The controller's store is at `epoch` (a screen's live Stats frames, a Stats header asked for
        it): sync now instead of at the next notice. The request leaves with the next clear frame."""
        if self.subscribed and type(epoch) is int:
            self.notified[store] = epoch
            if epoch != self.epochs.get(store):
                self._stale(store)
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
                self._resolve(
                    ("page", inner.get("request")),
                    [r for r in inner["records"] if isinstance(r, dict)],
                )
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
            page = self.pages[request] = {
                "seq": frame.get("seq"),
                "cols": frame["cols"].split(","),
                "rows": [],
            }
        elif page is None or page["seq"] != frame.get("seq"):
            return
        for values in rows:
            if (
                isinstance(values, list)
                and len(values) == len(page["cols"]) + 1
                and isinstance(values[-1], dict)
            ):
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
            self.counters["catchUpFetches"] += 1
            try:
                return await asyncio.wait_for(waiter, REQUEST_S)
            except asyncio.TimeoutError:
                log(
                    f"the controller did not answer the archive's {frame['t']} request; asking again"
                )

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
                    log(
                        f"the archive sync stopped ({error}); it resumes at the controller's next notice"
                    )
                finally:
                    self.syncing = None
        except Gone:
            pass

    def _steady(self, revision):
        """The user has not changed the archive since this pass started."""
        if self.store.revision != revision:
            raise Changed()

    async def _restart(self, store, generation, counters, revision, cleared=False):
        self._steady(revision)
        count = await self.store.restart(
            self.companion.device_id, store, generation, counters, cleared
        )
        log(
            f"the {NAMES[store]} history was cleared on the controller; the archive deleted its {count} "
            "record(s) too"
            if cleared
            else f"the controller's {NAMES[store]} history restarted; the archive keeps its {count} earlier record(s)"
        )
        return generation + 1

    async def _fetch(self, store, order, listed, ids, sink=None):
        """The records `ids` (positions in `order`), as (id, ident, rev, fields, curve), by fetch windows;
        with a `sink`, each page goes there as it arrives instead (so a broken-off pass keeps it)."""
        wanted, found = set(ids), []
        for offset, count in windows(
            [i for i, rid in enumerate(order) if rid in wanted], FETCH_MAX[store]
        ):
            self.request = (self.request + 1) % 2**32 or 1
            page = await self._ask(
                {"t": "rf", "s": store, "o": offset, "n": count, "r": self.request},
                ("page", self.request),
            )
            rows = []
            for fields, curve in page if store == "shots" else ((record, {}) for record in page):
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
        device, revision, mark = self.companion.device_id, self.store.revision, self.marks[store]
        generation, epoch, oldest, previous, counters = await self.store.sync_state(device, store)
        if epoch and self.notified.get(store) == epoch:
            self._synced(store, mark, epoch)
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
        if type(new_epoch) is int:
            self.notified[store] = (
                new_epoch  # The controller's own word on its epoch, newer than any notice.
            )
        if rows is None or type(new_epoch) is not int:
            if epoch and new_epoch == epoch:
                self._synced(store, mark, epoch)  # Unchanged since the epoch this archive holds.
            return
        named, gone = [index.get("gen"), index.get("next"), index.get("clr")], index.get("gone")
        if (
            not all(type(value) is int for value in named)
            or not isinstance(gone, list)
            or not all(type(rid) is int for rid in gone)
        ):
            raise ValueError("a record index without its counters or deletions")
        marked, listed, order = set(gone), dict(zip(rows[0::2], rows[1::2])), rows[0::2]
        # Exact, and decided before anything is written (an empty index included, so the counters
        # stored never fall back): a Clear count above the stored one is a Clear the user made (a
        # lower one only restarts the count: rolled-back firmware, a store it had to reset), and
        # otherwise either counter falling back is a restarted history.
        cleared = bool(counters) and len(counters) > 2 and named[2] > counters[2]
        restarted = cleared or bool(counters) and (named[0] < counters[0] or named[1] < counters[1])
        if (
            not listed
        ):  # Nothing to compare ids with: everything stays until the store records again.
            if restarted:
                generation, oldest, previous = (
                    await self._restart(store, generation, named, revision, cleared),
                    None,
                    [],
                )
            self._steady(revision)
            await self.store.adopt(device, store, generation, new_epoch, oldest, previous, named)
            self._synced(store, mark, new_epoch)
            return
        low, high = min(listed), max(listed)
        # Fallback: ids that cannot come after the last sync's oldest.
        if not restarted and oldest is not None and high < oldest:
            restarted = True
        if restarted:
            generation = await self._restart(store, generation, named, revision, cleared)
        archived = await self.store.records(device, store, generation)
        newest = max(archived) if archived else None
        shared = [rid for rid in order if rid in archived]
        # Shared records first, decided before anything new is written: a changed revision is a rating,
        # or another record under a reused id. One that differs needs every shared one to decide.
        found, missing = await self._fetch(
            store, order, listed, [rid for rid in shared if archived[rid][1] != listed[rid]]
        )
        replaced = [row for row in found if archived[row[0]][0] != row[1]]
        if replaced:
            more, still = await self._fetch(
                store, order, listed, [rid for rid in shared if archived[rid][1] == listed[rid]]
            )
            found, missing = found + more, missing | still
            replaced = [row for row in found if archived[row[0]][0] != row[1]]
        if missing:
            return self._again(store)  # A record arrived or went meanwhile: catch up again.
        ambiguous = bool(replaced) and len(replaced) < len(shared)
        if replaced and not ambiguous:
            restarted = True  # Every shared id is another record.
            generation = await self._restart(store, generation, named, revision)
            archived = {}
        for row in replaced if ambiguous else ():
            log(
                f"the controller's {NAMES[store]} {row[0]} may be a different record now; the archive keeps "
                "both"
            )
        self._steady(revision)
        await self.store.put(
            device, store, generation, found
        )  # An ambiguous old record is set aside.
        fetched = {row[0] for row in found}

        async def page(rows):
            self._steady(revision)
            await self.store.put(device, store, generation, rows)

        _, missing = await self._fetch(
            store,
            order,
            listed,
            [rid for rid in order if rid not in archived and rid not in fetched],
            page,
        )
        if missing:
            return self._again(store)
        if (
            not restarted and not ambiguous
        ):  # A pass that could not tell records apart mirrors no deletion.
            # Missing at or above the oldest, or named as deleted: the user deleted it; below the oldest
            # and not named, it rotated out and stays.
            deleted = [
                rid for rid in archived if rid not in listed and (rid >= low or rid in marked)
            ]
            await self.store.forget_deleted(device, store, generation, deleted)
        if not restarted and newest is not None and newest < low - 1:
            await self.store.hole(device, store, generation, newest, low)
            log(
                f"up to {low - newest - 1} {NAMES[store]} record(s) rotated out of the controller before they "
                "could be copied"
            )
        self._steady(revision)
        await self.store.adopt(device, store, generation, new_epoch, low, order, named)
        self._synced(store, mark, new_epoch)

    def _again(self, store):
        self.notified.pop(store, None)
        self.wanted.add(store)
        self.wake.set()

    async def _traces(self):
        """Each shot's trace once, newest first. One still being saved, or a controller too busy to read
        its storage, is asked again only after the next notice or TRACE_RETRY_S."""
        device, now = self.companion.device_id, time.monotonic()
        if now < self.busy_until:
            return
        while True:
            missing = [
                entry
                for entry in await self.store.missing_traces(device, len(self.trace_wait) + 20)
                if self.trace_wait.get(entry, 0) <= now
            ]
            if not missing:
                break
            for entry in missing:
                record_id, boot, end = entry
                answer = await self._ask(
                    {"t": "rt", "id": record_id, "b": boot, "e": end},
                    ("trace", record_id, boot, end),
                )
                result = answer.get("r")
                if result == "ok":
                    try:
                        data = base64.b64decode(answer.get("d") or "", validate=True)
                    except binascii.Error, ValueError:
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
            while (
                synced != epoch
                and not self.companion.sync_blocked()
                and time.monotonic() < deadline
            ):
                await asyncio.sleep(0.1)
                synced = (await self.store.sync_state(device, "shots"))[1]
            if synced != epoch:
                if not self.companion.sync_blocked():
                    raise Unavailable(
                        f"the copy is at shot epoch {synced}, the controller at {epoch}"
                    )
                if view in self.complete:
                    return self.complete[view]
        key = view + (self.store.revision, synced)
        if key not in self.headers:
            rows = await self.store.merged(device)
            built = await asyncio.to_thread(
                lambda: (stats.header(rows, window, active), stats.good(rows, *filters))
            )
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
            log(
                f"the Stats header over the whole history is unavailable ({error}); screens show the "
                "controller's"
            )

    # --- Facts -----------------------------------------------------------------------
    async def facts(self):
        facts = {
            "on": self.on,
            "available": self.available,
            "syncing": self.syncing,
            "syncedAt": self.synced_at,
            "error": self.error,
            "replica": {store: self.state(store) for store in STORES},
            **self.counters,
        }
        if self.usable():
            key = (self.companion.device_id, self.store.revision, self.store.synced)
            if self.facts_cache is None or self.facts_cache[0] != key:
                self.facts_cache = (key, await self.store.stats(self.companion.device_id))
            facts.update(self.facts_cache[1])
        return facts
