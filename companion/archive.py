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
from typing import TYPE_CHECKING, TypedDict, TypeIs

from . import log, pages, stats
from .index_mirror import IndexMirror
from .logstore import ARCHIVE_TABLES, table_bytes
from .store import offload

if TYPE_CHECKING:
    import sqlite3
    from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence

    from .logstore import LogStore
    from .pages import Json
    from .service import Companion

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

# Every statement is one constant, so the reads below spell out in full what they share: each
# record joined with its generation's sync row,
#   archive_records r left join archive_sync s on s.device_id = r.device_id
#       and s.store = r.store and s.generation = r.generation
# and what makes a row archive-only: a closed generation, or below the open one's oldest (rotated
# out of the controller),
#   (r.generation < :open or (s.oldest is not null and r.id < s.oldest))
#
# The rows of a Shots or History page, filtered as the controller filters its own
# (shotListFilterMatches, History types): `all` keeps the rows the controller holds too, `bad` the
# bad shots; an empty JSON list filters nothing. Each is bound by ArchiveStore._filter.
COUNT = (
    "select count(*), coalesce(sum(r.bad = 0), 0) from archive_records r "
    "left join archive_sync s on s.device_id = r.device_id and s.store = r.store "
    "and s.generation = r.generation "
    "where r.device_id = :device and r.store = :store "
    "and (:all or (r.generation < :open or (s.oldest is not null and r.id < s.oldest))) "
    "and (:bad or r.bad = 0) "
    "and (json_array_length(:result) = 0 or (coalesce(json_extract(r.body, '$.arrivalS'), 0) != 0 "
    "and json_extract(r.body, '$.verdict') in (select value from json_each(:result)))) "
    "and (json_array_length(:preset) = 0 "
    "or json_extract(r.body, '$.presetId') in (select value from json_each(:preset))) "
    "and (json_array_length(:scale) = 0 or obbw_scale_key(json_extract(r.body, '$.scaleName')) "
    "in (select value from json_each(:scale))) "
    "and (json_array_length(:types) = 0 or r.kind in (select value from json_each(:types)))"
)
# The same rows with their sort keys k0..., compared ascending, after the cursor `c0...` (all null
# on a first page), by (rating order, ascending): the controller's date order is its id order
# within a generation; its rating order puts unrated shots last whatever the direction, then the
# rating, then the newest first (shotLogCompareRatingOrder). Each with how many keys it has.
ROWS = {
    (False, True): (
        2,
        (
            "select r.generation, r.id, r.body, "
            "(r.generation < :open or (s.oldest is not null and r.id < s.oldest)) as only, "
            "r.generation as k0, r.id as k1 from archive_records r "
            "left join archive_sync s on s.device_id = r.device_id and s.store = r.store "
            "and s.generation = r.generation "
            "where r.device_id = :device and r.store = :store "
            "and (:all or (r.generation < :open or (s.oldest is not null and r.id < s.oldest))) "
            "and (:bad or r.bad = 0) "
            "and (json_array_length(:result) = 0 "
            "or (coalesce(json_extract(r.body, '$.arrivalS'), 0) != 0 "
            "and json_extract(r.body, '$.verdict') in (select value from json_each(:result)))) "
            "and (json_array_length(:preset) = 0 "
            "or json_extract(r.body, '$.presetId') in (select value from json_each(:preset))) "
            "and (json_array_length(:scale) = 0 "
            "or obbw_scale_key(json_extract(r.body, '$.scaleName')) "
            "in (select value from json_each(:scale))) "
            "and (json_array_length(:types) = 0 "
            "or r.kind in (select value from json_each(:types))) "
            "and (:c0 is null or (r.generation, r.id) > (:c0, :c1)) "
            "order by k0, k1 limit :limit offset :offset"
        ),
    ),
    (False, False): (
        2,
        (
            "select r.generation, r.id, r.body, "
            "(r.generation < :open or (s.oldest is not null and r.id < s.oldest)) as only, "
            "-r.generation as k0, -r.id as k1 from archive_records r "
            "left join archive_sync s on s.device_id = r.device_id and s.store = r.store "
            "and s.generation = r.generation "
            "where r.device_id = :device and r.store = :store "
            "and (:all or (r.generation < :open or (s.oldest is not null and r.id < s.oldest))) "
            "and (:bad or r.bad = 0) "
            "and (json_array_length(:result) = 0 "
            "or (coalesce(json_extract(r.body, '$.arrivalS'), 0) != 0 "
            "and json_extract(r.body, '$.verdict') in (select value from json_each(:result)))) "
            "and (json_array_length(:preset) = 0 "
            "or json_extract(r.body, '$.presetId') in (select value from json_each(:preset))) "
            "and (json_array_length(:scale) = 0 "
            "or obbw_scale_key(json_extract(r.body, '$.scaleName')) "
            "in (select value from json_each(:scale))) "
            "and (json_array_length(:types) = 0 "
            "or r.kind in (select value from json_each(:types))) "
            "and (:c0 is null or (-r.generation, -r.id) > (:c0, :c1)) "
            "order by k0, k1 limit :limit offset :offset"
        ),
    ),
    (True, True): (
        4,
        (
            "select r.generation, r.id, r.body, "
            "(r.generation < :open or (s.oldest is not null and r.id < s.oldest)) as only, "
            "(coalesce(json_extract(r.body, '$.rating'), 0) = 0) as k0, "
            "coalesce(json_extract(r.body, '$.rating'), 0) as k1, "
            "-r.generation as k2, -r.id as k3 from archive_records r "
            "left join archive_sync s on s.device_id = r.device_id and s.store = r.store "
            "and s.generation = r.generation "
            "where r.device_id = :device and r.store = :store "
            "and (:all or (r.generation < :open or (s.oldest is not null and r.id < s.oldest))) "
            "and (:bad or r.bad = 0) "
            "and (json_array_length(:result) = 0 "
            "or (coalesce(json_extract(r.body, '$.arrivalS'), 0) != 0 "
            "and json_extract(r.body, '$.verdict') in (select value from json_each(:result)))) "
            "and (json_array_length(:preset) = 0 "
            "or json_extract(r.body, '$.presetId') in (select value from json_each(:preset))) "
            "and (json_array_length(:scale) = 0 "
            "or obbw_scale_key(json_extract(r.body, '$.scaleName')) "
            "in (select value from json_each(:scale))) "
            "and (json_array_length(:types) = 0 "
            "or r.kind in (select value from json_each(:types))) "
            "and (:c0 is null or ((coalesce(json_extract(r.body, '$.rating'), 0) = 0), "
            "coalesce(json_extract(r.body, '$.rating'), 0), -r.generation, -r.id) "
            "> (:c0, :c1, :c2, :c3)) "
            "order by k0, k1, k2, k3 limit :limit offset :offset"
        ),
    ),
    (True, False): (
        4,
        (
            "select r.generation, r.id, r.body, "
            "(r.generation < :open or (s.oldest is not null and r.id < s.oldest)) as only, "
            "(coalesce(json_extract(r.body, '$.rating'), 0) = 0) as k0, "
            "-coalesce(json_extract(r.body, '$.rating'), 0) as k1, "
            "-r.generation as k2, -r.id as k3 from archive_records r "
            "left join archive_sync s on s.device_id = r.device_id and s.store = r.store "
            "and s.generation = r.generation "
            "where r.device_id = :device and r.store = :store "
            "and (:all or (r.generation < :open or (s.oldest is not null and r.id < s.oldest))) "
            "and (:bad or r.bad = 0) "
            "and (json_array_length(:result) = 0 "
            "or (coalesce(json_extract(r.body, '$.arrivalS'), 0) != 0 "
            "and json_extract(r.body, '$.verdict') in (select value from json_each(:result)))) "
            "and (json_array_length(:preset) = 0 "
            "or json_extract(r.body, '$.presetId') in (select value from json_each(:preset))) "
            "and (json_array_length(:scale) = 0 "
            "or obbw_scale_key(json_extract(r.body, '$.scaleName')) "
            "in (select value from json_each(:scale))) "
            "and (json_array_length(:types) = 0 "
            "or r.kind in (select value from json_each(:types))) "
            "and (:c0 is null or ((coalesce(json_extract(r.body, '$.rating'), 0) = 0), "
            "-coalesce(json_extract(r.body, '$.rating'), 0), -r.generation, -r.id) "
            "> (:c0, :c1, :c2, :c3)) "
            "order by k0, k1, k2, k3 limit :limit offset :offset"
        ),
    ),
}
# The presets of a page's archive-only good shots, newest first.
PRESETS = (
    "select json_extract(r.body, '$.presetId'), json_extract(r.body, '$.presetName') "
    "from archive_records r "
    "left join archive_sync s on s.device_id = r.device_id and s.store = r.store "
    "and s.generation = r.generation "
    "where r.device_id = :device and r.store = 'shots' and r.bad = 0 "
    "and (r.generation < :open or (s.oldest is not null and r.id < s.oldest)) "
    "order by r.generation desc, r.id desc"
)
# Whether the archive alone holds one record.
ARCHIVE_ONLY = (
    "select 1 from archive_records r "
    "left join archive_sync s on s.device_id = r.device_id and s.store = r.store "
    "and s.generation = r.generation "
    "where r.device_id = :device and r.store = :store and r.generation = :g and r.id = :i "
    "and (r.generation < :open or (s.oldest is not null and r.id < s.oldest))"
)
# One store's facts: its records, the archive-only ones, the first and last wall times.
FACTS = (
    "select count(*) as total, "
    "coalesce(sum((r.generation < :open or (s.oldest is not null and r.id < s.oldest))), 0) "
    "as only, min(nullif(r.ended_at, 0)) as first, max(nullif(r.ended_at, 0)) as last "
    "from archive_records r "
    "left join archive_sync s on s.device_id = r.device_id and s.store = r.store "
    "and s.generation = r.generation "
    "where r.device_id = :device and r.store = :store"
)
# Every stored shot with only what the Stats header reads (stats.FIELDS), never the curve.
MERGED = (
    "select json_object("
    "'durationS', json_extract(body, '$.durationS'), "
    "'goalG', json_extract(body, '$.goalG'), "
    "'fastBeforeS', json_extract(body, '$.fastBeforeS'), "
    "'slowAfterS', json_extract(body, '$.slowAfterS'), "
    "'arrivalS', json_extract(body, '$.arrivalS'), "
    "'actualG', json_extract(body, '$.actualG'), "
    "'cutLineG', json_extract(body, '$.cutLineG'), "
    "'avgFlowGS', json_extract(body, '$.avgFlowGS'), "
    "'verdict', json_extract(body, '$.verdict'), "
    "'shotType', json_extract(body, '$.shotType'), "
    "'stopDetail', json_extract(body, '$.stopDetail'), "
    "'presetId', json_extract(body, '$.presetId'), "
    "'presetName', json_extract(body, '$.presetName'), "
    "'scaleName', json_extract(body, '$.scaleName'), "
    "'hasWallTime', json_extract(body, '$.hasWallTime'), "
    "'endedAtLocalSec', json_extract(body, '$.endedAtLocalSec')"
    ") from archive_records where device_id = ? and store = 'shots' "
    "order by generation desc, id desc"
)

# A fetched page's records: (fields, curve), the curve empty for an activation.
type Fetched = list[tuple[dict[str, object], dict[str, object]]]
# A record to store: (id, ident, rev, fields, curve).
type Record = tuple[int, str, int, Mapping[str, object], Mapping[str, object]]
# The Stats filters a header counts good shots with: results, presets, scales.
type Filters = tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]
# A Stats header, how many good shots the filters keep, and the shot epoch it was built at.
type Header = tuple[stats.Header, int, int]


class GoneError(Exception):
    """The link closed: the sync stops and resumes with the next session."""


class ChangedError(Exception):
    """The user changed the archive during a pass: it starts again from the index."""


class UnavailableError(Exception):
    """The Stats header cannot be built now; the browser keeps the controller's."""


class Gathering(TypedDict):
    """A fetch page arriving in frames that share `seq`."""

    seq: object
    cols: list[str]
    rows: Fetched


def ident(store: str, fields: Mapping[str, object]) -> str:
    if store == "shots":
        return f"{fields.get('bootId')}:{fields.get('endedAtMs')}"
    return ":".join(
        str(fields.get(key, False if key == "noWeight" else None)) for key in HISTORY_IDENT
    )


def ints(values: object) -> TypeIs[list[int]]:
    """A list of ints, as the controller's counters and ids are."""
    return isinstance(values, list) and all(type(value) is int for value in values)


def windows(positions: Iterable[int], most: int) -> list[tuple[int, int]]:
    """Fetch windows (offset, count) covering the wanted index positions, runs joined across small
    gaps."""
    runs: list[list[int]] = []
    for position in sorted(positions):
        if (
            runs
            and position - runs[-1][0] < most
            and position - (runs[-1][0] + runs[-1][1]) < RUN_GAP
        ):
            runs[-1][1] = position - runs[-1][0] + 1
        else:
            runs.append([position, 1])
    return [(offset, count) for offset, count in runs]


class ArchiveStore:
    """The archive's rows, on the log store's connection (every call on its disk thread).

    `revision` moves with every change the user makes; `synced` with every
    sync that completes or restarts a generation. Caches key on both."""

    def __init__(self, db: LogStore) -> None:
        self.db = db
        self.revision = self.synced = 0
        self.changed: list[Callable[[], None]] = []  # Run when the user changed something.

    @property
    def connection(self) -> sqlite3.Connection:
        return self.db.db

    def _call[*Ts, R](self, work: Callable[[*Ts], R], *args: *Ts) -> Awaitable[R]:
        return offload(work, *args)

    async def _user[R](self, work: Callable[[], R]) -> R:
        """A change the user made: any sync pass in flight starts over, cached answers go."""
        self.revision += (
            1  # Before the work is queued: a pass's next write sees it (the disk thread is serial).
        )
        result = await self._call(work)
        for callback in self.changed:
            callback()
        return result

    def _open(self, device: str | None, store: str) -> int:
        row = self.connection.execute(
            "select max(generation) from archive_sync where device_id = ? and store = ?",
            (device, store),
        ).fetchone()
        opened: int = row[0] or 1
        return opened

    def _sync_row(self, device: str | None, store: str, generation: int) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.connection.execute(
            "select epoch, oldest, listed, restarted, counters from archive_sync "
            "where device_id = ? and store = ? and generation = ?",
            (device, store, generation),
        ).fetchone()
        return row

    def _write(self, statement: str, args: Sequence[object]) -> int:
        with self.connection:
            return self.connection.execute(statement, args).rowcount

    # --- Sync ------------------------------------------------------------------
    async def sync_state(
        self, device: str | None, store: str
    ) -> tuple[int, int, int | None, list[int], list[int] | None]:
        """(open generation, epoch, oldest, last listed ids, last counters) of one store; the open
        generation always has its sync row, so rows never land in one without it."""

        def read() -> tuple[int, int, int | None, list[int], list[int] | None]:
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

    async def records(
        self, device: str | None, store: str, generation: int
    ) -> dict[int, tuple[str, int]]:
        """{id: (ident, rev)} of one generation."""
        return await self._call(
            lambda: {
                row["id"]: (row["ident"], row["rev"])
                for row in self.connection.execute(
                    "select id, ident, rev from archive_records "
                    "where device_id = ? and store = ? and generation = ?",
                    (device, store, generation),
                )
            }
        )

    def _aside(self, device: str | None, store: str, generation: int, record_id: int) -> None:
        """Set a record aside (generation 0 or below, archive-only) instead of overwriting it."""
        lowest = self.connection.execute(
            "select min(generation) from archive_records where device_id = ? "
            "and store = ? and id = ?",
            (device, store, record_id),
        ).fetchone()[0]
        target = min(lowest, 1) - 1
        self.connection.execute(
            "update archive_records set generation = ? where device_id = ? and generation = ? "
            "and id = ? and store = ?",
            (target, device, generation, record_id, store),
        )
        if store == "shots":
            self.connection.execute(
                "update archive_traces set generation = ? where device_id = ? and generation = ? "
                "and id = ?",
                (target, device, generation, record_id),
            )

    async def put(
        self, device: str | None, store: str, generation: int, rows: Iterable[Record]
    ) -> None:
        """Rows as (id, ident, rev, fields, curve). A stored record with another identity is never
        overwritten: it is set aside first, with its trace."""

        def write() -> None:
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
                        "insert or replace into archive_records "
                        "(device_id, store, generation, id, ident, rev, kind, bad, ended_at, body) "
                        "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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

    def _drop_traces(self, device: str | None, generation: int, ids: Iterable[int]) -> None:
        self.connection.executemany(
            "delete from archive_traces where device_id = ? and generation = ? and id = ?",
            ((device, generation, record_id) for record_id in ids),
        )

    async def forget_deleted(
        self, device: str | None, store: str, generation: int, ids: Sequence[int]
    ) -> None:
        """Records the user deleted on the controller: gone from the archive too."""

        def write() -> None:
            with self.connection:
                self.connection.executemany(
                    "delete from archive_records where device_id = ? and store = ? "
                    "and generation = ? and id = ?",
                    [(device, store, generation, rid) for rid in ids],
                )
                if store == "shots":
                    self._drop_traces(device, generation, ids)

        await self._call(write)

    async def restart(
        self,
        device: str | None,
        store: str,
        generation: int,
        counters: list[int] | None,
        cleared: bool = False,
    ) -> int:
        """Close `generation` and open the next, which starts from the controller's `counters`;
        after a Clear the user made (`cleared`), every generation of the store goes first. Returns
        how many records the closed generation keeps, or how many a Clear deleted."""

        def write() -> int:
            with self.connection:
                if cleared:
                    count: int = self.connection.execute(
                        "select count(*) from archive_records where device_id = ? and store = ?",
                        (device, store),
                    ).fetchone()[0]
                else:
                    count = self.connection.execute(
                        "select count(*) from archive_records where device_id = ? and store = ? "
                        "and generation = ?",
                        (device, store, generation),
                    ).fetchone()[0]
                if cleared:
                    if store == "shots":
                        self.connection.execute(
                            "delete from archive_traces where device_id = ?", (device,)
                        )
                    for statement in (
                        "delete from archive_records where device_id = ? and store = ?",
                        "delete from archive_holes where device_id = ? and store = ?",
                        "delete from archive_sync where device_id = ? and store = ?",
                    ):
                        self.connection.execute(statement, (device, store))
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

    async def adopt(
        self,
        device: str | None,
        store: str,
        generation: int,
        epoch: int,
        oldest: int | None,
        listed: list[int],
        counters: list[int] | None,
    ) -> None:
        """A complete sync: its epoch, the controller's oldest id, the ids it listed and its
        counters."""

        def write() -> None:
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

    async def hole(
        self, device: str | None, store: str, generation: int, below: int, above: int
    ) -> None:
        await self._call(
            self._write,
            "insert or ignore into archive_holes values (?, ?, ?, ?, ?, ?, ?)",
            (device, store, generation, below, above, above - below - 1, time.time()),
        )

    async def missing_traces(
        self, device: str | None, limit: int = 20
    ) -> list[tuple[int, int, int]]:
        """The open generation's shots (id, bootId, endedAtMs) without a trace row, newest first."""

        def read() -> list[tuple[int, int, int]]:
            rows = self.connection.execute(
                "select r.id, r.ident from archive_records r where r.device_id = ? "
                "and r.store = 'shots' and r.generation = ? and r.ident glob '[0-9]*:[0-9]*' "
                "and r.ident not glob '*[^0-9:]*' and not exists (select 1 from archive_traces t "
                "where t.device_id = r.device_id and t.generation = r.generation and t.id = r.id) "
                "order by r.id desc limit ?",
                (device, self._open(device, "shots"), limit),
            ).fetchall()
            return [(row["id"], *map(int, row["ident"].split(":"))) for row in rows]

        return await self._call(read)

    async def put_trace(
        self, device: str | None, record_id: int, boot: int, end: int, data: bytes | None
    ) -> None:
        await self._call(
            lambda: self._write(
                "insert or replace into archive_traces values (?, ?, ?, ?, ?, ?)",
                (device, self._open(device, "shots"), record_id, boot, end, data),
            )
        )

    # --- Reading ---------------------------------------------------------------
    def _generations(self, device: str | None, store: str) -> list[dict[str, int | bool | None]]:
        opened = self._open(device, store)
        restarted = dict(
            self.connection.execute(
                "select generation, restarted from archive_sync where device_id = ? and store = ?",
                (device, store),
            )
        )
        counts = dict(
            self.connection.execute(
                "select generation, count(*) from archive_records where device_id = ? "
                "and store = ? group by generation",
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

    def _filter(
        self, device: str | None, store: str, query: Mapping[str, object], args: dict[str, object]
    ) -> None:
        """The bindings of the controller's own filter (shotListFilterMatches, History types) in
        COUNT and ROWS."""
        self.connection.create_function("obbw_scale_key", 1, stats.scale_key, deterministic=True)
        shots = store == "shots"
        args.update(
            device=device,
            store=store,
            open=self._open(device, store),
            all=bool(query.get("all", True)),
            bad=not shots or bool(query["bad"]),
            result=json.dumps(query["result"] if shots else []),
            preset=json.dumps(query["preset"] if shots else []),
            scale=json.dumps(query["scale"] if shots else []),
            types=json.dumps([] if shots else query["types"]),
        )

    def _trace_held(self, device: str | None, generation: int, record_id: int) -> bool:
        return (
            self.connection.execute(
                "select 1 from archive_traces where device_id = ? and generation = ? and id = ? "
                "and data is not null",
                (device, generation, record_id),
            ).fetchone()
            is not None
        )

    def _holes(self, device: str | None, store: str) -> list[dict[str, object]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "select generation, below, above, count from archive_holes where device_id = ? "
                "and store = ? order by generation desc, below desc",
                (device, store),
            )
        ]

    async def page(
        self, device: str | None, store: str, query: Mapping[str, object], offset: int, limit: int
    ) -> tuple[
        int,
        int,
        int,
        list[tuple[int, int, dict[str, Json], bool, bool]],
        dict[str, object] | None,
    ]:
        """One page of the whole history, controller-held and archive-only rows alike, filtered,
        ordered and sliced as the controller pages its own (shotLogPageSlice): (total, good, rows),
        each row (generation, id, body, archive-only, trace held). `good` counts the matches the
        Stats header calls good."""

        def read() -> tuple[
            int,
            int,
            int,
            list[tuple[int, int, dict[str, Json], bool, bool]],
            dict[str, object] | None,
        ]:
            args: dict[str, object] = {}
            self._filter(device, store, query, args)
            keys, statement = ROWS[query.get("sort", "date") == "rating", query["dir"] == "asc"]
            total, good = self.connection.execute(COUNT, args).fetchone()
            start = min(offset, total)
            args.update(dict.fromkeys((f"c{n}" for n in range(keys)), None))
            rows = self.connection.execute(
                statement, {**args, "limit": limit, "offset": start}
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
            meta: dict[str, object] | None = None
            if any(row[3] for row in listed):  # Markers need the histories and the copy's gaps.
                meta = {
                    "generations": self._generations(device, store),
                    "holes": self._holes(device, store),
                }
            return total, good, start, listed, meta

        return await self._call(read)

    async def tail(
        self, device: str | None, store: str, query: Mapping[str, object], limit: int
    ) -> tuple[
        list[dict[str, object]],
        str | None,
        list[dict[str, object]],
        list[dict[str, int | bool | None]],
        list[list[object]] | None,
    ]:
        """Archive-only rows filtered and ordered exactly as the controller filters and orders its
        own (shotListFilterMatches, History types), so the browser can merge both streams; `query`
        holds sort, dir, cursor (the previous page's last sort key), the filters and `all`: every
        copied row, each marked `archiveOnly`, for a browser reading with the controller off.
        Returns the rows, the next cursor, the holes, the generations and, for shots, the presets
        found among these rows."""

        def read() -> tuple[
            list[dict[str, object]],
            str | None,
            list[dict[str, object]],
            list[dict[str, int | bool | None]],
            list[list[object]] | None,
        ]:
            keys, statement = ROWS[query["sort"] == "rating", query["dir"] == "asc"]
            args: dict[str, object] = {"limit": limit + 1, "offset": 0}
            self._filter(device, store, query, args)
            cursor = query["cursor"]
            args.update(
                {f"c{n}": cursor[n] if isinstance(cursor, tuple) else None for n in range(keys)}
            )
            rows = self.connection.execute(statement, args).fetchall()
            bodies: list[dict[str, object]] = []
            for row in rows[:limit]:
                body = {**json.loads(row["body"]), "archiveGeneration": row["generation"]}
                if query["all"]:
                    body["archiveOnly"] = bool(row["only"])
                if store == "shots":
                    body["archiveTrace"] = self._trace_held(device, row["generation"], row["id"])
                bodies.append(body)
            last = rows[limit - 1] if len(rows) > limit else None
            following = ":".join(str(last[f"k{n}"]) for n in range(keys)) if last else None
            holes = self._holes(device, store)
            presets: list[list[object]] | None = None
            if store == "shots":
                presets, seen = [], set()
                for preset, name in self.connection.execute(PRESETS, args):
                    if preset is not None and preset not in seen and len(presets) < 8:
                        seen.add(preset)
                        presets.append([preset, name])
            return bodies, following, holes, self._generations(device, store), presets

        return await self._call(read)

    async def trace(self, device: str | None, record_id: int, boot: int, end: int) -> bytes | None:
        row = await self._call(
            lambda: self.connection.execute(
                "select data from archive_traces where device_id = ? and id = ? and boot_id = ? "
                "and ended_ms = ? order by generation desc limit 1",
                (device, record_id, boot, end),
            ).fetchone()
        )
        data: bytes | None = row["data"] if row else None
        return data

    async def merged(self, device: str | None) -> list[stats.Row]:
        """The whole history the Stats header counts, newest first by (generation, id): every
        stored shot, with only the fields the header reads."""
        return await self._call(
            lambda: [json.loads(row[0]) for row in self.connection.execute(MERGED, (device,))]
        )

    # --- The user's changes ------------------------------------------------------
    async def rate(
        self, device: str | None, generation: int | None, record_id: int, rating: int
    ) -> bool:
        """Rate an archive-only shot (the controller rates the ones it holds); False when there is
        none."""

        def write() -> bool:
            opened = self._open(device, "shots")
            key = {
                "device": device,
                "store": "shots",
                "g": opened if generation is None else generation,
                "i": record_id,
                "open": opened,
            }
            if self.connection.execute(ARCHIVE_ONLY, key).fetchone() is None:
                return False
            self._write(
                "update archive_records set body = json_set(body, '$.rating', ?) "
                "where device_id = ? and store = 'shots' and generation = ? and id = ?",
                (rating, device, key["g"], record_id),
            )
            return True

        return await self._user(write)

    async def remove(
        self, device: str | None, store: str, generation: int | None, record_id: int
    ) -> bool:
        """Delete one record the archive alone holds, with its trace; False when there is none (the
        controller deletes its own, and the archive follows)."""

        def write() -> bool:
            opened = self._open(device, store)
            g = opened if generation is None else generation
            key = {"device": device, "store": store, "g": g, "i": record_id, "open": opened}
            if self.connection.execute(ARCHIVE_ONLY, key).fetchone() is None:
                return False
            with self.connection:
                self.connection.execute(
                    "delete from archive_records where device_id = ? and store = ? "
                    "and generation = ? and id = ?",
                    (device, store, g, record_id),
                )
                if store == "shots":
                    self._drop_traces(device, g, (record_id,))
            return True

        return await self._user(write)

    # --- Facts and export ----------------------------------------------------------
    async def stats(self, device: str | None) -> dict[str, object]:
        def read() -> dict[str, object]:
            generations: dict[str, list[dict[str, int | bool | None]]] = {}
            facts: dict[str, object] = {
                "bytes": table_bytes(self.connection, ARCHIVE_TABLES),
                "generations": generations,
            }
            for store in STORES:
                row = self.connection.execute(
                    FACTS, {"device": device, "store": store, "open": self._open(device, store)}
                ).fetchone()
                facts[store], facts[store + "Total"] = row["only"], row["total"]
                facts[store + "First"], facts[store + "Last"] = row["first"], row["last"]
                generations[store] = self._generations(device, store)
            facts["traces"] = self.connection.execute(
                "select count(*) from archive_traces where device_id = ? and data is not null",
                (device,),
            ).fetchone()[0]
            facts["holes"] = self.connection.execute(
                "select coalesce(sum(count), 0) from archive_holes where device_id = ?", (device,)
            ).fetchone()[0]
            return facts

        return await self._call(read)

    async def chunk(
        self, device: str | None, store: str, after: tuple[int, int], limit: int = 200
    ) -> tuple[list[dict[str, object]], tuple[int, int] | None]:
        """The next rows of an export, oldest first by (generation, id): (bodies, cursor), cursor
        None at the end."""
        rows = await self._call(
            lambda: self.connection.execute(
                "select generation, id, body from archive_records where device_id = ? "
                "and store = ? and (generation, id) > (?, ?) order by generation, id limit ?",
                (device, store, *after, limit),
            ).fetchall()
        )
        return (
            [{**json.loads(row["body"]), "archiveGeneration": row["generation"]} for row in rows],
            (rows[-1]["generation"], rows[-1]["id"]) if rows else None,
        )

    async def trace_chunk(
        self, device: str | None, after: tuple[int, int], limit: int = 50
    ) -> tuple[list[dict[str, object]], tuple[int, int] | None]:
        rows = await self._call(
            lambda: self.connection.execute(
                "select generation, id, boot_id, ended_ms, data from archive_traces "
                "where device_id = ? and data is not null and (generation, id) > (?, ?) "
                "order by generation, id limit ?",
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

    async def holes(self, device: str | None) -> list[dict[str, object]]:
        return await self._call(
            lambda: [
                dict(row)
                for row in self.connection.execute(
                    "select store, generation, below, above, count from archive_holes "
                    "where device_id = ? order by store, generation, below",
                    (device,),
                )
            ]
        )


class Archive:
    """The sync: one store at a time over the link, activations first, then shots, then traces.

    It is also the replica the mux serves Shots and History from: a store is current once a pass
    ended at the epoch the controller last named (its `rs` notice, the epochs in its ping answer, an
    index answer) with nothing changed since; a notice of another epoch, or a rating, deletion or
    Clear the relay forwards, makes it not current and starts a catch-up at once, paused only by a
    sync hold."""

    def __init__(self, companion: Companion) -> None:
        self.companion = companion
        self.store = ArchiveStore(companion.logs)
        self.store.changed.append(self._user_changed)
        self.available = (
            False  # The archive switch is known: from a cfg, or remembered from the last.
        )
        self.on = False  # ...and the switch is on.
        self.notified: dict[str, int] = {}  # The epochs of the controller's last `rs`, per store.
        self.subscribed = False  # This session's rx went out.
        self.mirrors = {store: IndexMirror(f"archive's {store} index") for store in STORES}
        self.wanted: set[str] = set()
        self.wake = asyncio.Event()
        self.task: asyncio.Task[None] | None = None
        self.retry: asyncio.Task[None] | None = None
        # Index and trace requests waiting for their answer, and fetch pages, by request id.
        self.waiters: dict[tuple[object, ...], asyncio.Future[Mapping[str, object]]] = {}
        self.fetches: dict[object, asyncio.Future[Fetched]] = {}
        self.pages: dict[object, Gathering] = {}
        self.request = 0
        self.syncing: str | None = None
        self.synced_at: float | None = None
        self.error: str | None = None
        # Traces not given yet: asked again after these.
        self.trace_wait: dict[tuple[int, int, int], float] = {}
        self.busy_until = 0.0
        # Stats headers: by full key, and the last whole one per view.
        self.headers: dict[tuple[int, object, Filters, int, int], Header] = {}
        self.complete: dict[tuple[int, object, Filters], Header] = {}
        self.facts_cache: tuple[tuple[str | None, int, int], dict[str, object]] | None = None
        self.unavailable_at: float | None = None
        # The epoch each store's copy is at, as the controller named it last.
        self.epochs: dict[str, int] = {}
        self.current = dict.fromkeys(STORES, False)
        self.ready_at = {store: asyncio.Event() for store in STORES}
        self.marks = dict.fromkeys(
            STORES, 0
        )  # Moves on every reason a pass in flight may be stale.
        # Pages the replica served, pages that went to the controller instead, and requests sent to
        # catch up.
        self.counters = {"served": 0, "fallbacks": 0, "catchUpFetches": 0}

    def usable(self) -> bool:
        return self.companion._log_usable() and self.companion.device_id is not None

    def _user_changed(self) -> None:
        self.headers.clear()
        self.complete.clear()
        self.wake.set()  # A pass in flight sees the change and starts again from the index.
        self.companion.screens.mux.replica_changed()

    # --- Replica ---------------------------------------------------------------------
    def serving(self) -> bool:
        """The replica may serve pages: the switch is on and this link session follows the
        controller."""
        return self.on and self.subscribed and self.usable() and self.companion.outbox is not None

    def state(self, store: str) -> str:
        return "off" if not self.serving() else "current" if self.current[store] else "catchingUp"

    def _stale(self, store: str) -> None:
        self.marks[store] += 1
        self.current[store] = False
        self.ready_at[store].clear()

    def invalidate(self, store: str, done: bool = False) -> None:
        """A rating, deletion or Clear the relay forwards: the store is not current from the moment
        it leaves, and once the controller answered (`done`) the copy catches up."""
        if not self.subscribed:
            return
        self._stale(store)
        if done:
            self.notified.pop(store, None)
            self.wanted.add(store)
            self.wake.set()

    async def ready(self, store: str) -> bool:
        """Whether a page of `store` may come from the replica now: it is current, or catches up
        within CATCH_UP_S. During a sync hold the copy serves as it is: nothing goes upstream during
        a shot."""
        if not self.serving():
            return False
        if self.current[store] or self.companion.sync_hold:
            return True
        self.wanted.add(store)
        self.wake.set()
        try:
            await asyncio.wait_for(self.ready_at[store].wait(), CATCH_UP_S)
        except TimeoutError:
            return bool(self.companion.sync_hold) and self.serving()
        return self.current[store] and self.serving()

    def _synced(self, store: str, mark: int, epoch: int) -> None:
        """A pass ended with the copy at the controller's `epoch`: current unless anything moved
        since."""
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

    async def page(
        self, store: str, query: Mapping[str, object], offset: int, limit: int, boot: object
    ) -> pages.Page:
        """One page from the copy, as pages.py frames it: boot, epoch, good, total, offset, limit,
        hasMore, the row texts with their ids and, when the page holds rows only the archive
        keeps, `archive`."""
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

    async def held_trace(self, query: Mapping[str, str]) -> bytes | None:
        """A shot's trace as the controller's trace route answers it, when the replica holds it."""
        try:
            identity = [int(query[name]) for name in ("id", "boot", "end")]
        except KeyError, ValueError:
            return None
        if not self.serving():
            return None
        return await self.store.trace(self.companion.device_id, *identity)

    # --- Session -----------------------------------------------------------------
    def configure(self, cfg: Mapping[str, object]) -> None:
        """`cfg`: the switch. Off stops the sync and keeps everything stored."""
        self.available, self.on = "archive" in cfg, cfg.get("archive") is True
        if self.on:
            self.start()
        else:
            self.stop()

    def start(self) -> None:
        """Once per session, after `cfg` turned it on and `dev` named the controller: both stores'
        index."""
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

    def stop(self) -> None:
        """The session ended or the switch went off: what is in flight is asked again next time."""
        self.subscribed = False
        for task in (self.task, self.retry):
            if task is not None:
                task.cancel()
        self.task = self.retry = None
        for waiter in self.waiters.values():
            waiter.cancel()
        for fetch in self.fetches.values():
            fetch.cancel()
        self.waiters, self.fetches, self.pages, self.syncing = {}, {}, {}, None
        for store in STORES:
            self._stale(store)
        self.companion.screens.mux.replica_changed()  # Their pages go to the controller again.

    # --- Frames from the controller ------------------------------------------------
    def on_rs(self, frame: Mapping[str, object]) -> None:
        """A store changed and its change is saved: catch up now."""
        if self.subscribed:
            self.on_heartbeat(frame)
            self.trace_wait, self.busy_until = (
                {},
                0.0,
            )  # A notice is when a trace not given yet is asked again.

    def on_heartbeat(self, frame: Mapping[str, object]) -> None:
        """The epochs the controller names (`rs`, its ping answer): one the copy is not at starts a
        catch-up."""
        if not self.subscribed:
            return
        for store, key in (("shots", "sh"), ("history", "hi")):
            epoch = frame.get(key)
            if type(epoch) is int:
                self.notified[store] = epoch
                if epoch != self.epochs.get(store):
                    self._stale(store)
                    self.wanted.add(store)
        self.wake.set()

    def refresh(self, store: str, epoch: object) -> None:
        """The controller's store is at `epoch` (a screen's live Stats frames, a Stats header asked
        for it): sync now instead of at the next notice. The request leaves with the next clear
        frame."""
        if self.subscribed and type(epoch) is int:
            self.notified[store] = epoch
            if epoch != self.epochs.get(store):
                self._stale(store)
            self.wanted.add(store)
            self.wake.set()

    def on_rec(self, frame: Mapping[str, object]) -> None:
        inner = frame.get("f")
        if not isinstance(inner, dict):
            return
        kind = inner.get("type")
        if kind == "records":
            self._resolve(self.waiters, ("records", inner.get("store")), inner)
        elif kind == "history":
            if isinstance(inner.get("records"), list):
                records: Fetched = [(r, {}) for r in inner["records"] if isinstance(r, dict)]
                self._resolve(self.fetches, inner.get("request"), records)
        elif kind == "stats":
            self._stats_frame(inner)

    def on_trc(self, frame: Mapping[str, object]) -> None:
        self._resolve(
            self.waiters, ("trace", frame.get("id"), frame.get("b"), frame.get("e")), frame
        )

    def _resolve[K, V](self, waiters: dict[K, asyncio.Future[V]], key: K, value: V) -> None:
        waiter = waiters.pop(key, None)
        if waiter is not None and not waiter.done():
            waiter.set_result(value)

    def _stats_frame(self, frame: Mapping[str, object]) -> None:
        """A fetch page arrives in frames sharing `seq`; a new seq at rowBase 0 restarts it."""
        request, rows, cols = frame.get("request"), frame.get("rows"), frame.get("cols")
        if not isinstance(rows, list):
            return
        page = self.pages.get(request)
        if frame.get("rowBase") == 0 and isinstance(cols, str):
            page = self.pages[request] = {
                "seq": frame.get("seq"),
                "cols": cols.split(","),
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
                page["rows"].append((dict(zip(page["cols"], values[:-1], strict=True)), values[-1]))
        if frame.get("more") is not True:
            self._resolve(self.fetches, request, self.pages.pop(request)["rows"])

    async def _ask[K, V](
        self, frame: dict[str, object], waiters: dict[K, asyncio.Future[V]], key: K
    ) -> V:
        """Send a request and wait for its answer, asking again after REQUEST_S."""
        while True:
            waiter: asyncio.Future[V] = asyncio.get_running_loop().create_future()
            waiters[key] = waiter
            if not self.companion.post_sync(frame, "archive"):
                raise GoneError
            self.counters["catchUpFetches"] += 1
            try:
                return await asyncio.wait_for(waiter, REQUEST_S)
            except TimeoutError:
                log(
                    f"the controller did not answer the archive's {frame['t']} request; "
                    "asking again"
                )

    # --- The sync ------------------------------------------------------------------
    async def _run(self) -> None:
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
                            except ChangedError:
                                self.wanted.add(store)
                                self.wake.set()
                    self.syncing = "traces"
                    await self._traces()
                    self.synced_at, self.error = time.time(), None
                except Exception as error:  # A disk error or a bad answer: the next notice retries.
                    if isinstance(error, GoneError):
                        raise
                    self.error = str(error)
                    log(
                        f"the archive sync stopped ({error}); it resumes at the controller's next "
                        "notice"
                    )
                finally:
                    self.syncing = None
        except GoneError:
            pass

    def _steady(self, revision: int) -> None:
        """The user has not changed the archive since this pass started."""
        if self.store.revision != revision:
            raise ChangedError

    async def _restart(
        self,
        store: str,
        generation: int,
        counters: list[int],
        revision: int,
        cleared: bool = False,
    ) -> int:
        self._steady(revision)
        count = await self.store.restart(
            self.companion.device_id, store, generation, counters, cleared
        )
        log(
            f"the {NAMES[store]} history was cleared on the controller; the archive deleted its "
            f"{count} record(s) too"
            if cleared
            else f"the controller's {NAMES[store]} history restarted; the archive keeps its "
            f"{count} earlier record(s)"
        )
        return generation + 1

    async def _fetch(
        self,
        store: str,
        order: list[int],
        listed: dict[int, int],
        ids: Iterable[int],
        sink: Callable[[list[Record]], Awaitable[None]] | None = None,
    ) -> tuple[list[Record], set[int]]:
        """The records `ids` (positions in `order`), as (id, ident, rev, fields, curve), by fetch
        windows; with a `sink`, each page goes there as it arrives instead (so a broken-off pass
        keeps it)."""
        wanted, found = set(ids), []
        for offset, count in windows(
            [i for i, rid in enumerate(order) if rid in wanted], FETCH_MAX[store]
        ):
            self.request = (self.request + 1) % 2**32 or 1
            page = await self._ask(
                {"t": "rf", "s": store, "o": offset, "n": count, "r": self.request},
                self.fetches,
                self.request,
            )
            rows: list[Record] = []
            for fields, curve in page:
                rid = fields.get("id")
                if isinstance(rid, int) and rid in wanted:
                    wanted.discard(rid)
                    rows.append((rid, ident(store, fields), listed[rid], fields, curve))
            if sink is None:
                found += rows
            else:
                await sink(rows)
        return found, wanted

    async def _sync(self, store: str) -> None:
        device, revision, mark = self.companion.device_id, self.store.revision, self.marks[store]
        generation, epoch, oldest, previous, counters = await self.store.sync_state(device, store)
        if epoch and self.notified.get(store) == epoch:
            self._synced(store, mark, epoch)
            return  # The notice names the epoch this archive already holds.
        # A delta only against the index this mirror holds for that same epoch; one it cannot
        # rebuild asks the whole index once.
        mirror, ask = self.mirrors[store], {"t": "rx", "s": store, "ep": epoch or 0}
        delta = mirror.delta(epoch or 0)
        key = ("records", store)
        index = mirror.apply(await self._ask({**ask, "d": 1} if delta else ask, self.waiters, key))
        if index is None and delta:
            index = mirror.apply(await self._ask({**ask, "ep": 0}, self.waiters, key))
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
        gen, next_id, clr, gone = (
            index.get("gen"),
            index.get("next"),
            index.get("clr"),
            index.get("gone"),
        )
        if (
            type(gen) is not int
            or type(next_id) is not int
            or type(clr) is not int
            or not ints(gone)
            or not ints(rows)  # Always so: the mirror checked it.
        ):
            raise ValueError("a record index without its counters or deletions")
        named = [gen, next_id, clr]
        marked, order = set(gone), rows[0::2]
        listed = dict(zip(order, rows[1::2], strict=True))
        # Exact, and decided before anything is written (an empty index included, so the counters
        # stored never fall back): a Clear count above the stored one is a Clear the user made (a
        # lower one only restarts the count: rolled-back firmware, a store it had to reset), and
        # otherwise either counter falling back is a restarted history.
        cleared = bool(counters and len(counters) > 2 and named[2] > counters[2])
        restarted = cleared or bool(counters and (named[0] < counters[0] or named[1] < counters[1]))
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
        # Shared records first, decided before anything new is written: a changed revision is a
        # rating, or another record under a reused id. One that differs needs every shared one to
        # decide.
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
            self._again(store)  # A record arrived or went meanwhile: catch up again.
            return
        ambiguous = bool(replaced) and len(replaced) < len(shared)
        if replaced and not ambiguous:
            restarted = True  # Every shared id is another record.
            generation = await self._restart(store, generation, named, revision)
            archived = {}
        for row in replaced if ambiguous else ():
            log(
                f"the controller's {NAMES[store]} {row[0]} may be a different record now; the "
                "archive keeps both"
            )
        self._steady(revision)
        await self.store.put(
            device, store, generation, found
        )  # An ambiguous old record is set aside.
        fetched = {row[0] for row in found}

        async def page(rows: list[Record]) -> None:
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
            self._again(store)
            return
        if (
            not restarted and not ambiguous
        ):  # A pass that could not tell records apart mirrors no deletion.
            # Missing at or above the oldest, or named as deleted: the user deleted it; below the
            # oldest and not named, it rotated out and stays.
            deleted = [
                rid for rid in archived if rid not in listed and (rid >= low or rid in marked)
            ]
            await self.store.forget_deleted(device, store, generation, deleted)
        if not restarted and newest is not None and newest < low - 1:
            await self.store.hole(device, store, generation, newest, low)
            log(
                f"up to {low - newest - 1} {NAMES[store]} record(s) rotated out of the controller "
                "before they could be copied"
            )
        self._steady(revision)
        await self.store.adopt(device, store, generation, new_epoch, low, order, named)
        self._synced(store, mark, new_epoch)

    def _again(self, store: str) -> None:
        self.notified.pop(store, None)
        self.wanted.add(store)
        self.wake.set()

    async def _traces(self) -> None:
        """Each shot's trace once, newest first. One still being saved, or a controller too busy to
        read its storage, is asked again only after the next notice or TRACE_RETRY_S."""
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
                    self.waiters,
                    ("trace", record_id, boot, end),
                )
                result = answer.get("r")
                if result == "ok":
                    encoded = answer.get("d") or ""
                    try:
                        data = (
                            base64.b64decode(encoded, validate=True)
                            if isinstance(encoded, str)
                            else b""
                        )
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

    async def _later(self) -> None:
        await asyncio.sleep(TRACE_RETRY_S)
        self.wake.set()

    # --- Stats over the whole history ------------------------------------------------
    async def header(self, window: int, active: object, epoch: int, filters: Filters) -> Header:
        """The Stats header the firmware would build over the merged history, and how many good
        shots the filters keep, once the mirror is at the controller's `epoch`. While the
        controller holds sync (or a request waits for it), the newest complete header answers at
        once, with its own epoch."""
        if not self.on or not self.usable():
            raise UnavailableError("the archive is off or its store is closed")
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
                    raise UnavailableError(
                        f"the copy is at shot epoch {synced}, the controller at {epoch}"
                    )
                if view in self.complete:
                    return self.complete[view]
        key = (*view, self.store.revision, synced)
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

    def note_unavailable(self, error: Exception) -> None:
        """One log line per cause at most every five minutes: screens fall back without a word."""
        if self.unavailable_at is None or time.monotonic() - self.unavailable_at >= 300:
            self.unavailable_at = time.monotonic()
            log(
                f"the Stats header over the whole history is unavailable ({error}); screens show "
                "the controller's"
            )

    # --- Facts -----------------------------------------------------------------------
    async def facts(self) -> dict[str, object]:
        facts: dict[str, object] = {
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
