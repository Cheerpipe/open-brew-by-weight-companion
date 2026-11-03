"""The Web UI Stats header over the whole history: a port of the firmware's formatStatsHeader.

The firmware builds the header (the aggregate, both density charts, the
consistency series and the filter facets) over its newest 1000 shots; the
companion builds the same header over the merged history and the browser
draws it with the same renderer. The port follows the firmware line for line
(`OpenBrewByWeightStatsHeader.inc`, `OpenBrewByWeightStatsJson.inc`,
`shotLogStatsView` and the record helpers of `OpenBrewByWeightShotLogTypes.h`)
and is held to the shared golden vectors (`stats-header-v1.vectors.json`):

- Rows are Stats rows; each goes back to the stored record's integers first
  (`docs/schemas/README.md` in the firmware repository has the formulas).
- The density chart runs in float32: every operation is rounded to float32,
  `expf` is float32 rounding of `math.exp`, `roundf` and `lroundf` round half
  away from zero.
- The aggregate is double arithmetic printed with `%.1f`/`%.2f`; the BBW error
  is integer tenths (truncated) and its count may reach past the window.
- Sums are exact here: the firmware's 32-bit sums never see more than 100
  shots, while the companion also answers 500 and 1000.
"""

import math
import struct
import zlib
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from collections.abc import Collection, Iterable, Sequence

FILTER_MAX = 8  # SHOT_LIST_FILTER_MAX: facets list at most eight presets and eight scales.
MISSING = None
# Looked up with a row's verdict, which may be missing (None).
VERDICTS: dict[str | None, int] = {"on_recipe": 0, "fast": 1, "slow": 2}
BBW_STOPS = frozenset({"normal_target", "extended_max_weight", "slow_min_weight"})
# Every row field the header reads (Record below), so callers can leave the rest, the curve above
# all.
FIELDS = (
    "durationS",
    "goalG",
    "fastBeforeS",
    "slowAfterS",
    "arrivalS",
    "actualG",
    "cutLineG",
    "avgFlowGS",
    "verdict",
    "shotType",
    "stopDetail",
    "presetId",
    "presetName",
    "scaleName",
    "hasWallTime",
    "endedAtLocalSec",
)


class Row(TypedDict, total=False):
    """A Stats row: the fields above, each possibly missing or null."""

    durationS: float | None
    goalG: float | None
    fastBeforeS: float | None
    slowAfterS: float | None
    arrivalS: float | None
    actualG: float | None
    cutLineG: float | None
    avgFlowGS: float | None
    verdict: str | None
    shotType: str | None
    stopDetail: str | None
    presetId: int | None
    presetName: str | None
    scaleName: str | None
    hasWallTime: int | None  # true, or 1 as the archive reads it back (json_extract)
    endedAtLocalSec: int | None


class Aggregate(TypedDict):
    shotCount: int
    avgDurationS: float | None
    avgYieldG: float | None
    avgErrorPct: float | None
    avgFlowGps: float | None
    shotsPerDay: float | None


class Density(TypedDict):
    lo: int
    hi: int
    a: float
    b: float
    shared: bool
    n: list[int]
    h: list[int]


class Consistency(TypedDict):
    t: list[int | None]
    p: int | list[int]


class Facets(TypedDict):
    presets: list[list[int | str]]
    scales: list[list[int | str]]


class Header(Aggregate):
    dens: list[Density | bool | None]
    cons: Consistency
    facets: Facets


def f32(value: float) -> float:
    rounded: float = struct.unpack("f", struct.pack("f", value))[0]
    return rounded


def round_away(value: float) -> int:
    """C's roundf/lroundf: half away from zero."""
    return math.floor(value + 0.5) if value >= 0 else -math.floor(-value + 0.5)


def tenths(seconds: float | None) -> int | None:
    return None if seconds is None else round(seconds * 10)


def hundredths(grams: float | None) -> int | None:
    return None if grams is None else round(grams * 100)


def known(value: int | None) -> int:
    """A value the record's checks guarantee: an eligible record's yield, a timed one's arrival."""
    if value is None:
        raise ValueError("a value the record's checks guarantee is missing")
    return value


def scale_key(name: str | None) -> int:
    """shotLogScaleKey: the firmware's CRC-32 update from 0xFFFFFFFF, without the final xor."""
    return zlib.crc32(str(name or "").encode()) ^ 0xFFFFFFFF


class Record:
    """A Stats row back as the stored record's integers (missing values as None)."""

    __slots__ = (
        "actual",
        "arrival",
        "auto",
        "bbw_stop",
        "cut",
        "duration",
        "fast",
        "flow",
        "goal",
        "local",
        "preset",
        "preset_name",
        "result",
        "scale",
        "slow",
        "wall",
    )

    def __init__(self, row: Row) -> None:
        self.duration = tenths(row.get("durationS")) or 0
        self.goal = round((row.get("goalG") or 0) * 10)
        self.fast, self.slow = (
            tenths(row.get("fastBeforeS")) or 0,
            tenths(row.get("slowAfterS")) or 0,
        )
        self.arrival = tenths(row.get("arrivalS"))
        self.actual, self.cut, self.flow = (
            hundredths(row.get("actualG")),
            hundredths(row.get("cutLineG")),
            hundredths(row.get("avgFlowGS")),
        )
        timed = self.arrival is not None and self.arrival != 0
        self.result = VERDICTS.get(row.get("verdict"), 3) if timed else 3
        self.auto, self.bbw_stop = row.get("shotType") == "auto", row.get("stopDetail") in BBW_STOPS
        self.preset, self.preset_name = row.get("presetId") or 0, row.get("presetName") or ""
        self.scale = row.get("scaleName") or ""
        self.wall, self.local = bool(row.get("hasWallTime")), row.get("endedAtLocalSec") or 0

    def bad_reason(self) -> str | None:
        """shotLogBadReason: over 12 s with a settled yield over 2 g."""
        return (
            "short"
            if self.duration <= 120
            else "no_yield"
            if self.actual is None
            else "low_yield"
            if self.actual <= 200
            else None
        )

    def eligible(self) -> bool:
        return self.bad_reason() is None

    def bbw_tenths(self) -> int:
        planned = self.cut if self.cut is not None and self.cut > 0 else self.goal * 10
        return abs(known(self.actual) - planned) * 1000 // (planned if planned > 0 else 1)


def matches(
    record: Record, results: Collection[int], presets: Collection[int], scales: Collection[int]
) -> bool:
    """shotListFilterMatches for good shots: AND across groups, OR within."""
    if results and (record.result > 2 or record.result not in results):
        return False
    return (not presets or record.preset in presets) and (
        not scales or scale_key(record.scale) in scales
    )


def aggregate(records: Iterable[Record], window: int) -> Aggregate:
    """shotLogStatsView and buildIntegrationStats without the window, total and durations."""
    count = flows = bbw = timed = duration = actual = errors = flow = 0
    newest = oldest = -1
    for record in records:
        if count >= window and bbw >= window:
            break
        if not record.eligible():
            continue
        if bbw < window and record.auto and record.goal > 0 and record.bbw_stop:
            bbw += 1
            errors += record.bbw_tenths()
        if count >= window:
            continue
        count += 1
        duration += record.duration
        actual += known(record.actual)
        if record.flow is not None:
            flows += 1
            flow += record.flow * 100
        if record.wall and record.local:
            timed += 1
            day = record.local // 86400
            newest = max(newest, day)
            oldest = day if oldest < 0 or oldest > day else oldest
    span = newest - oldest if newest >= 0 and oldest >= 0 else 0

    def printed(value: float, places: int) -> float:
        return float(f"{value:.{places}f}")

    return {
        "shotCount": count,
        "avgDurationS": printed(duration / (10.0 * count), 1) if count else None,
        "avgYieldG": printed(actual / (100.0 * count), 1) if count else None,
        "avgErrorPct": printed(errors / bbw / 10.0, 1) if bbw else None,
        "avgFlowGps": printed(flow / flows / 10000.0, 2) if flows else None,
        "shotsPerDay": printed(timed / (span + 1.0), 1) if timed else None,
    }


def density(shots: Sequence[Record]) -> Density:
    """appendStatsDensity, operation for operation in float32."""
    shared, width, counts = True, 0.0, [0, 0, 0, 0]
    for shot in shots:
        shared = shared and shot.fast == shots[0].fast and shot.slow == shots[0].slow
        width = f32(width + f32(f32(shot.slow - shot.fast) / 10))
        counts[shot.result] += 1
    a = f32(shots[0].fast / 10) if shared else 0.0
    b = f32(shots[0].slow / 10) if shared else f32(round_away(f32(width / f32(len(shots)))))
    low, high, mapped = f32(a - 5), f32(b + 5), list[float]()
    for shot in shots:
        t, f, s = f32(known(shot.arrival) / 10), f32(shot.fast / 10), f32(shot.slow / 10)
        if t < f:
            x = f32(f32(a + t) - f)
        elif t > s:
            x = f32(f32(b + t) - s)
        elif s > f:
            x = f32(a + f32(f32(f32(t - f) / f32(s - f)) * f32(b - a)))
        else:
            x = a
        mapped.append(x)
        low, high = min(low, x), max(high, x)
    lo, hi = math.floor(f32(low - 1)), math.ceil(f32(high + 1))
    span = f32(hi - lo)
    bandwidth = max(f32(0.7), f32(span / 28))
    heights = []
    for k in range(121):
        x = f32(lo + f32(f32(span * k) / 120))
        total = 0.0
        for point in mapped:
            z = f32(f32(x - point) / bandwidth)
            if abs(z) < 4:
                total = f32(total + f32(math.exp(f32(f32(-0.5 * z) * z))))
        heights.append(total)
    peak = max(heights)
    return {
        "lo": lo,
        "hi": hi,
        "a": float(f"{a:.1f}"),
        "b": float(f"{b:.1f}"),
        "shared": shared,
        "n": [counts[1], counts[0], counts[2]],
        "h": [int(round_away(f32(f32(100 * height) / peak))) for height in heights],
    }


def header(rows: Iterable[Row], window: int, active: int) -> Header:
    """formatStatsHeader over `rows` (Stats rows, newest first) for `window` and the active
    preset."""
    records = [Record(row) for row in rows]
    built = aggregate(records, window)
    timed, own, found = [], 0, 0
    for record in records:
        if found >= window:
            break
        if not record.eligible():
            continue
        found += 1
        if record.result > 2:
            continue
        timed.append(record)
        own += record.preset == active
    one_preset = all(record.preset == timed[0].preset for record in timed)
    dens: list[Density | bool | None] = [
        density(timed) if timed else None,
        density([r for r in timed if r.preset == active])
        if 0 < own < len(timed)
        else bool(own) or None,
    ]
    cons: Consistency = {
        "t": [record.arrival for record in reversed(timed)],
        "p": (timed[0].preset if timed else 0)
        if one_preset
        else [record.preset for record in reversed(timed)],
    }
    presets: list[list[int | str]] = []
    scales: list[list[int | str]] = []
    for record in records:
        if (
            len(presets) < FILTER_MAX
            and record.eligible()
            and record.preset not in [p for p, _ in presets]
        ):
            presets.append([record.preset, record.preset_name])
    for record in records:
        key = scale_key(record.scale)
        if (
            len(scales) < FILTER_MAX
            and record.scale
            and record.eligible()
            and key not in [k for k, _ in scales]
        ):
            scales.append([key, record.scale])
    return {**built, "dens": dens, "cons": cons, "facets": {"presets": presets, "scales": scales}}


def good(
    rows: Iterable[Row],
    results: Collection[int],
    presets: Collection[int],
    scales: Collection[int],
) -> int:
    """How many good shots the filters keep: the N the window choices follow (S18)."""
    return sum(
        1
        for row in rows
        if (record := Record(row)).eligible() and matches(record, results, presets, scales)
    )
