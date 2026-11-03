"""The Stats and History pages, built from the archive's copy as the ui-stream sends them.

A port of the firmware's page senders (`sendStatsStream`, `sendHistoryStream`,
`formatShotStatsRow` and the Stats header's text): the same members in the
same order, numbers printed with the same decimals and frames split at the
same byte budget. The shared golden vectors (`companion-records-v1.vectors.json`,
its `page_*` cases) hold it to the firmware frame for frame, every member but
the page identities `tag`, `seq` and `request`, which the companion assigns
itself (`tag` is a CRC-32 of its own page). A row only the archive holds
carries the archive's markers: `archiveOnly`, `archiveGeneration` and, for a
shot, `archiveTrace` (in a Stats row's last object, beside its curve).
"""

import json
import zlib
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from collections.abc import Mapping

# A JSON value as json.loads returns it: a stored row's body.
type Json = bool | int | float | str | list[Json] | dict[str, Json] | None


class Page(TypedDict):
    """A page from the archive's copy (Archive.page): each row is (id, text, archive only)."""

    boot: object  # Home's boot as the controller sent it, passed through unchecked.
    epoch: int
    good: int
    total: int
    offset: int
    limit: int
    hasMore: bool
    rows: list[tuple[int, str, bool]]
    archive: dict[str, object] | None


# kStatsRowColumns, in the firmware's order.
COLUMNS = (
    "id,bootId,endedAtMs,hasWallTime,endedAtLocalSec,endedAtUnixSec,timezoneOffsetMinutesAtCommit,"
    "durationS,presetId,presetName,scaleName,goalG,actualG,offsetG,bbwAlgorithm,bbwAlgorithmVersion,"
    "bbwAlpha,bbwLearningApplied,avgFlowGS,targetTempDeciC,doseG,ratio,firstDropS,tareS,shotType,cutType,"
    "extractionGuardEnabled,extractionExtended,slowExtractionGuardEnabled,slowExtractionExtended,"
    "stopDetail,cutLineG,arrivalS,verdict,channeling,scaleLossSource,estimatedG,blind,fastBeforeS,"
    "slowAfterS,fastMarginG,slowMarginG,delayS,wallS,fastRampS,slowRampS,fastCurve,slowCurve,"
    "fastCurveHardness,slowCurveHardness,dripDelayS,actualWeightSource,rating,badReason,number"
)
NAMES = COLUMNS.split(",")
FRAME_BYTES = 8192  # kStatsStreamFrameBytes
# Decimals each number is printed with (%.1f, %.2f, FixedText(ms, 3)); every other number
# is an integer.
PLACES: dict[str | None, int] = {
    **dict.fromkeys(
        (
            "durationS",
            "goalG",
            "doseG",
            "firstDropS",
            "tareS",
            "arrivalS",
            "fastBeforeS",
            "slowAfterS",
            "fastMarginG",
            "slowMarginG",
            "delayS",
            "wallS",
            "fastRampS",
            "slowRampS",
            "fastCurveHardness",
            "slowCurveHardness",
            "dripDelayS",
            "avgDurationS",
            "avgYieldG",
            "avgErrorPct",
            "shotsPerDay",
            "a",
            "b",
        ),
        1,
    ),
    **dict.fromkeys(
        (
            "actualG",
            "offsetG",
            "bbwAlpha",
            "avgFlowGS",
            "ratio",
            "cutLineG",
            "estimatedG",
            "avgFlowGps",
        ),
        2,
    ),
    **dict.fromkeys(("dropS", "extendedS", "atmS", "atmClearedS", "endS"), 3),
}


def text(value: object, key: str | None = None) -> str:
    """JSON as the firmware prints it: compact, UTF-8 as is, numbers with their own decimals."""
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, (int, float)):
        places = PLACES.get(key)
        return f"{value:.{places}f}" if places is not None else str(int(value))
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(text(item, key) for item in value) + "]"
    if not isinstance(value, dict):
        raise TypeError(f"{type(value).__name__} is not JSON")
    return (
        "{"
        + ",".join(f"{json.dumps(name)}:{text(item, name)}" for name, item in value.items())
        + "}"
    )


def marks(only: bool, generation: int, trace: object = None) -> dict[str, object]:
    """The archive's markers on a row it alone holds."""
    if not only:
        return {}
    return {
        "archiveOnly": True,
        "archiveGeneration": generation,
        **({} if trace is None else {"archiveTrace": trace}),
    }


def stats_row(body: Mapping[str, object], marked: Mapping[str, object] | None = None) -> str:
    """formatShotStatsRow: the values in column order, then the curve object (and the markers)."""
    curve = {name: value for name, value in body.items() if name not in NAMES_SET}
    return (
        "["
        + ",".join(text(body.get(name), name) for name in NAMES)
        + ","
        + text({**curve, **(marked or {})})
        + "]"
    )


def history_row(body: Mapping[str, object], marked: Mapping[str, object] | None = None) -> str:
    return text({**body, **(marked or {})})


def _tag(*parts: str) -> int:
    return zlib.crc32("\n".join(parts).encode()) or 1


def _rows(page: Page, kept: bool) -> list[str]:
    return [str(rid) if kept and not only else row for rid, row, only in page["rows"]]


def _flag(value: bool) -> str:
    return "true" if value else "false"


def stats_frames(
    page: Page,
    seq: int,
    request: int,
    snapshot: bool,
    header: Mapping[str, object] | None = None,
    kept: int = 0,
) -> tuple[list[str], int]:
    """A Stats page's frames. `page`: boot, epoch, good, total, offset, limit, hasMore and `rows`
    (each row's id, text and whether only the archive holds it); `header` the header dict (None
    leaves it out, as for Home's rows-only fetch); `kept` a tag the screen still holds: when it is
    this page's, the rows go as their ids (whole when only the archive holds them: an id may repeat
    across histories). Returns (frames, tag)."""
    header_text = text(header) if header is not None else ""
    tag = _tag(
        header_text,
        COLUMNS,
        json.dumps([page[name] for name in ("epoch", "total", "offset", "limit")]),
        *(row for _, row, _ in page["rows"]),
    )
    rows = _rows(page, kept == tag)
    frames, sent = [], 0
    while True:
        first = sent == 0
        out = (
            f'{{"v":1,"type":"stats","boot":{page["boot"]},"snapshot":{_flag(first and snapshot)},'
            f'"epoch":{page["epoch"]},"seq":{seq},"request":{request},'
        )
        if first and header is not None:
            out += f'"stats":{header_text},'
        if first:
            out += f'"cols":"{COLUMNS}","tag":{tag},"good":{page["good"]},'
        out += (
            f'"total":{page["total"]},"offset":{page["offset"]},"limit":{page["limit"]},'
            f'"hasMore":{_flag(page["hasMore"])},"rows":['
        )
        used = base = len(out.encode())
        start = sent
        while sent < len(rows):
            size = len(rows[sent].encode())
            if used + (1 if used > base else 0) + size + 48 > FRAME_BYTES and used > base:
                break
            out += ("," if used > base else "") + rows[sent]
            used += (1 if used > base else 0) + size
            sent += 1
        more = sent < len(rows)
        frames.append(out + f'],"rowBase":{start},"more":{_flag(more)}}}')
        if not more:
            return frames, tag


def history_frame(page: Page, request: int, snapshot: bool, kept: int = 0) -> tuple[str, int]:
    """A History page's one frame (at most 120 records stay under the frame budget).
    Returns (frame, tag)."""
    tag = _tag(
        json.dumps([page[name] for name in ("epoch", "total", "offset", "limit")]),
        *(row for _, row, _ in page["rows"]),
    )
    rows = _rows(page, kept == tag)
    return (
        f'{{"v":1,"type":"history","boot":{page["boot"]},"snapshot":{_flag(snapshot)},'
        f'"epoch":{page["epoch"]},"request":{request},"tag":{tag},"total":{page["total"]},'
        f'"offset":{page["offset"]},"limit":{page["limit"]},"hasMore":{_flag(page["hasMore"])},'
        f'"records":[{",".join(rows)}]}}'
    ), tag


NAMES_SET = frozenset(NAMES)
