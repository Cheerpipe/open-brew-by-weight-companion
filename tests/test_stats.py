"""The Stats header port against the firmware's golden vectors, field for field.

`tests/fixtures/stats-header-v1.vectors.json` is the firmware's own file
(docs/schemas/ in the firmware repository, written by its host test from
formatStatsHeader); its checksum pins the copy. The same records copied into
the archive give the controller's header too (AC14): the archive keeps every
field the header reads. Offline, inside the image (see the README).
"""

import asyncio
import hashlib
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, NotRequired, TypedDict, cast

from companion import stats
from companion.archive import ArchiveStore
from companion.logstore import LogStore

if TYPE_CHECKING:
    from collections.abc import Sequence

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests/fixtures/stats-header-v1.vectors.json"
SHA256 = "31973058e192b6ea7f5f133ee9a546e2a534b576e8d5b2df36d25acb91a4f884"


class VectorRow(stats.Row, TypedDict):
    id: int
    badReason: str | None


class Case(TypedDict):
    name: str
    window: int
    days: NotRequired[tuple[int, int]]  # A range of local days the window counts within.
    presetId: int
    rows: list[VectorRow]
    header: stats.Header


class Vectors(TypedDict):
    version: int
    cases: list[Case]


async def archived(cases: Sequence[Case]) -> list[list[stats.Row]]:
    """Each case's rows stored as the archive copies them, read back as its Stats header reads
    them."""
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-stats-") as temporary:
        logs = LogStore(Path(temporary))
        await logs.open()
        store = ArchiveStore(logs)
        merged: list[list[stats.Row]] = []
        for n, case in enumerate(cases):
            await store.put(
                f"case{n}",
                "shots",
                1,
                [(row["id"], f"7:{row['id']}", 0, row, {}) for row in case["rows"]],
            )
            merged.append(await store.merged(f"case{n}"))
        await logs.close()
        return merged


def load() -> Vectors:
    return cast("Vectors", json.loads(VECTORS.read_text()))


def days(case: Case) -> tuple[int, int] | None:
    return (case["days"][0], case["days"][1]) if "days" in case else None


def test_days_ok() -> None:
    assert [
        stats.days_ok(days)
        for days in (
            (1, 1),
            (20000, 20006),
            [65535, 65535],
            (0, 1),
            (5, 4),
            (1, 65536),
            (1,),
            (1.0, 2),
        )
    ] == [True, True, True, False, False, False, False, False]
    assert stats.window_and_days(50) == (50, None)
    assert stats.window_and_days((3, 4)) == (stats.RANGE_SHOTS, (3, 4))


def test_vectors_are_the_firmwares() -> None:
    assert hashlib.sha256(VECTORS.read_bytes()).hexdigest() == SHA256, (
        "the vectors differ from the firmware's: copy its file again"
    )
    vectors = load()
    assert vectors["version"] == 1
    assert len(vectors["cases"]) >= 14
    assert any("days" in case for case in vectors["cases"]), "ranges of days are covered"


def test_golden_cases() -> None:
    for case in load()["cases"]:
        for row in case["rows"]:
            assert stats.Record(row).bad_reason() == row["badReason"], (case["name"], row["id"])
        built = stats.header(case["rows"], case["window"], case["presetId"], days(case))
        assert built == case["header"], (
            case["name"],
            [key for key, value in case["header"].items() if built.get(key) != value],
        )
        assert json.loads(json.dumps(built)) == case["header"]


def test_window_count() -> None:
    rows = load()["cases"][0]["rows"]
    good = [row for row in rows if row["badReason"] is None]
    assert stats.good(rows, [], [], []) == len(good)
    fast = [row for row in good if row["verdict"] == "fast" and row["arrivalS"]]
    assert stats.good(rows, [1], [], []) == len(fast), "the result filter needs a time to target"
    pearl = stats.scale_key("Pearl S")
    assert stats.good(rows, [], [], [pearl]) == sum(row["scaleName"] == "Pearl S" for row in good)


def test_archive_parity() -> None:
    cases = load()["cases"]
    for case, copied in zip(cases, asyncio.run(archived(cases)), strict=True):
        assert (
            stats.header(copied, case["window"], case["presetId"], days(case)) == case["header"]
        ), f"{case['name']}: the archive's copy gives another header than the controller's"
