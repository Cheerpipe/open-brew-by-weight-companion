#!/usr/bin/env python3
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
import sys
import tempfile
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from companion import stats  # noqa: E402
from companion.archive import ArchiveStore  # noqa: E402
from companion.logstore import LogStore  # noqa: E402

VECTORS = ROOT / "tests/fixtures/stats-header-v1.vectors.json"
SHA256 = "ad46e4e9d0acc434d37a72b3f60e2dc2f4b7a1b713f37c0410f316d8188de547"


async def archived(cases):
    """Each case's rows stored as the archive copies them, read back as its Stats header reads them."""
    with tempfile.TemporaryDirectory(prefix="openbrewbyweight-stats-") as temporary:
        logs = LogStore(Path(temporary))
        await logs.open()
        store, merged = ArchiveStore(logs), []
        for n, case in enumerate(cases):
            await store.put(f"case{n}", "shots", 1, [(row["id"], f"7:{row['id']}", 0, row, {}) for row in case["rows"]])
            merged.append(await store.merged(f"case{n}"))
        await logs.close()
        return merged


def main():
    assert hashlib.sha256(VECTORS.read_bytes()).hexdigest() == SHA256, \
        "the vectors differ from the firmware's: copy its file again"
    vectors = json.loads(VECTORS.read_text())
    assert vectors["version"] == 1 and len(vectors["cases"]) >= 7
    for case in vectors["cases"]:
        for row in case["rows"]:
            assert stats.Record(row).bad_reason() == row["badReason"], (case["name"], row["id"])
        built = stats.header(case["rows"], case["window"], case["presetId"])
        assert built == case["header"], (case["name"], [key for key in case["header"]
                                                        if built.get(key) != case["header"][key]])
        assert json.loads(json.dumps(built)) == case["header"]
    rows = vectors["cases"][0]["rows"]
    good = [row for row in rows if row["badReason"] is None]
    assert stats.good(rows, [], [], []) == len(good)
    fast = [row for row in good if row["verdict"] == "fast" and row["arrivalS"]]
    assert stats.good(rows, [1], [], []) == len(fast), "the result filter needs a time to target"
    pearl = stats.scale_key("Pearl S")
    assert stats.good(rows, [], [], [pearl]) == sum(row["scaleName"] == "Pearl S" for row in good)
    for case, rows in zip(vectors["cases"], asyncio.run(archived(vectors["cases"]))):
        assert stats.header(rows, case["window"], case["presetId"]) == case["header"], \
            f"{case['name']}: the archive's copy gives another header than the controller's"
    print(f"Companion Stats header: {len(vectors['cases'])} golden cases, the archive's parity and the "
          "window count OK")


main()
