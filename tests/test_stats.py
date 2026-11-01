#!/usr/bin/env python3
"""The Stats header port against the firmware's golden vectors, field for field.

`tests/fixtures/stats-header-v1.vectors.json` is the firmware's own file
(docs/schemas/ in the firmware repository, written by its host test from
formatStatsHeader); its checksum pins the copy. Offline, inside the image
(see the README).
"""

import hashlib
import json
import sys
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from companion import stats  # noqa: E402

VECTORS = ROOT / "tests/fixtures/stats-header-v1.vectors.json"
SHA256 = "ad46e4e9d0acc434d37a72b3f60e2dc2f4b7a1b713f37c0410f316d8188de547"


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
    print(f"Companion Stats header: {len(vectors['cases'])} golden cases and the window count OK")


main()
