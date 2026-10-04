#!/usr/bin/env python3
"""Adapter correctness smoke test; builds must already exist, no latency claims."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = {"keygen", "ots-keygen", "sign", "verify", "linkable-sign", "linkable-verify"}
FIELDS = {"type", "schema_version", "suite", "case", "implementation", "falcon", "ring_size", "message_bytes", "round", "sample", "elapsed_ns", "output_bytes", "phases", "verified"}


def binary(n):
    return ROOT / f"build/bench/NOU-{n}-SIGMA-123-NONCE-40/raptor-bench"


def validate(n, operation=None, message_bytes=1024):
    args = [str(binary(n)), "--suite", "core", "--falcon", "512", "--ring-size", str(n), "--samples", "2", "--warmup", "1", "--message-bytes", str(message_bytes), "--round", "3"]
    if operation:
        args += ["--operation", operation]
    result = subprocess.run(args, capture_output=True, text=True, check=True, timeout=90)
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert records[0]["type"] == "config"
    assert records[0]["options"] == {"suite": "core", "falcon": 512, "ring_size": n, "message_bytes": message_bytes, "samples": 2, "warmup": 1, "round": 3}
    rows = records[1:-1]
    expected_cases = {operation} if operation else CASES
    assert len(rows) == 2 * len(expected_cases)
    assert {row["case"] for row in rows} == expected_cases
    for case in expected_cases:
        assert [row["sample"] for row in rows if row["case"] == case] == [0, 1]
    for row in rows:
        assert set(row) == FIELDS
        assert row["type"] == "sample" and row["schema_version"] == 1
        assert row["implementation"] == "c-raptor" and row["suite"] == "core"
        assert row["verified"] and isinstance(row["elapsed_ns"], int) and row["elapsed_ns"] > 0
        assert row["round"] == 3 and row["ring_size"] == n and row["falcon"] == 512
        assert row["message_bytes"] == message_bytes and row["phases"] == []
        if row["case"].startswith("linkable-"):
            assert row["output_bytes"] > 4 * 8 * 512 * n + 897
            assert row["output_bytes"] <= 4 * 8 * 512 * n + 897 + 690
        else:
            assert row["output_bytes"] is None
    assert records[-1] == {"type": "complete", "schema_version": 1, "samples": len(rows), "verified": True}


if __name__ == "__main__":
    for ring in [5, 10, 20, 50]:
        validate(ring)
        print(f"ring {ring}: JSONL and correctness checks passed")
    invalid = [["--samples", "0"], ["--warmup", "10001"], ["--message-bytes", "1048577"], ["--falcon", "1024"], ["--ring-size", "10"], ["--suite", "kem"], ["--operation", "bad"], ["--samples", "-1"], ["--samples", "1z"], ["--bad", "1"], ["--round"], ["--samples", "18446744073709551616"]]
    for args in invalid:
        result = subprocess.run([str(binary(5))] + args, capture_output=True, text=True, timeout=10)
        assert result.returncode != 0 and not result.stdout, args
    for case in sorted(CASES):
        validate(5, operation=case, message_bytes=0)
    print("12 malformed requests and all six operation filters/empty-message fixtures passed")
