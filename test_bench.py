#!/usr/bin/env python3
"""Build and check both C profiles; correctness smoke tests, no latency claims."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = {"keygen", "ots-keygen", "sign", "verify", "linkable-sign", "linkable-verify"}
FIELDS = {"type", "schema_version", "suite", "case", "implementation", "falcon", "ring_size", "message_bytes", "round", "sample", "elapsed_ns", "output_bytes", "phases", "verified"}


def build(degree, ring, target="bench-build"):
    subprocess.run(["make", "--no-print-directory", f"FALCON={degree}", f"NOU={ring}", target], cwd=ROOT, check=True, timeout=180)


def binary(degree, ring):
    return ROOT / f"build/bench/FALCON-{degree}-NOU-{ring}-SIGMA-123-NONCE-40/raptor-bench"


def validate(degree, ring, operation=None, message_bytes=1024, sample_count=1, warmup_count=0):
    args = [str(binary(degree, ring)), "--suite", "core", "--falcon", str(degree), "--ring-size", str(ring), "--samples", str(sample_count), "--warmup", str(warmup_count), "--message-bytes", str(message_bytes), "--round", "3"]
    if operation:
        args += ["--operation", operation]
    result = subprocess.run(args, capture_output=True, text=True, check=True, timeout=180)
    records = [json.loads(line) for line in result.stdout.splitlines()]
    config = records[0]
    assert config["type"] == "config"
    assert config["options"] == {"suite": "core", "falcon": degree, "ring_size": ring, "message_bytes": message_bytes, "samples": sample_count, "warmup": warmup_count, "round": 3}
    assert config["sigma"] == 123
    assert config["profile"] and config["challenge"].startswith("sha512" if degree == 512 else "shake256")
    assert len(config["limitations"]) >= 3
    rows = records[1:-1]
    expected_cases = {operation} if operation else CASES
    assert len(rows) == sample_count * len(expected_cases)
    for case in expected_cases:
        assert [row["sample"] for row in rows if row["case"] == case] == list(range(sample_count))
    assert {row["case"] for row in rows} == expected_cases
    for row in rows:
        assert set(row) == FIELDS
        assert row["type"] == "sample" and row["schema_version"] == 1
        assert row["implementation"] == "c-raptor" and row["suite"] == "core"
        assert row["verified"] and isinstance(row["elapsed_ns"], int) and row["elapsed_ns"] > 0
        assert row["round"] == 3 and row["ring_size"] == ring and row["falcon"] == degree
        assert row["message_bytes"] == message_bytes and row["phases"] == []
        if row["case"].startswith("linkable-"):
            public_key_bytes, signature_bytes = (897, 690) if degree == 512 else (1793, 1487)
            assert row["output_bytes"] > 4 * 8 * degree * ring + public_key_bytes
            assert row["output_bytes"] <= 4 * 8 * degree * ring + public_key_bytes + signature_bytes
        else:
            assert row["output_bytes"] is None
    assert records[-1] == {"type": "complete", "schema_version": 1, "samples": len(rows), "verified": True}
    # Emitting complete also proves the driver's preflight accepted both signature
    # roundtrips and rejected a changed message in each construction.
    return config


def validate_rejection(degree):
    invalid = [["--samples", "0"], ["--warmup", "10001"], ["--message-bytes", "1048577"], ["--falcon", str(1536 - degree)], ["--ring-size", "10"], ["--suite", "kem"], ["--operation", "bad"], ["--samples", "-1"], ["--samples", "1z"], ["--bad", "1"], ["--round"], ["--samples", "18446744073709551616"]]
    for args in invalid:
        result = subprocess.run([str(binary(degree, 5))] + args, capture_output=True, text=True, timeout=10)
        assert result.returncode != 0 and not result.stdout, args


def validate_switching():
    digests = {}
    for degree in [512, 1024, 512]:
        build(degree, 5, "all")
        path = ROOT / f"build/self/FALCON-{degree}-NOU-5-SIGMA-123-NONCE-40/raptor"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert hashlib.sha256((ROOT / "build/raptor").read_bytes()).hexdigest() == digest
        if degree in digests:
            assert digest == digests[degree], "cached degree changed on switching back"
        digests[degree] = digest
        build(degree, 5)
        validate(degree, 5, operation="verify")
    assert digests[512] != digests[1024]
    rejected = subprocess.run(["make", "FALCON=768", "bench-path"], cwd=ROOT, capture_output=True, text=True)
    assert rejected.returncode != 0 and "FALCON must be 512 or 1024" in rejected.stderr
    multiword = subprocess.run(["make", "FALCON=512 1024", "bench-path"], cwd=ROOT, capture_output=True, text=True)
    assert multiword.returncode != 0 and "FALCON must be 512 or 1024" in multiword.stderr


if __name__ == "__main__":
    profiles = {}
    for degree in [512, 1024]:
        for ring in [5, 10, 20, 50]:
            build(degree, ring)
            profiles[degree] = validate(degree, ring, sample_count=2 if ring == 5 else 1, warmup_count=1 if ring == 5 else 0)
            print(f"Falcon-{degree}, ring {ring}: JSONL, roundtrips and changed-message rejection passed", flush=True)
        validate_rejection(degree)
        for case in sorted(CASES):
            validate(degree, 5, operation=case, message_bytes=0)
    assert profiles[512]["profile"] != profiles[1024]["profile"]
    assert profiles[512]["challenge"] != profiles[1024]["challenge"]
    validate_switching()
    print("Both degrees: malformed requests, wrong-profile rejection, all six filters/empty messages, and build switching passed")
