"""Package and verify upload of only the local Docker CPU mock receipt and CSVs."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import getpass
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import sys
import warnings
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from . import r2_pilot, r2_pilot_prompt

ROOT = Path(__file__).resolve().parents[3]
RUN_PATTERN = re.compile(r"[0-9a-f]{12}\Z")
KEY_PATTERN = re.compile(r"tcc/piloto/docker-[0-9a-f]{12}-[0-9a-f]{32}\.zip\Z")
RECEIPT = {
    "status": "verified", "kind": "local-cpu-simulator-mock", "nodes": 20, "rounds": 5,
    "expected_node_rounds": 100, "verified_node_rounds": 100,
    "live_llm": False, "gpu": False, "separate_process_per_node": False,
}
ROUND_COLUMNS = (
    "experiment_id round_index task_id expected consensus_weighted consensus_correct consensus_majority "
    "majority_correct num_responses num_nodes mean_latency_ms n_distinct_answers n_absent absent_rate "
    "std_answers median_answers mad_answers consensus_margin_weighted consensus_margin_majority "
    "is_tie_weighted is_tie_majority is_test test_round pct_honest_exact pct_honest_responded audited calibration"
).split()
NODE_COLUMNS = (
    "experiment_id round_index task_id node_id profile answered answer expected correct abs_error rel_error "
    "latency_ms score_initial reputation_before reputation_after delta reward punishment alpha_used mechanism "
    "weight_used consensus_weighted_result consensus_majority_result consensus_weighted_correct "
    "consensus_majority_correct is_tie_weighted is_tie_majority is_test"
).split()
TEXT = {
    "experiment_id": re.compile(r"pilot\Z"),
    "task_id": re.compile(r"gsm8k-test-[0-4]\Z"),
    "node_id": re.compile(r"node-(?:[0-9]|1[0-9])\Z"),
    "profile": re.compile(r"honest\Z"),
    "mechanism": re.compile(r"ema_slow_up\Z"),
}
NUMERIC = re.compile(r"(?:[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)?\Z", re.ASCII)


def _read(root, name):
    path = root / name
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Expected local mock output file is missing or outside its output folder.")
    if path.stat().st_size > 100 * 1024:
        raise ValueError("Local mock output file exceeds the pilot bound.")
    return path.read_bytes()


def _rows(data, expected_columns):
    reader = csv.DictReader(io.StringIO(data.decode("utf-8"), newline=""), strict=True)
    if reader.fieldnames != expected_columns:
        raise ValueError("CSV columns do not match the allowed pilot format.")
    rows = list(reader)
    for row in rows:
        if set(row) != set(expected_columns) or any(
            value is None or len(value) > 64 or not TEXT.get(key, NUMERIC).fullmatch(value)
            for key, value in row.items()
        ):
            raise ValueError("CSV contains unexpected fields or data outside the safe pilot format.")
    return rows


def archive_run(root):
    receipt = json.loads(_read(root, "receipt.json"))
    if receipt != RECEIPT or any(type(receipt[k]) is not type(v) for k, v in RECEIPT.items()):
        raise ValueError("Only the verified CPU Docker mock receipt is compatible.")
    rounds = _read(root, "pilot/rounds.csv")
    nodes = _read(root, "pilot/per_node.csv")
    r = _rows(rounds, ROUND_COLUMNS)
    n = _rows(nodes, NODE_COLUMNS)
    if (len(r) != 5 or len(n) != 100
            or {(row["round_index"], row["task_id"], row["num_nodes"]) for row in r}
            != {(str(i), f"gsm8k-test-{i}", "20") for i in range(5)}
            or {(row["round_index"], row["task_id"], row["node_id"]) for row in n}
            != {(str(i), f"gsm8k-test-{i}", f"node-{j}") for i in range(5) for j in range(20)}):
        raise ValueError("CSV does not contain exactly the five rounds and 100 verified logical-node records.")
    payload = io.BytesIO()
    with ZipFile(payload, "w") as zipfile:
        for name, data in (
            ("receipt.json", (json.dumps(receipt, indent=2) + "\n").encode("ascii")),
            ("pilot/rounds.csv", rounds),
            ("pilot/per_node.csv", nodes),
        ):
            zipfile.writestr(ZipInfo(name), data, compress_type=ZIP_DEFLATED)
    return payload.getvalue()


def _save_local(root, data):
    path = root / "r2-docker-pilot.zip"
    try:
        with path.open("xb") as handle:
            handle.write(data)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != data:
            raise ValueError("Existing local package differs; refusing overwrite.") from None
    return path


def run(*, config, key, put_url, get_url, data, opener=None, now=None):
    return r2_pilot._send_payload(
        config, key, put_url, get_url, data=data, key_pattern=KEY_PATTERN,
        content_type="application/zip", opener=opener, now=now,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--prepare-only", action="store_true", help="Package and fingerprint locally, no network.")
    args = parser.parse_args()
    if not RUN_PATTERN.fullmatch(args.run_id):
        parser.error("Use a valid local Docker pilot ID.")
    if not args.prepare_only and (not sys.stdin.isatty() or not sys.stderr.isatty()):
        print("No upload: use a normal terminal with hidden input, or pass --prepare-only.", file=sys.stderr)
        return 2
    try:
        root = ROOT / "resultados" / "docker-local" / args.run_id
        if not root.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError("Unexpected local path.")
        data = archive_run(root)
        local = _save_local(root, data)
        print(json.dumps({"status": "prepared_locally", "file": str(local), "bytes": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()}))
        if args.prepare_only:
            return 0
        config = r2_pilot.load_config()
        key = f"tcc/piloto/docker-{args.run_id}-{secrets.token_hex(16)}.zip"
        print(f"Upload only the verified local mock package to {config['bucket']}/{key}.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            access_id = getpass.getpass("R2 S3 Access Key ID (hidden): ")
            secret = getpass.getpass("R2 S3 Secret Access Key (hidden): ")
        try:
            put_url, get_url = r2_pilot_prompt._create_urls(
                config, key, access_id.strip(), secret.strip(), datetime.now(timezone.utc), key_pattern=KEY_PATTERN
            )
        finally:
            del access_id, secret
        try:
            result = run(config=config, key=key, put_url=put_url, get_url=get_url, data=data)
        finally:
            del put_url, get_url
        print(json.dumps(result))
        return 0
    except (KeyboardInterrupt, EOFError):
        print("Stopped; remote write, if already attempted, is not reported as verified.", file=sys.stderr)
        return 130
    except Exception:
        print("Not verified. Check local pilot artifacts or scoped R2 access; no secrets will be printed.",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
