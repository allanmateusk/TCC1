"""CPU mock: one simulator process, 20 logical nodes and five rounds."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from sistema.simulate import parse_args, run_simulation

ROOT = Path(__file__).resolve().parent
OUTPUT = Path("/tmp/tcc-output")


def main():
    task_data = json.loads((ROOT / "pilot-tasks.json").read_text(encoding="utf-8"))
    args = parse_args([
        "--nodes", "20", "--rounds", "5", "--seed", "0", "--malicious", "0", "--unstable", "0",
        "--orchestration", "dynamic", "--topology", "kregular", "--degree", "4",
        "--signal", "consensus", "--consensus-mode", "distance", "--consensus-center", "medoid",
        "--defense", "all", "--mechanism", "ema_slow_up", "--calibration-rounds", "0",
        "--audit-mode", "random", "--audit-p", "0.2", "--validation-score", "exact",
        "--output", str(OUTPUT), "--experiment-id", "pilot", "--quiet", "--no-row-sync",
    ])
    args.tasks = task_data
    run_simulation(args)
    with (OUTPUT / "pilot" / "rounds.csv").open(newline="", encoding="utf-8") as h:
        rounds = list(csv.DictReader(h))
    with (OUTPUT / "pilot" / "per_node.csv").open(newline="", encoding="utf-8") as h:
        rows = list(csv.DictReader(h))
    expected = {(i, f"node-{j}") for i in range(5) for j in range(20)}
    observed = {(int(row["round_index"]), row["node_id"]) for row in rows}
    if len(rounds) != 5 or any(int(row["num_nodes"]) != 20 for row in rounds):
        raise RuntimeError("Pilot did not complete 5 × 20 logical nodes.")
    if len(rows) != 100 or observed != expected:
        raise RuntimeError("Missing or duplicate node-round rows.")
    receipt = {
        "status": "verified", "kind": "local-cpu-simulator-mock",
        "nodes": 20, "rounds": 5, "expected_node_rounds": 100, "verified_node_rounds": 100,
        "live_llm": False, "gpu": False, "separate_process_per_node": False,
    }
    (OUTPUT / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt), flush=True)


if __name__ == "__main__":
    main()
