"""Offline integration: real HTTP/node/protocol; stand-in model, no CUDA or weights."""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlparse

from . import benchmark

FAKE_ANSWER = 17


class StandInModel:
    def sample(self, question, *, temperature, top_p, seed):
        if not question or seed is None:
            raise ValueError("Expected an actual question and per-node seed")
        return FAKE_ANSWER, f"#### {FAKE_ANSWER}"


def start_test_node(args):
    from sistema.node import app
    from sistema.node.dedicated_inference import DedicatedModel
    import uvicorn

    class DedicatedTestModel(DedicatedModel):
        def __init__(self, **kwargs):
            super().__init__(factory=StandInModel, **kwargs)

    app.DedicatedModel = DedicatedTestModel
    uvicorn.run(app.app, host=args.host, port=args.port, workers=1, access_log=False)


def capture_outcome(work, profile, scenario):
    corrupted = 0
    unique_seeds = set()
    malicious = scenario["malicious_nodes"]
    for i in range(profile["nodes"]):
        node = f"node-{i}"
        db_path = work / "node-models" / node / "inferencias.sqlite"
        with closing(sqlite3.connect(db_path)) as db:
            rows = db.execute(
                "SELECT g.round_index,g.seed,g.answer,r.answer,r.base_node "
                "FROM generations g JOIN responses r USING(round_index) ORDER BY g.round_index"
            ).fetchall()
        if len(rows) != profile["rounds"]:
            raise RuntimeError(f"Missing own generations for {node}")
        for round_index, seed, fresh, sent, base in rows:
            if seed in unique_seeds or json.loads(fresh) != FAKE_ANSWER:
                raise RuntimeError("Invalid raw stand-in generation")
            unique_seeds.add(seed)
            is_corrupted = i < malicious and round_index >= profile["protocol"]["honest_rounds"]
            sent = json.loads(sent)
            if is_corrupted:
                if base != "node-0" or abs(sent) < (abs(FAKE_ANSWER) + 1) * 1000:
                    raise RuntimeError("Missing strong shared perturbation")
                corrupted += 1
            elif sent != FAKE_ANSWER or base != node:
                raise RuntimeError("Unintended perturbation")
    summary = json.loads((work / "summary.json").read_text(encoding="utf8"))
    return {"scenario": scenario["id"], "rounds": summary["summary"]["rounds"],
            "nodes": profile["nodes"], "own_mock_generations": len(unique_seeds),
            "strong_corruptions": corrupted, "ledgers_valid": summary["config"]["ledgers_valid"]}


def test_end_to_end(output):
    worker = benchmark.worker
    spawned = []
    profile, scenarios = benchmark.load_profile()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    snapshot_placeholder = output / "no-model-files"
    snapshot_placeholder.mkdir()
    reports = []
    for scenario_id in ("baseline", "m80-alto"):
        scenario = scenarios[scenario_id]
        config, item = benchmark.scenario_args(profile, scenario, 0)
        work = output / scenario_id
        work.mkdir()
        deadline = time.monotonic() + 300

        def check():
            if time.monotonic() > deadline:
                raise TimeoutError(f"Local integration timed out: {scenario_id}")

        def replace_model_only(command, *args, **kwargs):
            if command[1:3] == ["-m", "uvicorn"]:
                port = command[command.index("--port") + 1]
                command = [command[0], "-B", "-m", __spec__.name, "test-node", "--port", port]
            proc = subprocess.Popen(command, *args, **kwargs)
            spawned.append(proc)
            return proc

        print("Testing", scenario_id, flush=True)
        with patch.object(worker, "subprocess", SimpleNamespace(
            Popen=replace_model_only, TimeoutExpired=subprocess.TimeoutExpired, STDOUT=subprocess.STDOUT
        )):
            worker.execute_scenario(work, item, config, snapshot_placeholder, ["mock0", "mock1"],
                                    check, lambda _state, **_tags: None)
        reports.append(capture_outcome(work, profile, scenario))
        if any(proc.poll() is None for proc in spawned):
            raise RuntimeError("Supervisor left a subprocess running")
        for i in range(profile["nodes"]):
            port = urlparse(worker.URLS[f"node-{i}"]).port
            with socket.socket() as client:
                client.settimeout(0.15)
                if client.connect_ex(("127.0.0.1", port)) == 0:
                    raise RuntimeError(f"Node port {port} left open")
        print(json.dumps(reports[-1]), flush=True)
    (output / "integration-report.json").write_text(json.dumps(reports, indent=2)+"\n", encoding="utf8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    node = sub.add_parser("test-node")
    node.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1"])
    node.add_argument("--port", type=int, required=True)
    smoke = sub.add_parser("run")
    smoke.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "test-node":
        start_test_node(args)
    else:
        test_end_to_end(args.output)


if __name__ == "__main__":
    main()
