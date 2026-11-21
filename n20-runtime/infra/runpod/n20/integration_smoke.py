"""Offline integration: real HTTP/node/protocol; stand-in model, no CUDA or weights."""
from __future__ import annotations

import argparse
import csv
import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlparse

from . import artifact_store, benchmark

FAKE_ANSWER = 17


class StandInModel:
    def __init__(self, *, phase="initial"):
        self.phase=phase

    def sample(self, question, *, temperature, top_p, seed):
        if not question or seed is None:
            raise ValueError("Expected an actual question and per-node seed")
        run_id=os.getenv("N20_CHECKPOINT_RUN_ID")
        if run_id:
            node=os.environ["NODE_ID"]
            candidates=[r for r in range(5) if seed==int.from_bytes(
                hashlib.sha256(f"0:{r}:{node}".encode()).digest()[:8],"big")&((1<<63)-1)]
            if len(candidates)!=1:
                raise ValueError("Unexpected stand-in round seed")
            path=Path(os.environ["MODEL_CACHE_DIR"])/"stand-in-calls.jsonl"
            with path.open("a",encoding="utf-8") as stream:
                stream.write(json.dumps({"run_id":run_id,"phase":self.phase,"node":node,
                                         "round":candidates[0]+1,"seed":seed,"pid":os.getpid()})+"\n")
                stream.flush()
                os.fsync(stream.fileno())
        return FAKE_ANSWER, f"#### {FAKE_ANSWER}"


def start_test_node(args):
    from sistema.node import app
    from sistema.node.dedicated_inference import DedicatedModel
    import uvicorn

    class DedicatedTestModel(DedicatedModel):
        def __init__(self, **kwargs):
            super().__init__(factory=lambda:StandInModel(phase="resume" if getattr(args,"restore",False) else "initial"),
                             **kwargs)
    if getattr(args,"restore",False):
        from .resume_smoke import bound_frontier
        from .checkpoint import replay_replica
        work=Path(os.environ["MODEL_CACHE_DIR"]).resolve().parents[1]
        _, marker = bound_frontier(work,os.environ["N20_CHECKPOINT_RUN_ID"])
        app._replica=replay_replica(marker["replicas"][app.NODE_ID],marker["round_index"],app._protocol,app._graph)

    app.DedicatedModel = DedicatedTestModel
    uvicorn.run(app.app, host=args.host, port=args.port, workers=1, access_log=False)


def capture_outcome(work, profile, scenario, entry):
    corrupted = 0
    simulated_absent = 0
    plan = entry["audit_plan"]
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
        if len(rows) != entry["rounds"]:
            raise RuntimeError(f"Missing own generations for {node}")
        for round_index, seed, fresh, sent, base in rows:
            if seed in unique_seeds or json.loads(fresh) != FAKE_ANSWER:
                raise RuntimeError("Invalid raw stand-in generation")
            unique_seeds.add(seed)
            is_corrupted = i < malicious and round_index >= profile["protocol"]["honest_rounds"]
            sent = json.loads(sent)
            if node in plan["simulated_absences"].get(round_index+1, ()):
                if sent is not None:
                    raise RuntimeError("Planned absence was not applied after generation")
                simulated_absent += 1
            elif is_corrupted:
                if base != "node-0" or abs(sent) < (abs(FAKE_ANSWER) + 1) * 1000:
                    raise RuntimeError("Missing strong shared perturbation")
                corrupted += 1
            elif sent != FAKE_ANSWER or base != node:
                raise RuntimeError("Unintended perturbation")
    summary = json.loads((work / "summary.json").read_text(encoding="utf8"))
    events = [json.loads(line) for line in (work / "audit-events.jsonl").read_text("utf8").splitlines()]
    if len(events) != entry["rounds"] or not all(r["complete"] for r in events):
        raise RuntimeError("Incomplete campaign audit telemetry")
    if [r["round"] for r in events if r["planned"]] != plan["planned_rounds"]:
        raise RuntimeError("Audits in telemetry differ from the plan")
    genesis = [r["round"] for r in events if r["genesis"]]
    if genesis != plan["genesis_rounds"]:
        raise RuntimeError("Genesis rounds differ from the plan")
    if any(set(r["oracle_by_node"].values()) != {"applied"} or len(r["oracle_by_node"]) != profile["nodes"]
           for r in events if r["planned"] or r["genesis"]):
        raise RuntimeError("Ground truth was not applied on every node")
    if genesis:
        with (work / "leadership.csv").open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                if int(row["round_index"])+1 in genesis and (row["outcome"] != "calibration" or row["leader"] or row["auditor"]):
                    raise RuntimeError("Genesis has unexpected leadership/quorum")
        for ledger in (work / "ledgers").glob("*.json"):
            records = json.loads(ledger.read_text("utf8"))["records"]
            if [r["round_index"]+1 for r in records if r["kind"]=="calibration"] != genesis:
                raise RuntimeError("Genesis not committed in every ledger")
    trace = [json.loads(line) for line in (work / artifact_store.REPUTATION_TRACE).read_text("utf8").splitlines()]
    if len(trace)!=entry["rounds"] or [r["round_index"] for r in trace]!=list(range(entry["rounds"])):
        raise RuntimeError("Reputation trace did not cover every round")
    if not any(e["alpha_used"] == .05 for r in trace for updates in r["nodes"].values() for e in updates):
        raise RuntimeError("No authoritative ordinary EMA updates in the HTTP smoke")
    for index,round_trace in enumerate(trace):
        for node,updates in round_trace["nodes"].items():
            if node in plan["simulated_absences"].get(index+1,()) and any(
                e["kind"] in {"round","calibration","oracle"} and e["operation"]=="update" for e in updates):
                raise RuntimeError("Intentional omission was treated as a distance-scoring update")
    # Exercise the real post-shutdown generation-evidence path using this
    # stand-in database. It deliberately does not create a publishable manifest.
    artifact_store._seal_generation_evidence(work, {
        "scenario_id": scenario["id"], "run_kind": entry["run_kind"], "rounds": entry["rounds"],
        "scenario": entry, "experiment_id": entry["id"],
    })
    with (work / artifact_store.GENERATIONS).open("r",encoding="utf-8",newline="") as handle:
        evidence = list(csv.DictReader(handle))
    if (len(evidence) != entry["expected_own_generations"]
        or {int(row["seed"]) for row in evidence} != unique_seeds
        or sum(int(row["intentional_absence"]) for row in evidence) != simulated_absent
        or any(row["intentional_absence"]=="1" and row["submitted"]!="0" for row in evidence)):
        raise RuntimeError("Finalized-generation evidence diverged from the stand-in protocol")
    return {"scenario": scenario["id"], "rounds": summary["summary"]["rounds"],
            "generation_proof_rows": len(evidence),
            "nodes": profile["nodes"], "own_mock_generations": len(unique_seeds),
            "run_kind": entry["run_kind"], "expected_own_generations": entry["expected_own_generations"],
            "model_is_stand_in": True, "configured_dtype": profile["dtype"],
            "strong_corruptions": corrupted, "simulated_absences": simulated_absent,
            "genesis": genesis, "planned_audits": plan["planned_rounds"], "ledgers_valid": summary["config"]["ledgers_valid"]}


def test_end_to_end(output, pilot_rounds=None, scenario_filter=None, capture_checkpoints=False, fail_before=None):
    from . import checkpoint
    worker = benchmark.worker
    if capture_checkpoints:
        if scenario_filter not in (None,"pilot") or pilot_rounds not in (None,5):
            raise ValueError("Checkpoint HTTP smoke is restricted to the stand-in pilot")
        scenario_filter = "pilot"
    elif fail_before is not None:
        raise ValueError("Simulated interruption requires checkpoint capture")
    spawned = []
    profile, scenarios = benchmark.load_profile()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    snapshot_placeholder = output / "no-model-files"
    snapshot_placeholder.mkdir()
    reports = []
    for scenario_id in ((scenario_filter,) if scenario_filter else (("pilot",) if pilot_rounds else ("pilot", "C13"))):
        scenario = scenarios[scenario_id]
        config, item = benchmark.scenario_args(profile, scenario, 0, pilot_rounds)
        work = output / scenario_id
        if capture_checkpoints:
            rid=uuid.uuid4().hex
            work=output/rid
            item["checkpoint_capture"]={"run_id":rid,"git_sha":"8"*40,"tasks_sha256":profile["task_sha256"]}
        work.mkdir()
        deadline = time.monotonic() + 300

        def check():
            if time.monotonic() > deadline:
                raise TimeoutError(f"Local integration timed out: {scenario_id}")

        def replace_model_only(command, *args, **kwargs):
            if command[1:3] == ["-m", "uvicorn"]:
                port = command[command.index("--port") + 1]
                command = [command[0], "-B", "-m", __spec__.name, "test-node", "--port", port]
            elif command[1:3] == ["-m", "sistema.orchestrator.run"] and fail_before is not None:
                command = [command[0], "-B", "-m", __spec__.name, "interrupt-coordinator",
                           "--before", str(fail_before), "--config", command[-1]]
            proc = subprocess.Popen(command, *args, **kwargs)
            spawned.append(proc)
            return proc

        print("Testing", scenario_id, flush=True)
        with patch.object(worker, "subprocess", SimpleNamespace(
            Popen=replace_model_only, TimeoutExpired=subprocess.TimeoutExpired, STDOUT=subprocess.STDOUT
        )):
            try:
                worker.execute_scenario(work, item, config, snapshot_placeholder, ["mock0", "mock1"],
                                        check, lambda _state, **_tags: None)
                if fail_before is not None:
                    raise AssertionError("Expected the injected coordinator interruption")
            except RuntimeError:
                if fail_before is None or b"TEST_CONTROLLED_CHECKPOINT_INTERRUPTION" not in (
                    work/"orchestrator.log").read_bytes():
                    raise
        report = capture_outcome(work, profile, scenario, item) if fail_before is None else {
            "scenario":scenario_id,"model_is_stand_in":True,"interrupted_before_checkpoint":fail_before+1}
        if capture_checkpoints:
            from sistema.orchestrator.run import _protocol_config, load_config
            from sistema.core.topology import build_graph
            raw=load_config(str(work/"config.yaml"))
            identity=checkpoint.Identity(**raw["checkpoint_identity"])
            last,_=checkpoint.CheckpointStore(work,identity).recover()
            expected = item["rounds"]-1 if fail_before is None else fail_before-1
            if last["round_index"]!=expected:
                raise RuntimeError("Checkpoint marker did not match the durable boundary")
            checkpoint.verify_log_prefixes(work,last)
            protocol=_protocol_config(raw)
            graph=build_graph(checkpoint.NODES,raw["topology"],degree=raw["degree"],seed=raw["seed"])
            for row in last["replicas"].values():
                checkpoint.replay_replica(row,expected,protocol,graph)
            report.update(checkpoint_run_id=identity.run_id,checkpoint_completed_rounds=expected+1,
                          verified_replica_replays=len(last["replicas"]))
            if fail_before is not None:
                with (work/"rounds.csv").open(encoding="utf-8",newline="") as h:
                    if len(list(csv.DictReader(h))) != fail_before+1:
                        raise RuntimeError("Controlled interruption did not leave the expected uncommitted suffix")
                for node in checkpoint.NODES:
                    with closing(sqlite3.connect((work/"node-models"/node/"inferencias.sqlite").resolve().as_uri()+"?mode=ro",uri=True)) as db:
                        if db.execute("SELECT MAX(round_index) FROM generations").fetchone()[0] != fail_before:
                            raise RuntimeError("Missing preserved next-round stand-in sample")
                report["speculative_generations_preserved"]=20
        reports.append(report)
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


def interrupted_coordinator(args):
    from .checkpoint import CheckpointStore
    from sistema.orchestrator import run
    saved=CheckpointStore.publish
    def stop_between_logs_and_marker(store, round_index, **kwargs):
        if round_index==args.before:
            raise RuntimeError("TEST_CONTROLLED_CHECKPOINT_INTERRUPTION")
        return saved(store,round_index,**kwargs)
    with patch.object(CheckpointStore,"publish",stop_between_logs_and_marker):
        sys.argv=["test-coordinator","--config",args.config]
        run.main()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    node = sub.add_parser("test-node")
    node.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1"])
    node.add_argument("--port", type=int, required=True)
    node.add_argument("--restore", action="store_true", help=argparse.SUPPRESS)
    smoke = sub.add_parser("run")
    smoke.add_argument("--output", type=Path, required=True)
    smoke.add_argument("--rounds", type=int, choices=(5,), help="Run only the five-round baseline pilot.")
    smoke.add_argument("--scenario", choices=("pilot", "C11", "C13", "C05"), help="Test one configured path.")
    smoke.add_argument("--checkpoint", action="store_true")
    smoke.add_argument("--interrupt-before-checkpoint", type=int, choices=(1,2,3,4))
    cut=sub.add_parser("interrupt-coordinator", help=argparse.SUPPRESS)
    cut.add_argument("--config",required=True)
    cut.add_argument("--before",type=int,required=True)
    args = parser.parse_args()
    if args.mode == "test-node":
        start_test_node(args)
    elif args.mode=="interrupt-coordinator":
        interrupted_coordinator(args)
    else:
        test_end_to_end(args.output,args.rounds,args.scenario,args.checkpoint,args.interrupt_before_checkpoint)


if __name__ == "__main__":
    main()
