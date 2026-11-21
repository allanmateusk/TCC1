
"""Offline proof: actually restart 20 HTTP stand-ins in the same UUID after round two."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from contextlib import contextmanager
import csv
import json
from pathlib import Path
import socket
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import patch

from . import artifact_store, benchmark, checkpoint, integration_smoke as fixture
from sistema.orchestrator import run as orchestrator


def bound_frontier(work, expected_id):
    cfg=orchestrator.load_config(str(work/"config.yaml"))
    i=checkpoint.Identity(**cfg["checkpoint_identity"])
    if i.run_id!=expected_id or i.scenario_id!="pilot" or i.rounds!=5:
        raise ValueError("Offline restart identity mismatch")
    core={k:v for k,v in cfg.items() if k!="checkpoint_identity"}
    if artifact_store.sha(artifact_store.json_bytes(core))!=i.config_sha256:
        raise ValueError("Offline restart effective configuration mismatch")
    marker,_=checkpoint.CheckpointStore(work,i).recover()
    if marker is None or marker["round_index"]!=1:
        raise ValueError("Offline restart fixture requires the exact round-two marker")
    checkpoint.verify_log_prefixes(work,marker)
    return cfg, marker


def quarantine_prefix(work, marker):
    """Leave the original attempt and all committed histories inspectable."""
    archive=work/"interrupted-attempt"
    archive.mkdir(exist_ok=False)
    sources=(*sorted(checkpoint.LOGS),"config.yaml","orchestrator.log",
             *(f"{n}.log" for n in sorted(checkpoint.NODES)))
    hashes={}
    for name in sources:
        data=artifact_store.read_file(work,name)
        artifact_store.write_atomic(archive/name,data)
        hashes[name]=artifact_store.sha(data)
    artifact_store.write_atomic(archive/"archive-proof.json",artifact_store.json_bytes(hashes))
    for name in sorted(checkpoint.LOGS):
        old=(archive/name).read_bytes()
        size=marker["log_prefixes"][name]["bytes"]
        artifact_store.write_atomic(work/name,old[:size],replace=True)
    checkpoint.verify_log_prefixes(work,marker)
    return archive


def _ports_are_clear():
    for i in range(20):
        with socket.socket() as s:
            s.settimeout(.2)
            if s.connect_ex(("127.0.0.1",18100+i))==0:
                raise RuntimeError("An old or unrelated local runner still owns a fixture port")


@contextmanager
def _claim(work):
    path=work/"offline-resume.claim"
    with path.open("x",encoding="utf-8") as f:
        f.write("Local-only one-shot test; do not start the same fixture twice.\n")
    yield


def _calls(work, run_id):
    rows=[]
    for node in sorted(checkpoint.NODES):
        path=work/"node-models"/node/"stand-in-calls.jsonl"
        for line in path.read_text(encoding="utf-8").splitlines():
            r=json.loads(line)
            if r["run_id"]!=run_id or r["node"]!=node:
                raise RuntimeError("Mock generation invocation belongs to another run")
            rows.append(r)
    return rows


def _normalize_csv(root,name):
    # The flood visits peers concurrently; its observed traversal depth is
    # schedule-dependent like timings, not a reputation or quorum decision.
    remove={"per_node.csv":{"latency_ms"},"rounds.csv":{"mean_latency_ms"},
            "leadership.csv":{"hops"}}.get(name,set())
    with (root/name).open(encoding="utf-8",newline="") as h:
        return [{k:v for k,v in row.items() if k not in remove} for row in csv.DictReader(h)]


def restored_coordinator(args):
    work=Path(args.config).resolve().parent
    config,marker=bound_frontier(work,args.run_id)
    asyncio.run(orchestrator.run_dynamic_experiment(config,offline_test_resume=marker))


def main_proof(root):
    root=root.resolve()
    if root.is_relative_to(benchmark.ROOT.parent.resolve()):
        raise ValueError("Offline proof output must be outside the Git worktree")
    root.mkdir(exist_ok=False)
    _ports_are_clear()
    fixture.test_end_to_end(root/"reference",capture_checkpoints=True)
    _ports_are_clear()
    fixture.test_end_to_end(root/"cut",capture_checkpoints=True,fail_before=2)
    def get_run(kind):
        parent=root/kind
        rid=json.loads((parent/"integration-report.json").read_text(encoding="utf-8"))[0]["checkpoint_run_id"]
        return parent/rid,rid
    ref,ref_id=get_run("reference")
    work,rid=get_run("cut")
    with _claim(work):
        try:
            bound_frontier(work,"0"*32)
        except ValueError:
            pass
        else:
            raise AssertionError("Wrong UUID did not fail closed")
        try:
            with _claim(work):
                pass
        except FileExistsError:
            pass
        else:
            raise AssertionError("Concurrent or repeated restart was accepted")
        _,marker=bound_frontier(work,rid)
        observed=_calls(work,rid)
        counts=Counter((r["phase"],r["round"]) for r in observed)
        if counts!={("initial",1):20,("initial",2):20,("initial",3):20}:
            raise RuntimeError("Unexpected number of real stand-in invocations before the cut")
        archived=quarantine_prefix(work,marker)
        _ports_are_clear()
        profile,cases=benchmark.load_profile()
        config,item=benchmark.scenario_args(profile,cases["pilot"],0)
        item["checkpoint_capture"]={"run_id":rid,"git_sha":"8"*40,"tasks_sha256":profile["task_sha256"]}
        worker=benchmark.worker
        children=[]
        deadline=time.monotonic()+150
        def check():
            if time.monotonic()>deadline:
                raise TimeoutError("Timed out starting restored mock nodes")
        def replace(command,*a,**k):
            if command[1:3]==["-m","uvicorn"]:
                port=command[command.index("--port")+1]
                command=[command[0],"-B","-m",fixture.__spec__.name,"test-node","--port",port,"--restore"]
            elif command[1:3]==["-m","sistema.orchestrator.run"]:
                command=[command[0],"-B","-m","infra.runpod.n20.resume_smoke","coordinator",
                         "--run-id",rid,"--config",command[-1]]
            p=subprocess.Popen(command,*a,**k)
            children.append(p)
            return p
        with patch.object(worker,"subprocess",SimpleNamespace(Popen=replace,TimeoutExpired=subprocess.TimeoutExpired,
                                                               STDOUT=subprocess.STDOUT)):
            worker.execute_scenario(work,item,config,root/"cut"/"no-model-files",["mock0","mock1"],
                                    check,lambda *_args,**_opts:None)
        if len(children)!=21 or any(p.poll() is None for p in children):
            raise RuntimeError("Restart did not execute and clean up 20 new mock nodes and one coordinator")
        _ports_are_clear()
        outcome=fixture.capture_outcome(work,profile,cases["pilot"],item)
        after=_calls(work,rid)
        reference=_calls(ref,ref_id)
        target={("initial",1):20,("initial",2):20,("initial",3):20,("resume",4):20,("resume",5):20}
        if (Counter((r["phase"],r["round"]) for r in after)!=target or len(reference)!=100
            or len({(r["round"],r["node"]) for r in after})!=100):
            raise RuntimeError("Duplicate or missing physical model invocation")
        if {(r["round"],r["node"],r["seed"]) for r in after}!={(r["round"],r["node"],r["seed"]) for r in reference}:
            raise RuntimeError("Reference task assignments differ")
        for name in checkpoint.LOGS:
            if name.endswith(".csv"):
                match=_normalize_csv(work,name)==_normalize_csv(ref,name)
            else:
                match=(work/name).read_bytes()==(ref/name).read_bytes()
            if not match:
                raise RuntimeError("Restart differs semantically from reference: "+name)
        def summary(p):
            summ=json.loads((p/"summary.json").read_bytes())["summary"]
            summ.pop("mean_latency_ms",None)
            summ["dynamic"].pop("mean_hops",None)
            summ["dynamic"].pop("max_hops",None)
            return summ
        if summary(work)!=summary(ref):
            raise RuntimeError("Resumed analytical summary differs from baseline")
        for n in checkpoint.NODES:
            name=f"ledgers/{n}.json"
            if json.loads((work/name).read_bytes())!=json.loads((ref/name).read_bytes()):
                raise RuntimeError("Ledger diverged from clean reference")
        final_cfg=orchestrator.load_config(str(work/"config.yaml"))
        final,_=checkpoint.CheckpointStore(work,checkpoint.Identity(**final_cfg["checkpoint_identity"])).recover()
        ref_cfg=orchestrator.load_config(str(ref/"config.yaml"))
        clean,_=checkpoint.CheckpointStore(ref,checkpoint.Identity(**ref_cfg["checkpoint_identity"])).recover()
        if final["round_index"]!=4 or final["replicas"]!=clean["replicas"] or (
            final["groups"],final["next_gid"])!=(clean["groups"],clean["next_gid"]):
            raise RuntimeError("Final restored states or coordinator layout differs")
        q=json.loads((archived/"archive-proof.json").read_bytes())
        if any(artifact_store.sha((archived/name).read_bytes())!=sha for name,sha in q.items()):
            raise RuntimeError("Quarantined attempt changed")
        result={"status":"verified_offline_restart","model_is_stand_in":True,"same_uuid":rid,
                "cut_after_model_calls":len(observed),"new_calls_round_three":0,"new_calls_rounds_four_five":40,
                "physical_calls_restarted":len(after),"physical_calls_reference":len(reference),
                "matching_ledger_and_replica_heads":20,"matching_semantic_logs":len(checkpoint.LOGS),
                "matching_analytical_summary":True,
                "excluded_nondeterministic_metrics":["latency_ms","mean_latency_ms","hops","mean_hops","max_hops"],
                "rounds":outcome["rounds"],"wrong_identity_and_repeat_rejected":True}
        artifact_store.write_atomic(root/"restart-report.json",artifact_store.json_bytes(result))
        print(json.dumps(result),flush=True)


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    sub=cli.add_subparsers(dest="mode",required=True)
    proof=sub.add_parser("run")
    proof.add_argument("--output",type=Path,required=True)
    coordinator=sub.add_parser("coordinator",help=argparse.SUPPRESS)
    coordinator.add_argument("--config",required=True)
    coordinator.add_argument("--run-id",required=True)
    args=cli.parse_args()
    if args.mode=="coordinator":
        restored_coordinator(args)
    else:
        main_proof(args.output)


if __name__=="__main__":
    main()
