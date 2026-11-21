"""Exercise the real worker with 20 resident processes and CPU-only stand-in models."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid
from unittest.mock import patch

from . import artifact_store, benchmark, checkpoint, integration_smoke, watchdog
from sistema.node.resident import ResidentError, exchange
from sistema.scripts.resident_pool import ResidentPool
from sistema.scripts import runpod_worker as worker


def prove(root):
    root=root.resolve()
    if root.is_relative_to(benchmark.ROOT.parent.resolve()):
        raise ValueError("Scratch output must be outside source tree")
    root.mkdir(exist_ok=False)
    snapshot=root/"no-model-files"
    snapshot.mkdir()
    profile,scenarios=benchmark.load_profile()
    case_a=scenarios["pilot"]
    case_b={**case_a,"genesis_rounds":1}
    work_a=root/uuid.uuid4().hex
    work_b=root/uuid.uuid4().hex
    work_a.mkdir()
    work_b.mkdir()
    started=time.time()
    deadline=started+400
    def check():
        if time.time()>=deadline:
            raise TimeoutError("Bounded resident integration test elapsed")

    def spawn(command,*args,**kw):
        if command[2:]!=["-m","sistema.node.resident"]:
            raise AssertionError("Expected a dedicated subprocess command")
        # Windows venv launchers are proxy processes; this stdlib-only CPU test
        # starts the direct interpreter so Popen.pid matches the true resident.
        interpreter=sys._base_executable if sys.platform=="win32" else command[0]
        return subprocess.Popen([interpreter,"-B","-c","from sistema.node.resident import serve; serve(test_model=True)"],
                                *args,**kw)

    leases={}
    process_waves=[]
    def run(work,scenario,*,interrupt=False,digest=None):
        config,entry=benchmark.scenario_args(profile,scenario,0)
        entry["checkpoint_capture"]={"run_id":work.name,"scenario_id":"pilot",
                                     "git_sha":"8"*40,"tasks_sha256":profile["task_sha256"]}
        children=[]
        def capture(command,*args,**kw):
            if command[1:3]==["-m","uvicorn"]:
                actual=kw["env"]
                if work==work_b and not children:
                    revoked(work_a,"fresh")
                leases.setdefault((work.name,"resume" if digest else "fresh"),{})[actual["NODE_ID"]]={
                    k:actual[k] for k in ("N20_RESIDENT_PORT","N20_RESIDENT_TOKEN","N20_RESIDENT_EPOCH")}
                if actual["CUDA_VISIBLE_DEVICES"]!="":
                    raise AssertionError("Protocol processes have access to GPU slots")
            if interrupt and command[1:3]==["-m","sistema.orchestrator.run"]:
                command=[command[0],"-B","-m","infra.runpod.n20.integration_smoke",
                         "interrupt-coordinator","--before","2","--config",command[-1]]
            p=subprocess.Popen(command,*args,**kw)
            children.append(p)
            return p
        try:
            with patch.object(worker,"subprocess",SimpleNamespace(Popen=capture,TimeoutExpired=subprocess.TimeoutExpired,
                                                                   STDOUT=subprocess.STDOUT)):
                worker.execute_scenario(work,entry,config,snapshot,["mock0","mock1"],check,
                                       lambda *_args,**_kw:None,restart_digest=digest,
                                       resident_pool=pool,case_deadline=deadline)
        except RuntimeError:
            if not interrupt or b"TEST_CONTROLLED_CHECKPOINT_INTERRUPTION" not in (work/"orchestrator.log").read_bytes():
                raise
        else:
            if interrupt:
                raise AssertionError("Expected controlled cut")
        finally:
            if any(child.poll() is None for child in children):
                raise AssertionError("Nonresident processes were not cleaned")
        if len(children)!=21:
            raise AssertionError("Expected 20 protocol child processes and one coordinator")
        process_waves.append(children)
        identity=checkpoint.Identity(**worker.yaml.safe_load((work/"config.yaml").read_text("utf8"))["checkpoint_identity"])
        latest,digest=checkpoint.CheckpointStore(work,identity).recover()
        if latest["round_index"]!=(1 if interrupt else 4):
            raise AssertionError("Wrong committed checkpoint frontier")
        if not interrupt and scenario==case_a:
            outcome=integration_smoke.capture_outcome(work,profile,scenario,entry)
            if outcome["own_mock_generations"]!=100:
                raise AssertionError("Unexpected independent-generation ledger")
        return digest

    def revoked(work,phase):
        old=leases[work.name,phase]["node-0"]
        try:
            exchange(int(old["N20_RESIDENT_PORT"]),old["N20_RESIDENT_TOKEN"],
                     {"op":"health","node":"node-0","run":work.name,"epoch":old["N20_RESIDENT_EPOCH"]},timeout=3)
        except ResidentError:
            return True
        raise AssertionError("Expired lease still works")

    with ResidentPool(root,deadline=deadline,start_process=spawn) as pool:
        run(work_a,case_a)
        a=pool.stats()
        revoked(work_a,"fresh")
        # Try the same real worker entry without confirmation. No files/procs created.
        try:
            run(work_b,case_b)
        except ValueError as e:
            if "verified previous receipt" not in str(e):
                raise
        else:
            raise AssertionError("Second case bypassed the upload receipt barrier")
        if list(work_b.iterdir()):
            raise AssertionError("Disallowed second case wrote output")
        binding=watchdog.Binding(work_a.name,"fake-harness-resource","tcc",deadline,started,30)
        archive=b"offline fake verifier fixture only"
        digest=artifact_store.sha(archive)
        receipt={"schema":"tcc-n20-r2-receipt/v1","status":"verified","run_id":work_a.name,
                 "run_kind":"pilot","scenario_id":"pilot","bucket":"tcc","key":binding.key,"sha256":digest,
                 "bytes":len(archive),"nodes":20,"rounds":5,"verified_own_generations":100}
        try:
            pool.mark_verified(binding,{**receipt,"sha256":"0"*64},digest=digest,size=len(archive))
        except ValueError:
            pass
        else:
            raise AssertionError("Mismatched archive receipt released the barrier")
        pool.mark_verified(binding,receipt,digest=digest,size=len(archive))
        cut=run(work_b,case_b,interrupt=True)
        b_pre=pool.stats()
        revoked(work_b,"fresh")
        run(work_b,case_b,digest=cut)
        b=pool.stats()
        revoked(work_b,"resume")
        if any(a[n]["pid"]!=b[n]["pid"] or b[n]["loads"]!=1 or b[n]["mock"] is not True
               or a[n]["calls"]!=5 or b_pre[n]["calls"]!=8 or b[n]["calls"]!=10
               or len(b[n]["by_run"][work_a.name])!=5 or len(b[n]["by_run"][work_b.name])!=5
               or any(c!=1 for samples in b[n]["by_run"].values() for c in samples.values())
               or set(b[n]["by_run"][work_a.name])!=set(b[n]["by_run"][work_b.name])
               for n in b) or len(b)!=20:
            raise AssertionError("Physical calls/load/PIDs were not exactly run-scoped")
        ports=[c.port for c in pool.children.values()]
        processes=[c.process for c in pool.children.values()]
        if len({p.pid for p in processes})!=20:
            raise AssertionError("Dedicated resident process identity is not unique")
    if any(c.poll() is None for c in processes):
        raise AssertionError("Resident processes leaked")
    for port in ports:
        with socket.socket() as s:
            s.settimeout(.2)
            if s.connect_ex(("127.0.0.1",port))==0:
                raise AssertionError("Private resident port leaked")
    if len({id(proc) for wave in process_waves for proc in wave})!=63 or any(
            len({proc.pid for proc in wave})!=21 or any(proc.poll() is None for proc in wave)
            for wave in process_waves):
        raise AssertionError("Fresh protocol process handles or cleanup not verified")
    all_rows={}
    for name,work in [("a",work_a),("b",work_b)]:
        with (work/"reputation_history.csv").open(encoding="utf8",newline="") as f:
            initial=[r for r in csv.DictReader(f) if r["checkpoint"]=="0"]
        if len(initial)!=20 or any(float(row["reputation"])!=.5 for row in initial):
            raise AssertionError("Cross-run reputation leak")
        ledgers=[json.loads((work/f"ledgers/{n}.json").read_bytes()) for n in b]
        all_rows[name]={
            "kinds":[r["kind"] for r in ledgers[0]["records"]],
            "initial_reputation":.5,"verified_ledgers":len(ledgers),
            "unique_heads":sorted(set(x["records"][-1]["hash"] for x in ledgers))}
        if len(list((work/"node-models").glob("*/inferencias.sqlite")))!=20:
            raise AssertionError("Missing separate exact SQLite caches")
        if list((work/"node-models").glob("*/model-runtime.json")):
            raise AssertionError("Stand-in generated purported real BF16 evidence")
    if "calibration" in all_rows["a"]["kinds"] or all_rows["b"]["kinds"][0]!="calibration":
        raise AssertionError("Ledger, Gênese or audit state crossed run boundary")
    result={"status":"verified_cpu_worker_residency","real_gpu":False,"real_r2":False,"rounds_per_case":5,
            "resident_pids":sorted(x.pid for x in processes),"total_model_loads":20,"physical_calls_each_case":100,
            "physical_calls_before_b_restart":160,"physical_calls_after_b_restart":200,"replayed_round_new_calls":0,
            "retained_task_seed_keys_across_uuids":True,"fresh_protocol_processes":[len(x) for x in process_waves],
            "startup_reused_prior_ema":False,"separate_sqlite":True,"receipt_barrier_fixture_verified":True,
            "expired_leases_refused":True,"stopped_processes_and_ports":True,"protocol_evidence":all_rows}
    artifact_store.write_atomic(root/"resident-report.json",artifact_store.json_bytes(result))
    print(json.dumps(result,sort_keys=True),flush=True)


if __name__=="__main__":
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--output",required=True,type=Path)
    prove(cli.parse_args().output)
