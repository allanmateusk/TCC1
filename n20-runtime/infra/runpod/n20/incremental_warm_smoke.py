"""Two real localhost protocol waves using 20 persistent CPU-only model doubles."""
from __future__ import annotations

import argparse
from contextlib import closing
import csv
import ctypes
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
import uuid

from . import artifact_store, benchmark, campaign_profiles, incremental_same_host, warm_batch, watchdog
from .same_host_batch import HostPolicy


def free_mib():
    if sys.platform=="win32":
        class Memory(ctypes.Structure):
            _fields_=[("length",ctypes.c_ulong),("load",ctypes.c_ulong)]+[
                (k,ctypes.c_ulonglong) for k in ("total","available","page_total","page_free",
                                                "virtual_total","virtual_free","extra")]
        m=Memory()
        m.length=ctypes.sizeof(m)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
            raise OSError("Could not measure Windows memory")
        return m.available//1048576
    return next(int(line.split()[1])//1024 for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemAvailable:"))


def prove(scratch):
    start=time.time()
    if free_mib()<1550:
        raise MemoryError("Not enough free memory to safely start 41 lightweight subprocesses")
    scratch=scratch.resolve()
    if scratch.is_relative_to(benchmark.ROOT.parent.resolve()):
        raise ValueError("Use separate temporary space outside source")
    scratch.mkdir(exist_ok=False)
    (scratch/"CPU_ONLY_NOT_PRODUCTION.txt").write_text("No real model, Pod, ZIP or R2.\n",encoding="utf-8")
    worker_data=scratch/"worker"
    worker_data.mkdir()
    empty=worker_data/"no-model"
    empty.mkdir()
    fixture_store=scratch/"local-get-fixture"
    fixture_store.mkdir()
    p,rows=benchmark.load_profile("incremental-v1")
    plan=incremental_same_host.IncrementalPlan(uuid.uuid4().hex,"8"*40,campaign_profiles.digest(p),
                                              "tcc",start,start+420,200)
    policy=HostPolicy("offline-fixture-resource",90)
    ctrl=incremental_same_host.IncrementalSameHost(scratch/"controller.sqlite",plan,policy)
    pod=watchdog.Resource(policy.resource_id,plan.batch_id,"active")
    ctrl.arm(pod)
    low=free_mib()
    seen=[]
    order=[]
    resident_children=[]
    protocol_children=[]
    stats=[]
    def observe(resource):
        if resource!=pod.resource_id:
            raise AssertionError("wrong local fixture ID")
        return pod
    def beat():
        nonlocal low
        low=min(low,free_mib())
        if low<620:
            raise MemoryError(f"Offline RAM guard: {low} MiB free")
        now=time.time()
        return ctrl.beat(now,now,trusted=pod)
    def resident(command,*a,**kw):
        if command[2:]!=["-m","sistema.node.resident"]:
            raise AssertionError("unexpected resident command")
        interpreter=sys._base_executable if sys.platform=="win32" else sys.executable
        process=subprocess.Popen([interpreter,"-B","-c","from sistema.node.resident import serve; serve(test_model=True)"],
                                 *a,**kw)
        resident_children.append(process)
        return process
    def protocol(command,*a,**kw):
        if command[1:3]==["-m","uvicorn"] and kw["env"].get("CUDA_VISIBLE_DEVICES")!="":
            raise AssertionError("Protocol child must not see any GPU")
        kw["env"]={**kw["env"],"CUDA_VISIBLE_DEVICES":""}
        process=subprocess.Popen([command[0],"-B",*command[1:]],*a,**kw)
        protocol_children.append(process)
        return process
    def audit_output(out,entry,samples):
        sid=entry["checkpoint_capture"]["scenario_id"]
        seen.append(sid)
        stats.append(samples)
        traces=[json.loads(l) for l in (out/artifact_store.REPUTATION_TRACE).read_text("utf-8").splitlines()]
        alphas={e["alpha_used"] for rr in traces for es in rr["nodes"].values() for e in es if e["operation"]=="update"}
        if alphas!={.05,.95}:
            raise AssertionError("Unexpected EMA rates in committed events")
        with (out/"reputation_history.csv").open(encoding="utf-8",newline="") as f:
            initial=[r for r in csv.DictReader(f) if r["checkpoint"]=="0"]
        assert len(initial)==20 and all(float(r["reputation"])==.5 for r in initial)
        changed=0
        for i in range(20):
            n=f"node-{i}"
            path=out/"node-models"/n/"inferencias.sqlite"
            with closing(sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True)) as db:
                scoped=json.loads(db.execute("SELECT config FROM meta WHERE id=1").fetchone()[0])
                evidence=db.execute("SELECT g.round_index,g.seed,g.answer,r.answer,r.base_node "
                                    "FROM generations g JOIN responses r USING(round_index)").fetchall()
            assert scoped["run_id"]==out.name and scoped["node_id"]==n and len(evidence)==50
            for j,seed,raw,answer,base in evidence:
                assert json.loads(raw)==17 and base==n and samples[n]["by_run"][out.name][str(seed)]==1
                value=json.loads(answer)
                if i<rows[sid]["malicious_nodes"] and j+1>5 and (j+1)%10:
                    assert abs(abs(value-17)-3.4)<1e-8, (sid,i,j,value)
                    changed+=1
                else:
                    assert value==17, (sid,i,j,value)
        print("Local worker finalized",sid,out.name,"changed",changed,flush=True)
    def put(out,*,run_id,**kw):
        order.append(("put",run_id))
        data=(out/"offline-proof.json").read_bytes()
        assert kw["key"]==campaign_profiles.candidate_key(run_id)
        with (fixture_store/f"{run_id}.cpu.json").open("xb") as dest:
            dest.write(data)
            dest.flush()
            os.fsync(dest.fileno())
        if len(seen)==1:
            # Durable external bytes exist even though the Pod did not get ACK.
            raise TimeoutError("Local mock after writing bytes")
    def get(_out,*,run_id,**kw):
        order.append(("get",run_id))
        return (fixture_store/f"{run_id}.cpu.json").read_bytes()
    with patch.object(benchmark.worker,"subprocess",SimpleNamespace(Popen=protocol,
                      TimeoutExpired=subprocess.TimeoutExpired,STDOUT=subprocess.STDOUT)):
        result=warm_batch.run_incremental_candidate(ctrl,worker_data,empty,observe_exact=observe,
             pod_upload=put,verify_transfer=get,check_scheduler=beat,start_test_process=resident,
             max_cases=2,observe_fixture=audit_output)
    assert seen==list(rows)[:2] and len(result)==2
    ids=[c["run_id"] for c in result]
    assert ids[0]!=ids[1] and order==[(op,rid) for rid in ids for op in ("put","get")]
    assert result[0]["pids"]==result[1]["pids"] and len(set(result[0]["pids"]))==20
    assert all(x["verified_audit_rounds"]==[10,20,30,40,50] for x in result)
    assert all(len(s["by_run"])==2 and s["calls"]==100 and s["loads"]==1 for s in stats[-1].values())
    assert len(resident_children)==20 and len(protocol_children)==42 and all(c.poll() is not None for c in resident_children+protocol_children)
    for u in benchmark.worker.URLS.values():
        with socket.socket() as test:
            test.settimeout(.15)
            assert test.connect_ex(("127.0.0.1",int(u.rsplit(":",1)[1])))!=0
    assert not list(scratch.rglob("*.zip")) and not list(scratch.rglob("model-runtime.json"))
    report={"status":"passed_cpu_only_not_production","scenarios":seen,"run_ids":ids,"resident_pids":20,
            "load_count":20,"physical_samples_each":1000,"independent_mock_gets":2,"lost_first_put_ack_reconciled":True,
            "protocol_processes_exited":42,"resident_processes_exited":20,"remain_unexecuted":18,
            "verified_real_r2":False,"eligible_for_live_admission":False,"min_available_ram_mib":low,
            "seconds":round(time.time()-start,2)}
    artifact_store.write_atomic(scratch/"SYNTHETIC-WARM-REPORT.json",artifact_store.json_bytes(report))
    print(json.dumps(report),flush=True)


if __name__=="__main__":
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--output",type=Path,required=True)
    prove(cli.parse_args().output)
