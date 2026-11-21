"""Offline end-to-end warm worker, final archive validator and same-host controller."""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from types import SimpleNamespace as O
from unittest.mock import patch
import uuid

from . import artifact_store as a, benchmark, campaign, integration_smoke, warm_batch, watchdog
from .batch_sequence import BatchPlan
from .r2_verified_pilot import prepare as archive_prepare
from .same_host_batch import HostPolicy, SameHostBatch
from sistema.node.dedicated_inference import DedicatedModel
from sistema.scripts.resident_pool import ResidentPool
from sistema.scripts.runpod_worker import execute_scenario

GATES={"TCC_N20_RESIDENT_QUALIFIED":"true","TCC_LIVE_N20_APPROVED":"true",
       "TCC_N20_OFFICIAL_QUALIFIED":"true"}


class FakePod:
    def __init__(self, resource, owner):
        self.resource=resource
        self.owner=owner
        self.phase="active"
        self.stops=[]
    def inspect_exact(self, resource):
        assert resource==self.resource
        return watchdog.Resource(self.resource,self.owner,self.phase)
    def stop_exact(self, resource, *, expected_run_id):
        assert resource==self.resource and expected_run_id==self.owner
        self.stops.append((resource,expected_run_id))
        self.phase="stopped"


def controller(folder):
    folder.mkdir()
    now=time.time()
    plan=BatchPlan(uuid.uuid4().hex,"8"*40,"c"*64,"tcc",now,now+1000,420)
    policy=HostPolicy("offline-fake-pod",90)
    ctrl=SameHostBatch(folder/"controller.sqlite",plan,policy)
    pod=FakePod(policy.resource_id,plan.batch_id)
    ctrl.arm(pod.inspect_exact(pod.resource))
    def scheduler():
        t=time.time()
        return ctrl.beat(t,t,trusted=pod.inspect_exact(pod.resource))
    return ctrl,pod,scheduler


def receipt(grant, digest, size):
    rid=grant["run_id"]
    return dict(schema="tcc-n20-r2-receipt/v1",status="verified",run_kind="official",
                scenario_id=grant["scenario_id"],run_id=rid,key=f"tcc/prod/n20-{rid}.zip",
                bucket="tcc",sha256=digest,bytes=size,nodes=20,rounds=50,verified_own_generations=1000)


def cpu_launcher(args,*a,**kw):
    assert args[2:]==["-m","sistema.node.resident"]
    interpreter=sys._base_executable if sys.platform=="win32" else args[0]
    return subprocess.Popen([interpreter,"-B","-c","from sistema.node.resident import serve; serve(test_model=True)"],
                            *a,**kw)


def package_fixture(src, dest, manifest):
    """Only this ephemeral fixture emulates BF16 telemetry; never touch real R2."""
    dest.mkdir()
    for name in a.METRICS:
        if name not in (*a.RUNTIME,a.GENERATIONS):
            p=dest/name
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(a.read_file(src,name))
    fake_model=O(model=O(dtype="torch.bfloat16",generation_config=O(use_cache=True),
                       get_memory_footprint=lambda:6150197248))
    cuda=O(get_device_name=lambda _:"offline fixture only",**{k:lambda _:6400000000 for k in
        ("memory_allocated","memory_reserved","max_memory_allocated","max_memory_reserved")})
    for node in a.NODES:
        rel=Path("node-models")/node/"inferencias.sqlite"
        dst=dest/rel
        dst.parent.mkdir(parents=True)
        with closing(sqlite3.connect((src/rel).as_uri()+"?mode=ro",uri=True)) as old, \
             closing(sqlite3.connect(dst)) as new:
            scoped=json.loads(old.execute("SELECT config FROM meta WHERE id=1").fetchone()[0])
            assert scoped["run_id"]==manifest["run_id"] and scoped["node_id"]==node
            old.backup(new)
        scoped["model_name"]=scoped.pop("model")
        obj=DedicatedModel(**scoped,cache_dir=dst.parent,factory=lambda:fake_model)
        obj.ensure_loaded()
        with patch.dict(sys.modules,{"torch":O(cuda=cuda)}):
            obj._record_memory()
    try:
        a.finalize_run(dest,{**manifest,"model_is_stand_in":True})
    except ValueError as exc:
        if "verified, real" not in str(exc):
            raise
    else:
        raise AssertionError("Simulated run could pass real archive gate")
    eligible=a.finalize_run(dest,{**manifest,"model_is_stand_in":False})
    (dest/a.MANIFEST).write_bytes(a.json_bytes(eligible))
    return archive_prepare(dest,manifest["run_id"])


def negative(folder, parent, snapshot, *, mode):
    ctrl,pod,beat=controller(folder)
    outputs=parent/mode
    outputs.mkdir()
    calls=[]
    payload=b"mock test only"
    def run(_profile,scenario,_seed,_snapshot,*,durable_root,run_id,**kw):
        calls.append(run_id)
        work=durable_root/run_id
        work.mkdir()
        (work/"preserved.txt").write_bytes(payload)
    def pack(out,rid):
        return payload,f"tcc/prod/n20-{rid}.zip"
    def bad_transfer(_out,**expected):
        if mode=="missing_receipt":
            return None
        return {**receipt(expected,"f"*64,len(payload)),"bucket":expected["bucket"]}
    with patch.dict(os.environ,GATES), patch.object(benchmark,"live",side_effect=run), \
         patch.object(warm_batch.r2_verified_pilot,"prepare",side_effect=pack):
        try:
            warm_batch.run_qualified(ctrl,outputs,snapshot,observe_exact=pod.inspect_exact,
                verify_transfer=bad_transfer,check_scheduler=beat)
        except ValueError as exc:
            assert "invalid verified archive" in str(exc)
        else:
            raise AssertionError("Bad receipt did not prevent next case")
    assert len(calls)==1 and pod.stops==[]
    assert ctrl.reserve(time.time(),uuid.uuid4().hex,trusted=pod.inspect_exact(pod.resource))["status"]=="stop_required"
    stopped=ctrl.tick(time.time(),backend=pod,apply=True)
    assert stopped=={"status":"stopped","reason":"receipt_mismatch"} and len(pod.stops)==1
    assert (outputs/calls[0]/"preserved.txt").read_bytes()==payload
    return {"next_case_blocked":True,"fake_pod_stopped":True,"local_data_preserved":True,
            "worker_stub_only":True}


def prove(root):
    root=root.resolve()
    if root.is_relative_to(benchmark.ROOT.parent.resolve()):
        raise ValueError("Use external scratch directory")
    root.mkdir(exist_ok=False)
    worker_data=root/"worker-volume"
    worker_data.mkdir()
    fixture_vol=root/"local-finalizer-fixtures"
    fixture_vol.mkdir()
    objects=root/"fake-independent-store"
    objects.mkdir()
    snapshot=root/"mock-model-no-weights"
    snapshot.mkdir()
    ctrl,pod,beat=controller(root/"external-control-fixture")
    # First 15 entries are controller-only fixtures, not claimed as worker runs.
    for scenario in campaign.IDS[:-2]:
        grant=ctrl.reserve(time.time(),uuid.uuid4().hex,trusted=pod.inspect_exact(pod.resource))
        assert grant["scenario_id"]==scenario
        assert ctrl.seal(time.time(),grant["run_id"],sha256="c"*64,size=2)
        assert ctrl.finish(time.time(),grant["run_id"],trusted_receipt=receipt(grant,"c"*64,2),
                          trusted=pod.inspect_exact(pod.resource))["stop_required"] is False
    prepared={}
    active_pool=[]
    dynamic=[]
    states={}
    def make_pool(*args,**kw):
        pool=ResidentPool(*args,**kw,start_process=cpu_launcher)
        active_pool.append(pool)
        return pool

    def live(profile,scenario,seed,snap,*,durable_root,resource_id,run_id,resident_pool,warm_case,**_kw):
        cfg,entry=benchmark.scenario_args(profile,scenario,seed)
        end=warm_case.verify(resource_id=resource_id,run_id=run_id,entry=entry,scenario=scenario["id"])
        assert pod.phase=="active" and not pod.stops
        out=durable_root/run_id
        out.mkdir()
        entry["checkpoint_capture"]=dict(run_id=run_id,scenario_id=scenario["id"],git_sha="8"*40,
                                         tasks_sha256=profile["task_sha256"])
        execute_scenario(out,entry,cfg,snap,["CPU-fixture-0","CPU-fixture-1"],warm_case.check,
                         lambda *_a,**_kw:None,resident_pool=resident_pool,case_deadline=end)
        facts=integration_smoke.capture_outcome(out,profile,scenario,entry)
        assert facts["own_mock_generations"]==1000 and facts["ledgers_valid"]
        states[scenario["id"]]=resident_pool.stats()
        dynamic.append(dict(case=scenario["id"],uuid=run_id,facts=facts))
        manifest=dict(run_id=run_id,experiment_id=entry["id"],status="verified_local",completed=True,
            run_kind="official",scenario_id=scenario["id"],scenario=entry,nodes=20,rounds=50,seed=0,
            verified_own_generations=1000,dtype=profile["dtype"],quantization=profile["quantization"],
            model=profile["model"],model_revision=profile["model_revision"],git_sha="8"*40)
        prepared[run_id]=package_fixture(out,fixture_vol/run_id,manifest)

    def prepare(_out,rid):
        return prepared[rid]

    def verify_transfer(out,*,run_id,scenario_id,bucket,key,sha256,size,deadline):
        assert pod.phase=="active" and pod.stops==[] and time.time()<deadline
        assert ctrl.tick(time.time(),backend=pod,apply=True)["status"]=="watching"
        data, wanted=prepared[run_id]
        assert bucket=="tcc" and key==wanted
        mock_object=objects/f"{run_id}.zip"
        a.write_atomic(mock_object,data)
        # Detect corrupt read; keep the exact case reserved until independent GET succeeds.
        damaged=data[:-1]+bytes([data[-1]^1])
        assert a.sha(damaged)!=sha256
        assert ctrl.reserve(time.time(),uuid.uuid4().hex,trusted=pod.inspect_exact(pod.resource))["status"]=="blocked_active"
        downloaded=mock_object.read_bytes()
        assert len(downloaded)==size and a.sha(downloaded)==sha256
        metrics=a.verify_archive(downloaded,run_id)
        assert metrics["scenario_id"]==scenario_id and metrics["verified_own_generations"]==1000
        assert (out/"rounds.csv").is_file()
        return receipt(dict(run_id=run_id,scenario_id=scenario_id),sha256,size)

    with patch.dict(os.environ,GATES), patch.object(warm_batch,"ResidentPool",side_effect=make_pool), \
         patch.object(benchmark,"live",side_effect=live), patch.object(warm_batch.r2_verified_pilot,"prepare",side_effect=prepare):
        finished=warm_batch.run_qualified(ctrl,worker_data,snapshot,observe_exact=pod.inspect_exact,
                         verify_transfer=verify_transfer,check_scheduler=beat)
    assert [r["case"] for r in dynamic]==list(campaign.IDS[-2:])
    assert finished=={"status":"verified","scenario_id":"C13","stop_required":True} and pod.stops==[]
    stopped=ctrl.tick(time.time(),backend=pod,apply=True)
    assert stopped=={"status":"stopped","reason":"all_receipts_verified"} and len(pod.stops)==1
    first,second=(states[x] for x in campaign.IDS[-2:])
    assert len(first)==len(second)==20 and all(first[n]["pid"]==second[n]["pid"] and second[n]["loads"]==1
            and first[n]["calls"]==50 and second[n]["calls"]==100 and second[n]["mock"]
            and list(map(len,second[n]["by_run"].values()))==[50,50]
            and all(v==1 for r in second[n]["by_run"].values() for v in r.values()) for n in first)
    assert all(p.process.poll() is not None for p in active_pool[0].children.values())
    assert all((worker_data/r["uuid"]/"rounds.csv").is_file() and (objects/f"{r['uuid']}.zip").is_file() for r in dynamic)
    negative_checks={name:negative(root/f"control-{name}",root,snapshot,mode=name)
                     for name in ("missing_receipt","wrong_digest")}
    out={"status":"verified_offline_worker_controller","actual_worker_cases":dynamic,"first_15":"controller fixtures only",
         "resident_models":20,"loads_per_resident":1,"same_pids_across_cases":True,"stop_between":False,
         "fake_pod_stop_requests_at_end":len(pod.stops),"fake_pod_stop_confirmed":True,
         "corruption_blocked_advance_while_active":True,"negative_paths":negative_checks,
         "local_data_preserved":True,"real_model":False,"real_provider":False,"real_R2":False}
    a.write_atomic(root/"controller-proof.json",a.json_bytes(out))
    print(json.dumps(out,sort_keys=True),flush=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",required=True,type=Path)
    prove(p.parse_args().output)
