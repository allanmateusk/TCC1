"""Credential-free localhost warm/journal integration, never live-admissible."""
from __future__ import annotations

import argparse
from base64 import b64encode
from pathlib import Path
import json
import os
import shutil
import socket
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import patch
import uuid

from . import artifact_store as store
from . import incremental_warm_smoke as smoke, warm_batch
from .incremental_batch_protection import BatchProtection
from .incremental_campaign import IDS
from .incremental_warm_journal import Authorities, GET, Journal, LEASE, Scope, _key_der

ORIGINAL=warm_batch.run_incremental_candidate
PAST=1767323045
MARKER="tcc-local-synthetic-warm-bundle/v1"
FILES=("offline-proof.json","audit-events.jsonl","summary.json","rounds.csv")
class DeniedReadback(ValueError):
    pass


class FixtureBridge:
    def __init__(self,root,mode):
        self.root,self.mode=root,mode
        self.started=time.monotonic()
        self.protocol=[]
        self.residents=[]
        self.ordered=[]
        self.readback=None
        self.bundle=None
        self.path=root/"signed-controller-fixture"
        self.external=root/"independent-object-readback-fixture"
        exe=shutil.which("openssl")
        if not exe and os.name=="nt":
            exe=r"C:\Program Files\Git\mingw64\bin\openssl.exe"
        if not exe or not Path(exe).is_file():
            raise ValueError("Existing trusted OpenSSL binary required (no installs)")
        self.openssl=Path(exe).resolve(strict=True)

    def clock(self):
        return PAST+int(time.monotonic()-self.started)

    def _open(self,*args):
        return subprocess.run([str(self.openssl),*args],capture_output=True,check=True,timeout=5).stdout

    def _prepare(self,ctrl):
        self.path.mkdir()
        self.external.mkdir()
        keys={}
        for role in ("lease","get"):
            f=self.path/(role+".ephemeral-fixture-key")
            self._open("genpkey","-algorithm","ED25519","-out",str(f))
            keys[role]=self._open("pkey","-in",str(f),"-pubout")
        batch=ctrl.plan.batch_id
        p=BatchProtection(batch,ctrl.policy.resource_id,"offline-fixture-owner","OFFLINE-1",
            "tcc-n20-batch-"+batch,ctrl.plan.git_sha,ctrl.plan.profile_sha256,PAST,
            PAST+17700,PAST+18000,300,90,2_000_000,0,12_000_000)
        self.scope=Scope(p,str(uuid.UUID(hex=batch)),str(uuid.uuid4()),str(uuid.uuid4()),
                         *[store.sha(_key_der(keys[r])) for r in ("lease","get")])
        self.ctrl=Journal(self.path/"independent-fixture.sqlite",
            Authorities(self.scope,keys["lease"],keys["get"],self.openssl),clock=self.clock)

    def _sign(self,ev,role):
        f=self.path/"pending-historical-test-statement.json"
        f.write_bytes(store.json_bytes(ev))
        sig=self._open("pkeyutl","-sign","-inkey",str(self.path/(role+".ephemeral-fixture-key")),
                      "-rawin","-in",str(f))
        return {"evidence":ev,"signature_ed25519_base64":b64encode(sig).decode("ascii")}

    def _base(self,kind,index,rid):
        now=self.clock()
        return dict(schema=kind,scope_sha256=self.scope.digest,index=index,scenario_id=IDS[index],
                    run_id=rid,observed_at=now,expires_at=now+30)

    def _lease(self,index,rid,prior):
        return self._sign({**self._base(LEASE,index,rid),"prior_readback_sha256":prior,
            "case_deadline":self.clock()+280,"guard_observation_sha256":"9"*64},"lease")

    def _observed_get(self,rid,body,facts):
        return self._sign({**self._base(GET,0,rid),"method":"GET","bucket":"tcc",
            "key":f"tcc/prod/incremental-v1/n20-{rid}.zip","sha256":store.sha(body),"size":len(body),
            "verified_own_generations":facts["verified_own_generations"],"verified_ledgers":facts["verified_ledgers"],
            "rounds":facts["rounds"],"nodes":facts["nodes"],"archive_verified":True,"independent_get":True},"get")

    def run(self,controller,durable_root,snapshot,**kwargs):
        self._prepare(controller)
        reserve=controller.reserve
        put,get=kwargs["pod_upload"],kwargs["verify_transfer"]
        spawn=kwargs["start_test_process"]
        shell=smoke.benchmark.worker.subprocess

        def resident(*a,**kw):
            proc=spawn(*a,**kw)
            self.residents.append(proc)
            return proc

        def protocol(*a,**kw):
            proc=shell.Popen(*a,**kw)
            self.protocol.append(proc)
            return proc

        def signed_reserve(now,rid,*,trusted):
            if trusted.resource_id!=self.scope.allocation.resource_id or trusted.owner_run_id!=self.scope.allocation.batch_id:
                raise ValueError("Fixture Pod or batch changed")
            index=len(self.ordered)
            if index==0:
                self.ctrl.first(self._lease(0,rid,None))
            elif index==1:
                if self.readback is None:
                    raise DeniedReadback("No independently verified fixture GET")
                prior=store.sha(store.json_bytes(self.readback["evidence"]))
                self.ctrl.transition(self.readback,self._lease(1,rid,prior))
                assert len(self.protocol)==21, "second case started before signed journal transition"
            else:
                raise AssertionError("Never execute more than two local fixture cases")
            reply=reserve(now,rid,trusted=trusted)
            assert reply["status"]=="reserved" and reply["scenario_id"]==IDS[index]
            self.ordered.append(rid)
            return reply

        def seal_and_put(out,*,run_id,**kw):
            if len(self.ordered)==1:
                # Bundle is canonical JSON for this proof only, not an R2-eligible ZIP.
                source={name:store.read_file(out,name).decode("utf-8") for name in FILES}
                body=store.json_bytes({"schema":MARKER,"test_only":True,"files":source,
                                       "run_id":run_id,"scope_sha256":self.scope.digest})
                self.bundle=(store.sha(body),len(body))
                self.ctrl.seal_active(run_id,sha256=self.bundle[0],size=self.bundle[1])
                with (self.external/"case-1.synthetic.json").open("xb") as f:
                    f.write(body)
                    f.flush()
                    os.fsync(f.fileno())
            return put(out,run_id=run_id,**kw)

        def independent_get(out,*,run_id,**kw):
            base=get(out,run_id=run_id,**kw)
            if len(self.ordered)==1:
                local=self.external/"case-1.synthetic.json"
                downloaded=local.read_bytes() if self.mode!="missing" else None
                if downloaded is not None and self.mode=="corrupt":
                    downloaded=downloaded[:-1]+b"!"
                if downloaded is None or (store.sha(downloaded),len(downloaded))!=self.bundle:
                    before=self.ctrl.status()
                    with_no_receipt=self._lease(1,uuid.uuid4().hex,"0"*64)
                    try:
                        self.ctrl.transition(None,with_no_receipt)
                    except ValueError:
                        pass
                    else:
                        raise AssertionError("Signed journal advanced without verified GET bytes")
                    assert self.ctrl.status()==before
                    raise DeniedReadback("Missing or corrupt independent fixture readback")
                body=json.loads(downloaded)
                if (body["schema"],body["test_only"],body["run_id"],body["scope_sha256"],set(body["files"])) != (
                     MARKER,True,run_id,self.scope.digest,set(FILES)):
                    raise DeniedReadback("Wrong synthetic bundle binding")
                if body["files"]["offline-proof.json"].encode("utf-8")!=base:
                    raise DeniedReadback("Independent downloads disagree")
                f=json.loads(body["files"]["offline-proof.json"])
                audit=[json.loads(l) for l in body["files"]["audit-events.jsonl"].splitlines()]
                if (f["model_is_stand_in"],f["run_id"],f["scenario_id"],f["verified_own_generations"],
                    f["verified_ledgers"],f["nodes"],f["rounds"],[e["round"] for e in audit if e["planned"]]) != (
                    True,run_id,IDS[0],1000,20,20,50,[10,20,30,40,50]) or len(audit)!=50 or any(
                    not e["complete"] or e["generation_barrier_nodes"]!=20 for e in audit):
                    raise DeniedReadback("Incomplete or unrecognized synthetic metrics")
                self.readback=self._observed_get(run_id,downloaded,f)
            return base

        with patch.object(controller,"reserve",signed_reserve), patch.object(smoke.benchmark.worker,"subprocess",
                SimpleNamespace(Popen=protocol,TimeoutExpired=subprocess.TimeoutExpired,STDOUT=subprocess.STDOUT)):
            return ORIGINAL(controller,durable_root,snapshot,**{**kwargs,"pod_upload":seal_and_put,
                 "verify_transfer":independent_get,"start_test_process":resident})

    def cleanup(self):
        for role in ("lease","get"):
            (self.path/(role+".ephemeral-fixture-key")).unlink(missing_ok=True)


def prove(root,mode):
    root=root.resolve()
    bridge=FixtureBridge(root,mode)
    try:
        with patch.object(warm_batch,"run_incremental_candidate",bridge.run):
            try:
                smoke.prove(root)
            except DeniedReadback:
                if mode not in ("missing","corrupt"):
                    raise
            else:
                if mode!="valid":
                    raise AssertionError("Second scenario should have stayed blocked")
    finally:
        bridge.cleanup()
    expected=2 if mode=="valid" else 1
    assert len(bridge.ordered)==expected and len(bridge.ctrl.status())==expected
    assert len(bridge.residents)==20 and len(bridge.protocol)==21*expected
    assert all(p.poll() is not None for p in bridge.residents+bridge.protocol)
    for u in smoke.benchmark.worker.URLS.values():
        with socket.socket() as s:
            s.settimeout(.15)
            assert s.connect_ex(("127.0.0.1",int(u.rsplit(":",1)[1])))!=0
    records=bridge.ctrl.status()
    assert (records[0]["receipt_sha"] is not None)==(mode=="valid")
    assert not list(root.rglob("*.zip")) and not list(root.rglob("*.fixture-key"))
    report=dict(status="passed_not_production",mode=mode,verified_transitions=expected-1,scenario_rounds=50,
                scenario_waves=expected,fixture_samples=expected*1000,resident_pids=20,
                protocol_processes_closed=21*expected,real_gpu=False,real_r2=False,live_admission=False,
                seconds=round(time.monotonic()-bridge.started,2))
    store.write_atomic(root/"SIGNED-JOURNAL-CPU-REPORT.json",store.json_bytes(report))
    print(json.dumps(report),flush=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--mode",choices=("valid","missing","corrupt"),required=True)
    a=p.parse_args()
    prove(a.output,a.mode)
