"""Offline fixture checks for evidence and transport. These files are not real runs."""
from datetime import datetime, timezone
import csv
import io
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode

from sistema.core.ledger import Ledger, RoundRecord
from sistema.node.dedicated_inference import DedicatedModel
from sistema.scripts.runpod_worker import child_environment
from sistema.scripts import runpod_worker as worker
from . import artifact_store as store
from . import r2_verified_pilot as r2
from . import watchdog

RUN = "b"*32
EXPERIMENT = "pilot-n20-r5-pilot-s0"
NOW = datetime(2026,11,21,12,0,tzinfo=timezone.utc)
CFG = {"endpoint": "https://"+"a"*32+".r2.cloudflarestorage.com","bucket":"tcc","prefix":"tcc/piloto","region":"auto"}


def url(method,kind="pilot"):
    signature = ("d" if method=="PUT" else "e")*64
    return f"{CFG['endpoint']}/tcc/{r2.object_key(RUN,kind)}?"+urlencode({
        "X-Amz-Algorithm":"AWS4-HMAC-SHA256","X-Amz-Credential":"FAKE/20261121/auto/s3/aws4_request",
        "X-Amz-Date":"20261121T120000Z","X-Amz-Expires":"600","X-Amz-Signature":signature,
        "X-Amz-SignedHeaders":"host;if-none-match" if method=="PUT" else "host",
    })


def csv_bytes(rows):
    f=io.StringIO(newline="")
    w=csv.DictWriter(f,fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
    return f.getvalue().encode()



class CapturedNodeLaunch(Exception):
    pass


def checkpointed_worker_node_env(root, config, entry, profile, scenario):
    # Capture the actual environment at Popen (never spawn a worker or load a model).
    captured={}
    (root/"test-model").mkdir()
    def capture(*_args, **kwargs):
        captured.update(kwargs["env"])
        raise CapturedNodeLaunch
    with patch.object(worker.subprocess,"Popen",side_effect=capture):
        try:
            worker.execute_scenario(root,{**entry,"checkpoint_capture":{
                "run_id":RUN,"git_sha":"8"*40,"tasks_sha256":profile["task_sha256"],
                "scenario_id":scenario}},config,root/"test-model",["fixture-0","fixture-1"],
                lambda:None,lambda *_args,**_kwargs:None)
        except CapturedNodeLaunch:
            pass
        else:
            raise AssertionError("Expected the checkpointed worker to attempt a node launch")
    if captured.get("NODE_ID")!="node-0":
        raise AssertionError("Missing node startup environment")
    return captured


def fixture(root, *, missing_quorum=False, scenario="pilot"):
    from . import benchmark
    profile, cases = benchmark.load_profile()
    config,entry = benchmark.scenario_args(profile,cases[scenario],0)
    boot=checkpointed_worker_node_env(root,config,entry,profile,scenario)
    for d in ("ledgers","node-models"):
        (root/d).mkdir()
    plan=entry["audit_plan"]
    n_rounds=entry["rounds"]
    genesis, audits, fixed=(set(plan[k]) for k in ("genesis_rounds","planned_rounds","fixed_test_rounds"))
    source=json.loads((benchmark.ROOT/profile["task_file"]).read_text(encoding="utf-8"))["tarefas"][:n_rounds]
    tasks=[t["id"] for t in source]
    malicious=set(store.NODES[:cases[scenario]["malicious_nodes"]])
    method=cases[scenario].get("mechanism","ema_slow_up")
    l=Ledger()
    for r in range(1,n_rounds+1):
        kind="calibration" if r in genesis else "round"
        l.append(RoundRecord(kind,r-1,prev_hash=l.head,task_id=tasks[r-1]).sealed())
        if r in audits:
            l.append(RoundRecord("oracle",r-1,prev_hash=l.head,task_id=tasks[r-1]).sealed())
    def omitted(r,n):
        return n in plan["simulated_absences"].get(r,())
    def trace_events(r,n):
        cand = [rec for rec in l.records if rec.round_index==r-1]
        return [dict(node_id=n,kind=rec.kind,record_hash=rec.hash,track="consensus",source="applied_record",
            operation="skip" if omitted(r,n) else "update",
            alpha_used=None if omitted(r,n) else .05 if rec.kind=="round" else .8,
            signal=None if omitted(r,n) else .5,mechanism=method,before=.5,after=.5) for rec in cand]
    def scalar(r,n):
        seq=[e["alpha_used"] for e in trace_events(r,n) if e["operation"]=="update"]
        return seq[0] if len(seq)==1 else ""
    files = {
        store.REPUTATION_TRACE:"".join(json.dumps(dict(round_index=r-1,nodes={
            n:trace_events(r,n) for n in store.NODES}))+"\n" for r in range(1,n_rounds+1)).encode(),
        "rounds.csv":csv_bytes([dict(round_index=r-1,num_nodes=20,calibration=int(r in genesis),is_test=int(r in fixed),
            audited=int(r in audits),task_id=tasks[r-1]) for r in range(1,n_rounds+1)]),
        "per_node.csv":csv_bytes([dict(round_index=r-1,node_id=n,profile="malicious" if n in malicious else "honest",
            mechanism=method,answered=int(not omitted(r,n)),answer="" if omitted(r,n) else "42",task_id=tasks[r-1],
            alpha_used=scalar(r,n),reputation_before=.5,reputation_after=.5)
            for r in range(1,n_rounds+1) for n in store.NODES]),
        "leadership.csv":csv_bytes([dict(round_index=r-1,is_reference=1,leader="" if r in genesis else "node-1",
            auditor="" if r in genesis else "node-2",outcome="calibration" if r in genesis else "accepted",
            confirmed_mass=0 if r in genesis else 10,total_mass=0 if r in genesis else 10,
            oracle="calibration" if r in genesis else "applied" if r in audits else "") for r in
            range(1,n_rounds+(0 if missing_quorum else 1))]),
        "reputation_history.csv":csv_bytes([dict(checkpoint=r,node_id=n,reputation=.5) for r in range(n_rounds+1) for n in store.NODES]),
        "audit-events.jsonl":"".join(json.dumps(dict(round=r,complete=True,planned=r in audits,genesis=r in genesis,
            preempted=r in plan["preempted_rounds"],simulated_absences=plan["simulated_absences"].get(r,[]),
            oracle_by_node={n:"applied" for n in store.NODES} if r in (audits|genesis) else {}))+"\n"
            for r in range(1,n_rounds+1)).encode(),
    }
    def node_seed(r,n):
        return int.from_bytes(hashlib.sha256(f"0:{r}:{n}".encode()).digest()[:8],"big")&((1<<63)-1)
    # Real SQLite/writer format with a deterministic stand-in and fake GPU counters.
    # No actual torch, network, snapshot, or CUDA is loaded by this regression test.
    model=SimpleNamespace(dtype="torch.bfloat16",generation_config=SimpleNamespace(use_cache=True),
                          get_memory_footprint=lambda:6_150_197_248)
    standin=SimpleNamespace(model=model,sample=lambda *_a,**_kw:(42,"#### 42"))
    counters=SimpleNamespace(get_device_name=lambda _: "offline test fake device",
        memory_allocated=lambda _:6_150_197_248,memory_reserved=lambda _:6_400_000_000,
        max_memory_allocated=lambda _:6_150_197_248,max_memory_reserved=lambda _:6_400_000_000)
    for n in store.NODES:
        backend=DedicatedModel(node_id=n,run_id=boot["MODEL_RUN_ID"],model_name=boot["MODEL_NAME"],
            cache_dir=root/"node-models"/n,dtype=boot["MODEL_DTYPE"],quantization=boot["MODEL_QUANTIZATION"],
            device=boot["MODEL_DEVICE"],revision=boot["MODEL_REVISION"],factory=lambda:standin)
        for r,t in enumerate(tasks):
            backend.generate(round_index=r,task_id=t,question=source[r]["question"],seed=node_seed(r,n))
            backend.record_response(r,None if omitted(r+1,n) else 42,n)
        with patch.dict(sys.modules,{"torch":SimpleNamespace(cuda=counters)}):
            backend._record_memory()
        files[f"ledgers/{n}.json"]=store.json_bytes(dict(node_id=n,valid=True,records=l.to_json()))
    for name,data in files.items():
        (root/name).write_bytes(data)
    manifest=dict(run_id=RUN,status="verified_local",completed=True,run_kind=entry["run_kind"],scenario_id=scenario,
        experiment_id=entry["id"], scenario=entry,nodes=20,rounds=n_rounds,seed=0,verified_own_generations=20*n_rounds,
        model_is_stand_in=False,dtype="bfloat16",quantization="none",git_sha="8"*40,
        model="HuggingFaceTB/SmolLM3-3B",model_revision="a07cc9a04f16550a088caea529712d1d335b0ac1")
    manifest=store.finalize_run(root,manifest)
    (root/store.MANIFEST).write_bytes(store.json_bytes(manifest))
    return manifest


class Response(io.BytesIO):
    def __init__(self, status, body=b""):
        super().__init__(body)
        self.status=status


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=store.durable_run(Path(self.temp.name),RUN)
        self.root.mkdir()
        self.manifest=fixture(self.root)
        self.calls=[]
        self.server_bytes=b""

    def op(self,req,timeout):
        method=req.get_method()
        self.calls.append(method)
        self.assertGreater(timeout,0)
        if method=="PUT":
            self.assertEqual(req.get_header("If-none-match"),"*")
            self.assertEqual(req.get_header("Content-type"),"application/zip")
            self.server_bytes=bytes(req.data)
            return Response(200)
        return Response(200,self.server_bytes)

    def upload(self,op=None,**kwargs):
        return r2.upload(self.root,RUN,CFG,url("PUT"),url("GET"),opener=op or self.op,now=NOW,
                         sleep=lambda _:None,**kwargs)

    def test_happy_path_keeps_independent_validated_copy_and_receipt(self):
        receipt=self.upload()
        self.assertEqual(self.calls,["PUT","GET"])
        self.assertEqual(receipt, json.loads((self.root/store.RECEIPT).read_bytes()))
        self.assertEqual(receipt["verified_quorum_rounds"],5)
        self.assertEqual(receipt["verified_ledgers"],20)
        self.assertEqual(receipt["verified_audit_rounds"],[3])
        self.assertEqual((self.root/store.DOWNLOADED).read_bytes(), self.server_bytes)
        self.assertTrue(watchdog.matches_receipt(
            watchdog.Binding(RUN,"fake-provider-id","tcc",1000,100,30),receipt))
        self.assertEqual(self.upload(),receipt)
        self.assertEqual(self.calls,["PUT","GET"])

    def test_archive_binds_worker_uuid_separately_from_experiment(self):
        runtime_name=store.RUNTIME[0]
        runtime_path=self.root/runtime_name
        manifest_path=self.root/store.MANIFEST
        original=runtime_path.read_bytes()
        source=json.loads(original)
        self.assertEqual(source["run_id"],RUN)
        self.assertEqual(self.manifest["experiment_id"],EXPERIMENT)
        self.assertNotEqual(source["run_id"],self.manifest["experiment_id"])

        def install(meta):
            runtime_path.write_bytes(store.json_bytes(meta))
            manifest={**self.manifest,"artifacts_sha256":{
                **self.manifest["artifacts_sha256"],runtime_name:store.sha(runtime_path.read_bytes())}}
            manifest_path.write_bytes(store.json_bytes(manifest))

        for mut in ({"run_id":EXPERIMENT},{"run_id":"a"*32},{"node_id":"node-1"}):
            with self.subTest(delta=mut):
                install({**source,**mut})
                with self.assertRaisesRegex(ValueError,"another node or external run UUID"):
                    self.upload()
        install({**source,"loaded_model_dtype":"torch.float16"})
        with self.assertRaisesRegex(ValueError,"actual BF16"):
            self.upload()
        runtime_path.write_bytes(original)
        for manifest in ({**self.manifest,"experiment_id":RUN},
                         {**self.manifest,"scenario":{**self.manifest["scenario"],"id":RUN}}):
            manifest_path.write_bytes(store.json_bytes(manifest))
            with self.assertRaisesRegex(ValueError,"Wrong experiment identity"):
                self.upload()
        self.assertEqual(self.calls,[])

    def test_corrupt_get_preserves_local_files_and_creates_no_receipt(self):
        def corrupt(req,timeout):
            if req.get_method()=="PUT":
                return self.op(req,timeout)
            return Response(200, self.server_bytes[:-1]+bytes([self.server_bytes[-1]^1]))
        with self.assertRaisesRegex(r2.TransferError,"SHA-256"):
            self.upload(corrupt)
        self.assertTrue((self.root/store.ARCHIVE).is_file())
        self.assertFalse((self.root/store.DOWNLOADED).exists())
        self.assertFalse((self.root/store.RECEIPT).exists())

    def test_missing_quorum_rejected_even_when_hash_updated(self):
        p=self.root/"leadership.csv"
        p.write_bytes(b"\n".join(p.read_bytes().splitlines()[:-1])+b"\n")
        self.manifest["artifacts_sha256"][p.name]=store.sha(p.read_bytes())
        (self.root/store.MANIFEST).write_bytes(store.json_bytes(self.manifest))
        with self.assertRaisesRegex(ValueError,"quorum"):
            self.upload()
        self.assertEqual(self.calls,[])

    def test_unfinished_inconsistent_and_mock_do_not_upload(self):
        p=self.root/store.MANIFEST
        for delta in (dict(completed=False),dict(verified_own_generations=99),dict(model_is_stand_in=True)):
            p.write_bytes(store.json_bytes({**self.manifest,**delta}))
            with self.assertRaisesRegex(ValueError,"verified, real|count of verified"):
                self.upload()
        self.assertEqual(self.calls,[])

    def test_wrong_account_or_unsigned_conditional_put_is_rejected(self):
        for put in (url("PUT").replace("a"*32+".r2", "c"*32+".r2"),
                    url("PUT").replace("host%3Bif-none-match", "host")):
            with self.assertRaises(ValueError):
                r2.upload(self.root,RUN,CFG,put,url("GET"),opener=self.op,now=NOW)
        self.assertEqual(self.calls,[])

    def test_blob_key_collision_is_not_confirmed_as_upload(self):
        def collide(req,timeout):
            self.calls.append(req.get_method())
            if req.get_method()=="PUT":
                raise HTTPError(req.full_url,412,"fixture",None,None)
            return Response(200,b"a different object")
        with self.assertRaisesRegex(r2.TransferError,"object differs"):
            self.upload(collide)
        self.assertEqual(self.calls,["PUT","GET"])
        self.assertFalse((self.root/store.RECEIPT).exists())

    def test_ambiguous_put_recovers_by_get_only(self):
        def ambiguous(req,timeout):
            result=self.op(req,timeout)
            if req.get_method()=="PUT":
                result.close()
                raise TimeoutError("fixture")
            return result
        self.assertEqual(self.upload(ambiguous)["status"],"verified")
        self.assertEqual(self.calls,["PUT","GET"])

    def test_timeout_is_bounded_and_local_archive_is_preserved(self):
        def broken(req,timeout):
            self.calls.append(req.get_method())
            raise TimeoutError("fixture")
        with self.assertRaisesRegex(r2.TransferError,"bounded"):
            self.upload(broken)
        self.assertEqual(self.calls,["PUT","GET","GET","GET"])
        self.assertTrue((self.root/store.ARCHIVE).is_file())
        self.assertFalse((self.root/store.RECEIPT).exists())

    def test_uploader_received_only_expected_secrets_and_children_get_none(self):
        parent={name:"discard-canary" for name in (
            "RUNPOD_API_KEY","GITHUB_TOKEN","HF_TOKEN","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY",
            "TCC_S3_KEY", r2.PUT_ENV,r2.GET_ENV)}
        parent.update(PATH="runtime path", SYSTEMROOT="C:/Windows")
        self.assertEqual(child_environment(parent),{"PATH":"runtime path","SYSTEMROOT":"C:/Windows"})

    def test_durable_root_requires_existing_absolute_outside_source(self):
        with self.assertRaises(ValueError):
            store.durable_run(Path("relative"), RUN)
        with self.assertRaises(ValueError):
            store.durable_run(self.root.parent,RUN,repo=self.root.parent)

    def test_live_arm_binds_exact_uuid_resource_and_deadline(self):
        from .benchmark import verify_controller_arm
        with tempfile.TemporaryDirectory() as external:
            path=Path(external)/"armed.json"
            binding=watchdog.Binding(RUN,"fake-provider-id","tcc",1000,100,30)
            watchdog.arm(path,binding)
            self.assertEqual(verify_controller_arm(path,self.root,"fake-provider-id",RUN,now=101),1000)
            for deadline, resource in ((150,"fake-provider-id"),(105,"another-id"),(1000,"fake-provider-id")):
                with self.assertRaisesRegex(ValueError,"stale|expired|timed|not armed"):
                    verify_controller_arm(path,self.root,resource,RUN,now=deadline)
        with self.assertRaisesRegex(ValueError,"independent"):
            verify_controller_arm(None,self.root,"fake-provider-id",RUN)


    def test_official_outages_recover_exact_durable_zip_without_regeneration(self):
        with tempfile.TemporaryDirectory() as temp:
            root=store.durable_run(Path(temp),RUN)
            root.mkdir()
            m=fixture(root,scenario="C13")
            self.assertEqual(m["verified_own_generations"],1000)
            official={**CFG,"prefix":"tcc/prod"}
            blob=None
            calls=[]
            def fault(req,timeout):
                nonlocal blob
                method=req.get_method()
                calls.append(method)
                if method=="PUT":
                    blob=bytes(req.data)
                    raise TimeoutError("simulated PUT dropped after accepting")
                raise TimeoutError("simulated read outage")
            def recovered(req,timeout):
                method=req.get_method()
                calls.append(method)
                if method=="PUT":
                    self.assertEqual(req.data,blob)
                    raise HTTPError(req.full_url,412,"fixture",None,None)
                return Response(200,blob)
            kwargs=dict(now=NOW,sleep=lambda _:None)
            with self.assertRaisesRegex(r2.TransferError,"bounded"):
                r2.upload(root,RUN,official,url("PUT","official"),url("GET","official"),opener=fault,**kwargs)
            existed=(root/store.OFFICIAL_ARCHIVE).read_bytes()
            self.assertEqual(blob,existed)
            self.assertFalse((root/store.RECEIPT).exists())
            with patch.object(store,"build_archive",side_effect=AssertionError("must not rebuild original ZIP")):
                receipt=r2.upload(root,RUN,official,url("PUT","official"),url("GET","official"),opener=recovered,**kwargs)
            self.assertEqual(calls,["PUT","GET","GET","GET","PUT","GET"])
            self.assertEqual(receipt["key"],r2.object_key(RUN,"official"))
            self.assertEqual(receipt["scenario_id"],"C13")
            self.assertEqual(receipt["verified_own_generations"],1000)
            self.assertEqual(receipt["verified_quorum_rounds"],47)
            self.assertEqual(receipt["verified_intentional_absences"],215)
            self.assertEqual(receipt["verified_genesis_rounds"],[1,2,3])
            self.assertEqual(existed,(root/store.DOWNLOADED).read_bytes())
            self.assertTrue(watchdog.matches_receipt(watchdog.Binding(RUN,"fake-provider-id","tcc",1000,100,30,
                run_kind="official",scenario_id="C13"),receipt))
            with self.assertRaises(ValueError):
                r2.upload(root,RUN,CFG,url("PUT"),url("GET"),opener=recovered,**kwargs)

    def test_official_outage_before_put_landing_then_same_zip_is_sent(self):
        with tempfile.TemporaryDirectory() as temp:
            root=store.durable_run(Path(temp),RUN)
            root.mkdir()
            fixture(root,scenario="C11")
            cfg={**CFG,"prefix":"tcc/prod"}
            kwargs=dict(now=NOW,sleep=lambda _:None)
            def never_landed(req,timeout):
                raise TimeoutError("fixture")
            with self.assertRaises(r2.TransferError):
                r2.upload(root,RUN,cfg,url("PUT","official"),url("GET","official"),opener=never_landed,**kwargs)
            expected=(root/store.OFFICIAL_ARCHIVE).read_bytes()
            def good(req,timeout):
                if req.get_method()=="PUT":
                    self.assertEqual(req.data,expected)
                    return Response(200)
                return Response(200,expected)
            report=r2.upload(root,RUN,cfg,url("PUT","official"),url("GET","official"),opener=good,**kwargs)
            self.assertEqual(report["verified_audit_rounds"],[3,9,16,22,28,34,41,47])
            self.assertEqual(report["scenario_id"],"C11")

    def test_archive_disallows_extra_members(self):
        import zipfile
        data,_=r2.prepare(self.root,RUN)
        stream=io.BytesIO(data)
        with zipfile.ZipFile(stream,"a") as archive:
            archive.writestr("node-models/node-0/inferencias.sqlite-wal","fixture")
        with self.assertRaisesRegex(ValueError,"Unrecognized ZIP"):
            store.verify_archive(stream.getvalue(),RUN)


if __name__=="__main__":
    unittest.main()
