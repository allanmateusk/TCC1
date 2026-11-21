"""Offline fixture checks for evidence and transport. These files are not real runs."""
from datetime import datetime, timezone
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.parse import urlencode

from sistema.core.ledger import Ledger, RoundRecord
from sistema.scripts.runpod_worker import child_environment
from . import artifact_store as store
from . import r2_verified_pilot as r2
from . import watchdog

RUN = "b"*32
EXPERIMENT = "pilot-n20-r5-pilot-s0"
NOW = datetime(2026,11,21,12,0,tzinfo=timezone.utc)
CFG = {"endpoint": "https://"+"a"*32+".r2.cloudflarestorage.com","bucket":"tcc","prefix":"tcc/piloto","region":"auto"}


def url(method):
    signature = ("d" if method=="PUT" else "e")*64
    return f"{CFG['endpoint']}/tcc/{r2.object_key(RUN)}?"+urlencode({
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


def fixture(root, *, missing_quorum=False):
    for d in ("ledgers","node-models"):
        (root/d).mkdir()
    l=Ledger()
    for r in range(5):
        l.append(RoundRecord("round",r,prev_hash=l.head,task_id=f"q-{r}").sealed())
        if r==2:
            l.append(RoundRecord("oracle",r,prev_hash=l.head,task_id=f"q-{r}").sealed())
    files = {
        "rounds.csv":csv_bytes([dict(round_index=r,num_nodes=20,calibration=0,is_test=0,audited=int(r==2),task_id=f"q-{r}") for r in range(5)]),
        "per_node.csv":csv_bytes([dict(round_index=r,node_id=n,profile="honest",task_id=f"q-{r}") for r in range(5) for n in store.NODES]),
        "leadership.csv":csv_bytes([dict(round_index=r,is_reference=1,leader="node-1",auditor="node-2",outcome="accepted",
            confirmed_mass=10,total_mass=10,oracle="applied" if r==2 else "") for r in range(4 if missing_quorum else 5)]),
        "reputation_history.csv":csv_bytes([dict(checkpoint=r,node_id=n,reputation=.5) for r in range(6) for n in store.NODES]),
        "audit-events.jsonl":"".join(json.dumps(dict(round=r,complete=True,planned=r==3,genesis=False,
            preempted=False,simulated_absences=[],oracle_by_node={n:"applied" for n in store.NODES} if r==3 else {}))+"\n"
            for r in range(1,6)).encode(),
    }
    for n in store.NODES:
        (root/"node-models"/n).mkdir()
        files[f"ledgers/{n}.json"]=store.json_bytes(dict(node_id=n,valid=True,records=l.to_json()))
        files[f"node-models/{n}/model-runtime.json"]=store.json_bytes(dict(
            node_id=n,run_id=EXPERIMENT,loaded_model_dtype="torch.bfloat16",dtype="bfloat16",quantization="none",
            peak_reserved_bytes=6000000000,kv_cache=True))
    for name,data in files.items():
        (root/name).write_bytes(data)
    manifest=dict(run_id=RUN,status="verified_local",completed=True,run_kind="pilot",scenario_id="pilot",
        experiment_id=EXPERIMENT, nodes=20,rounds=5,seed=0,verified_own_generations=100,
        model_is_stand_in=False,dtype="bfloat16",quantization="none",git_sha="8"*40,
        model="HuggingFaceTB/SmolLM3-3B",model_revision="a07cc9a04f16550a088caea529712d1d335b0ac1",
        pilot_artifacts_sha256={n:store.sha(raw) for n,raw in files.items()})
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
        self.manifest["pilot_artifacts_sha256"][p.name]=store.sha(p.read_bytes())
        (self.root/store.MANIFEST).write_bytes(store.json_bytes(self.manifest))
        with self.assertRaisesRegex(ValueError,"quorum"):
            self.upload()
        self.assertEqual(self.calls,[])

    def test_unfinished_inconsistent_and_mock_do_not_upload(self):
        p=self.root/store.MANIFEST
        for delta in (dict(completed=False),dict(verified_own_generations=99),dict(model_is_stand_in=True)):
            p.write_bytes(store.json_bytes({**self.manifest,**delta}))
            with self.assertRaisesRegex(ValueError,"verified, real"):
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
            raise HTTPError(req.full_url,412,"simulated precondition failed",None,None)
        with self.assertRaisesRegex(r2.TransferError,"already exists"):
            self.upload(collide)
        self.assertEqual(self.calls,["PUT"])
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
                with self.assertRaisesRegex(ValueError,"stale"):
                    verify_controller_arm(path,self.root,resource,RUN,now=deadline)
        with self.assertRaisesRegex(ValueError,"independent"):
            verify_controller_arm(None,self.root,"fake-provider-id",RUN)

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
