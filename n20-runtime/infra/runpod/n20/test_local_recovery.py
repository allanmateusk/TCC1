"""Sensitive restart boundary: no real inference or provider operations."""
import hashlib
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from . import benchmark, checkpoint, local_recovery
from sistema.node.dedicated_inference import DedicatedModel


class RecoveryTests(unittest.TestCase):
    def test_scope_attestation(self):
        expected = {"run_id": "a"*32, "scenario_id": "C13", "resource_id": "runner-1",
                    "git_sha": "b"*40, "snapshot_revision": "c"*40}
        valid={"schema":"tcc-n20-local-recovery-permit/v1",**expected,"marker_sha256":"d"*64,
               "old_processes_fenced":True,"issued_epoch":1000,"expires_epoch":1050}
        def check(proposal):
            return local_recovery.check_permit(proposal,expected=expected,now=1010,provider_deadline=1100)
        self.assertEqual(check(valid), "d"*64)
        for changes in ({"old_processes_fenced":False}, {"resource_id":"wrong"}, {"expires_epoch":1010},
                        {"expires_epoch":1160}, {"issued_epoch":True}, {"run_id":"0"*32},
                        {"marker_sha256":"https://example.org"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                check({**valid,**changes})

    def test_official_qualification_and_recovery_gate_do_not_access_gpu(self):
        profile, scenarios = benchmark.load_profile()
        env={"TCC_LIVE_N20_APPROVED":"true"}
        with patch.object(benchmark.sys,"platform","linux"), patch.dict(benchmark.os.environ,env,clear=True):
            with self.assertRaisesRegex(ValueError,"Official case disabled"):
                benchmark.live(profile,scenarios["C13"],0,Path("model"),recovery_permit=Path("permit"))
            env["TCC_N20_OFFICIAL_QUALIFIED"]="true"
            with patch.dict(benchmark.os.environ,env,clear=True):
                with self.assertRaisesRegex(ValueError,"Real restart disabled"):
                    benchmark.live(profile,scenarios["C13"],0,Path("model"),recovery_permit=Path("permit"))

    def test_ambiguous_invocation_not_reissued(self):
        calls=[]
        class InterruptedModel:
            def sample(self, *_a, **_kw):
                calls.append(1)
                raise InterruptedError("stand-in terminated after call began")
        with tempfile.TemporaryDirectory() as tmp:
            def node():
                return DedicatedModel(node_id="node-0",run_id="a"*32,model_name="stand-in",cache_dir=tmp,
                    quantization="none", revision="c"*40,factory=InterruptedModel)
            kw=dict(round_index=0, task_id="q", question="query",seed=42)
            with self.assertRaises(InterruptedError):
                node().generate(**kw)
            with self.assertRaisesRegex(RuntimeError, "refusing automatic duplicate"):
                node().generate(**kw)
            self.assertEqual(len(calls),1)
            with closing(sqlite3.connect(Path(tmp)/"inferencias.sqlite")) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM generation_intents").fetchone(),(1,))
                self.assertEqual(db.execute("SELECT count(*) FROM generations").fetchone(),(0,))

    def test_cached_complete_call_with_same_identity_is_never_reissued(self):
        calls=[]
        class Model:
            def sample(self,*_a,**_kw):
                calls.append(1)
                return 12,"#### 12"
        with tempfile.TemporaryDirectory() as tmp:
            def node():
                return DedicatedModel(node_id="node-0",run_id="a"*32,model_name="stand-in",cache_dir=tmp,
                    quantization="none", revision="c"*40,factory=Model)
            kw=dict(round_index=0,task_id="q",question="query",seed=42)
            self.assertEqual(node().generate(**kw), node().generate(**kw))
            self.assertEqual(len(calls),1)
            with self.assertRaisesRegex(ValueError,"conflicting"):
                node().generate(**{**kw,"seed":54})

    def test_prepare_requires_twenty_bound_caches_and_no_uncommitted_intent(self):
        class Model:
            def sample(self,*_a,**_kw): return 12,"#### 12"
        with tempfile.TemporaryDirectory() as tmp:
            runid="a"*32
            root=Path(tmp).resolve()/runid
            root.mkdir()
            ident=checkpoint.Identity(runid,"n20-C13","C13",0,50,"b"*40,"c"*40,"d"*64,"e"*64,"f"*64)
            tasks=[{"id":f"q{i}","question":f"query{i}"} for i in range(50)]
            scope={"device":"cuda","dtype":"bfloat16","max_new_tokens":256,"model":"stand-in","quantization":"none",
                   "revision":"c"*40,"temperature":.7,"top_p":.95}
            digest="1"*64
            proof=dict(round_index=0)
            def prepare(value=digest):
                return local_recovery.prepare(root,ident,tasks,scope,accepted_digest=value)
            def create(n):
                cache=root/"node-models"/n
                backend=DedicatedModel(node_id=n,run_id=runid,model_name="stand-in",cache_dir=cache,
                                       quantization="none",revision="c"*40,factory=Model)
                seed=int.from_bytes(hashlib.sha256(f"0:0:{n}".encode()).digest()[:8],"big") & (2**63-1)
                backend.generate(round_index=0,task_id="q0",question="query0",seed=seed)
                backend.record_response(0,12,n)
            with patch.object(local_recovery.c,"CheckpointStore") as markers, patch.object(local_recovery.c,"verify_log_prefixes"):
                markers.return_value.recover.return_value=(proof,digest)
                with self.assertRaisesRegex(ValueError,"Trusted frontier"):
                    prepare("2"*64)
                with self.assertRaises(FileNotFoundError): prepare()
                for n in checkpoint.NODES: create(n)
                prepared, m=prepare()
                self.assertEqual((prepared["index"],m),(0,proof))
                with closing(sqlite3.connect(root/"node-models"/"node-19"/"inferencias.sqlite")) as db:
                    db.execute("INSERT INTO generation_intents VALUES(1,'node-19','q1','pending',567)")
                    db.commit()
                with self.assertRaisesRegex(ValueError,"Ambiguous"):
                    prepare()


if __name__=="__main__":
    unittest.main()
