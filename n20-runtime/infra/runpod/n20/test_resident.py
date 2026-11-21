"""Fail-closed gates for the resident worker, no model weights or network."""
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from infra.runpod.n20 import benchmark, warm_batch
from sistema.node.resident import Actor, ResidentClient, ResidentError
from sistema.scripts.resident_pool import ResidentPool

SET={"model_name":"test-only","revision":"f"*40,"quantization":"none","device":"cuda",
     "dtype":"bfloat16","max_new_tokens":256,"temperature":.7,"top_p":.95}


class Tests(unittest.TestCase):
    def test_private_actor_revokes_epoch_and_checks_exact_tasks(self):
        now=time.time()
        aid,token,epoch=map(lambda s:s*64,("a","b","c"))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            rid="1"*32
            (root/rid).mkdir()
            q=Actor(dict(node="node-0",admin=aid,root=str(root),model_config=SET),test_model=True)
            def invoke(secret,op,**values):
                return q.handle("Bearer "+secret,{"node":"node-0","op":op,"run":rid,"epoch":epoch,**values})
            with self.assertRaises(PermissionError):
                invoke(token,"health")
            open_kw={"token":token,"deadline":now+20,"tasks":[["T","Q",42]],"resume":False}
            self.assertEqual(invoke(aid,"open",**open_kw)["loads"],1)
            kwargs={"round_index":0,"task_id":"T","question":"Q","seed":42}
            with self.assertRaises(ValueError):
                invoke(token,"generate",**{**kwargs,"seed":43})
            with self.assertRaises(ValueError):
                invoke(aid,"open",**open_kw)
            self.assertEqual(invoke(token,"generate",**kwargs)["result"],invoke(token,"generate",**kwargs)["result"])
            before=invoke(aid,"stats")
            self.assertEqual(before["calls"],1)
            invoke(aid,"close")
            with self.assertRaises(PermissionError):
                invoke(token,"health")
            with self.assertRaises(ValueError):
                invoke(aid,"open",**open_kw)
            self.assertEqual(q.handle("Bearer "+aid,{"node":"node-0","op":"open","run":rid,"epoch":"d"*64,
                           **{**open_kw,"resume":True}})["loads"],1)
            with self.assertRaises(PermissionError):
                invoke(token,"health")
            with self.assertRaises(PermissionError):
                with patch("sistema.node.resident.time.time",return_value=now+21):
                    q.handle("Bearer "+token,{"node":"node-0","op":"health","run":rid,"epoch":"d"*64})
            self.assertFalse((root/rid/"node-models/node-0/model-runtime.json").exists())

    def test_incomplete_private_environment_cannot_fall_back(self):
        with self.assertRaises(ResidentError):
            ResidentClient({"N20_RESIDENT_PORT":"1"},"node-0")

    def test_no_live_optin_from_normal_environment(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(ValueError,"defaults to disabled"):
                warm_batch.run_qualified(None,Path("test"),Path("test"),
                    observe_exact=lambda *_:None,verify_transfer=lambda *_:None,check_scheduler=lambda:True)
        profile,cases=benchmark.load_profile()
        with patch.object(benchmark.sys,"platform","linux"), patch.dict(os.environ,{"TCC_LIVE_N20_APPROVED":"true",
                "TCC_N20_OFFICIAL_QUALIFIED":"true","TCC_N20_RESIDENT_QUALIFIED":"true"},clear=True):
            with tempfile.TemporaryDirectory() as tmp:
                pool=ResidentPool(Path(tmp).resolve(),deadline=time.time()+20,start_process=lambda *_:None)
                with self.assertRaisesRegex(ValueError,"test or unknown resident"):
                    benchmark.live(profile,cases["C13"],0,Path("test"),resident_pool=pool,warm_case=object())

    def test_mismatched_case_and_expired_scope(self):
        allowed=[]
        case=warm_batch.WarmCase("a"*32,"C15","pod","8"*40,"9"*64,time.time()+10,
                                 lambda:allowed.append(True))
        fields={"resource_id":"pod","run_id":"a"*32,"scenario":"C15",
                "entry":{"run_kind":"official","rounds":50,"semente":0}}
        self.assertEqual(case.verify(**fields),case.deadline)
        with self.assertRaises(ValueError): case.verify(**{**fields,"run_id":"b"*32})
        with self.assertRaises(ValueError): case.verify_revision("8"*40,"0"*64)
        with patch("infra.runpod.n20.warm_batch.time.time",return_value=case.deadline):
            with self.assertRaises(InterruptedError): case.check()
        self.assertEqual(allowed,[True])


if __name__=="__main__":
    unittest.main()
