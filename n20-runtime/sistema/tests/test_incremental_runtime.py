"""CPU proof: incremental scheduling, private barrier, warm lookup and own raw records."""
import hashlib
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from sistema.core import behavior
from sistema.core.protocol import malicious_acts_honest, oracle_round
from sistema.core.reputation import ReputationTracker
from sistema.node import app, incremental, resident
from sistema.node.dedicated_inference import DedicatedModel
from sistema.orchestrator import run as coord

RUN="a"*32
TOKEN="b"*64
H={"X-N20-Checkpoint-Token":TOKEN,"X-N20-Checkpoint-Run":RUN}


class IncrementalTests(unittest.IsolatedAsyncioTestCase):
    async def test_shared_numeric_order_negative_zero_and_no_base(self):
        nodes=["node-10","node-2","node-1"]
        for base,value in [(20,24),(-20,-16),(0,0),(12.5,15),("20",None)]:
            xs={"node-10":float("inf"),"node-2":base,"node-1":True}
            for n in nodes:
                got=await incremental.transform(node_id=n,own_answer=xs[n],colluders=nodes,collusion=True,
                    seed=0,round_index=5,read_peer=AsyncMock(side_effect=lambda p:xs[p]))
                self.assertEqual(got,(value,"node-2" if value is not None else ""))
        no_peer=AsyncMock(side_effect=AssertionError("must not read peer"))
        got=[await incremental.transform(node_id=n,own_answer=20,colluders=nodes,
            collusion=False,seed=0,round_index=5,read_peer=no_peer) for n in (f"node-{i}" for i in range(20))]
        self.assertEqual({x[0] for x in got},{16,24})
        no_peer.assert_not_awaited()

    async def test_fixed_random_honesty_and_actual_source_rate(self):
        c=dict(behavior="incremental",defense="all",calibration_rounds=0,signal="consensus",
            reputation_mechanism="ema",malicious_strategy="knows_schedule",honest_rounds=5,
            consensus_alpha=.05,oracle_alpha=.95,rounds=50,explicit_audit_schedule=True)
        fixed=coord._protocol_config({**c,"audit_mode":"fixed","audit_rounds_override":[9,19,29,39,49]})
        rand=coord._protocol_config({**c,"audit_mode":"random","audit_rounds_override":[4,11,21,28,30,37,40,41,47]})
        self.assertEqual([i+1 for i in range(50) if oracle_round(i,fixed)],[10,20,30,40,50])
        self.assertEqual([i+1 for i in range(50) if oracle_round(i,rand)],[5,12,22,29,31,38,41,42,48])
        self.assertTrue(all(malicious_acts_honest(i,fixed) for i in (*range(5),9,19,29,39,49)))
        self.assertTrue(all(malicious_acts_honest(i,rand) for i in range(5)))
        self.assertFalse(malicious_acts_honest(11,rand))
        tr=ReputationTracker(["node-0"],mechanism=fixed.mechanism)
        self.assertEqual(tr.update("node-0",True,alpha=fixed.consensus_alpha).alpha_used,.05)
        self.assertEqual(tr.update("node-0",False,alpha=fixed.oracle_alpha,ground_truth=True).alpha_used,.95)

    async def test_auth_barrier_requires_exact_twenty_receipts(self):
        nodes=[f"node-{i}" for i in range(20)]; urls={n:f"http://127.0.0.1:{18100+i}" for i,n in enumerate(nodes)}
        seen=[]; deny=False
        async def receive(client,url,payload,timeout,*,headers):
            self.assertEqual(headers,H)
            self.assertEqual(url,urls[payload["node_id"]]+"/generation_ready")
            self.assertEqual((payload["round_index"],payload["task_id"],payload["question"]),(5,"r6","test question"))
            seen.append(payload["node_id"])
            return None if deny and payload["node_id"]==nodes[-1] else {
                **{k:v for k,v in payload.items() if k!="question"},"generated":True}
        args=(None,urls,nodes,5,{"id":"r6","question":"test question"},{"checkpoint_identity":{"run_id":RUN}},3)
        with patch.dict(os.environ,N20_CHECKPOINT_TOKEN=TOKEN,N20_CHECKPOINT_RUN_ID=RUN), patch.object(coord,"_post",side_effect=receive):
            await coord._prime_incremental_generations(*args)
            self.assertCountEqual(seen,nodes)
            deny=True
            with self.assertRaisesRegex(RuntimeError,"round was not submitted"):
                await coord._prime_incremental_generations(*args)

    async def test_real_asgi_and_sqlite_honest_omission(self):
        question="a real CPU fixture request"; seen=[]
        class Dummy:
            def sample(self,text,**kw):
                seen.append(text)
                return 20,"model trace #### 20"
        request=dict(task_id="r6",question=question,round_index=5,run_id=RUN,node_id="node-19")
        pins=[["r6",hashlib.sha256(question.encode()).hexdigest()]]*50
        with tempfile.TemporaryDirectory() as scratch:
            db=DedicatedModel(node_id="node-19",run_id=RUN,model_name="CPU",cache_dir=scratch,
                              factory=Dummy,quantization="none",dtype="bfloat16")
            with patch.dict(os.environ,MODEL_RUN_ID=RUN,N20_CHECKPOINT_TOKEN=TOKEN,N20_CHECKPOINT_RUN_ID=RUN), \
                patch.multiple(app,NODE_ID="node-19",INFERENCE_MODE="model",PROFILE=behavior.HONEST,
                               _noise_policy="incremental_upward",_incremental_task_pins=pins,
                               _campaign_absences=frozenset({5})), patch.object(app,"_get_dedicated_backend",return_value=db):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app,client=("127.0.0.1",12345)),
                      base_url="http://localhost") as http:
                    self.assertEqual((await http.post("/generation_ready",json=request)).status_code,404)
                    self.assertEqual((await http.post("/generation_ready",json={**request,"question":"wrong"},headers=H)).status_code,409)
                    self.assertEqual((await http.post("/model_answer",json=request,headers=H)).status_code,409)
                    self.assertEqual(seen,[])
                    for _ in range(2):
                        obj=await http.post("/generation_ready",json=request,headers=H)
                        self.assertEqual(obj.json(),{**{k:v for k,v in request.items() if k!="question"},"generated":True})
                    self.assertEqual((await http.post("/model_answer",json=request,headers=H)).json(),
                        {"node_id":"node-19","run_id":RUN,"answer":20})
                    self.assertIsNone((await app._dedicated_inference(app.InferRequest(task_id="r6",question=question,round_index=5)))[0])
                self.assertEqual(seen,[question])
            conn=sqlite3.connect(db.path)
            try:
                self.assertEqual(conn.execute("SELECT answer,text FROM generations").fetchall(),[("20","model trace #### 20")])
                self.assertEqual(conn.execute("SELECT answer,base_node FROM responses").fetchall(),[("null","node-19")])
            finally: conn.close()

    async def test_resident_read_only_and_wrong_seed(self):
        seen=[]
        class Dummy:
            def sample(self,text,**kw):
                seen.append(text)
                return 20,"CPU"
        with tempfile.TemporaryDirectory() as scratch:
            db=DedicatedModel(node_id="node-0",run_id=RUN,model_name="CPU",cache_dir=scratch,factory=Dummy)
            actor=resident.Actor.__new__(resident.Actor)
            actor.node="node-0";actor.admin="c"*64;actor.pid=111
            actor.active=dict(backend=db,token=TOKEN,run=RUN,epoch="e"*64,deadline=9999999999,tasks=[["a","q",99]])
            req=dict(op="read_generation",node=actor.node,run=RUN,epoch="e"*64,round_index=0,task_id="a",question="q",seed=99)
            auth="Bearer "+TOKEN
            with self.assertRaisesRegex(ValueError,"not durably logged"): actor.handle(auth,req)
            self.assertEqual(seen,[])
            actor.handle(auth,{**req,"op":"generate"})
            self.assertEqual(actor.handle(auth,req)["result"]["answer"],20)
            with self.assertRaisesRegex(ValueError,"differs from assigned"): actor.handle(auth,{**req,"seed":98})
            self.assertEqual(seen,["q"])
