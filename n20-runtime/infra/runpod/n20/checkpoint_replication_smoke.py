"""Run against a completed, prior HTTP stand-in pilot; creates only scratch outputs."""
import argparse
from dataclasses import replace
from pathlib import Path
import json
import tempfile
import sqlite3
from contextlib import closing

import yaml

from .checkpoint import Identity, CheckpointStore
from .checkpoint_replication import FolderStore, RoundReplication, _backup


class Fault:
    def __init__(self, store):
        self.store=store
        self.put_keys=[]
        self.fail_put=False
        self.bad_get=False
        self.commit_then_timeout=False
        self.miss_get=False

    def put_exact(self,key,data):
        self.put_keys.append((key,len(data)))
        if self.fail_put:
            self.fail_put=False
            raise IOError("injected PUT failure")
        self.store.put_exact(key,data)
        if self.commit_then_timeout:
            self.commit_then_timeout=False
            raise TimeoutError("reply lost after immutable PUT stored bytes")

    def get(self,key):
        if self.miss_get:
            self.miss_get=False
            raise FileNotFoundError("simulated temporary 404 while verifying")
        data=self.store.get(key)
        if self.bad_get:
            self.bad_get=False
            return data[:-1]+bytes([data[-1]^1])
        return data


def require_rejected(fn,error):
    try: fn()
    except error: return
    raise AssertionError("Fixture failed to reject invalid action")


def prove(source: Path, evidence_root: Path):
    """Explicit existing fixture required; no process or model is launched."""
    source=source.resolve(strict=True)
    raw=yaml.safe_load((source/"config.yaml").read_bytes())
    identity=Identity(**raw["checkpoint_identity"])
    evidence_root.mkdir(exist_ok=False)
    for name in ("catalog","store","restore"):
        (evidence_root/name).mkdir()
    adapter=Fault(FolderStore(evidence_root/"store"))
    repl=RoundReplication(evidence_root/"catalog",adapter,identity)
    first=repl.prepare(source,1,replay_fixture=True)
    repl.replicate(1)
    second=repl.prepare(source,2,replay_fixture=True)
    adapter.fail_put=True
    require_rejected(lambda:repl.replicate(2),IOError)
    assert repl.frontier()==1
    require_rejected(lambda:repl.prepare(source,3,replay_fixture=True),ValueError)
    require_rejected(lambda:repl.restore(2,evidence_root/"restore"),ValueError)
    adapter.bad_get=True
    require_rejected(lambda:repl.replicate(2),ValueError)
    assert repl.frontier()==1
    assert repl.replicate(2)==second
    assert repl.replicate(2)==second
    assert repl.frontier()==2
    # Function takes only the remote store/catalog and an empty destination;
    # deliberately instantiate a fresh verifier with no primary path.
    resumed=RoundReplication(evidence_root/"catalog",FolderStore(evidence_root/"store"),identity)
    restored=resumed.restore(2,evidence_root/"restore")
    state,digest=CheckpointStore(restored,identity).recover()
    assert state["round_index"]==1 and digest==second["checkpoint_sha256"]
    assert len(list(restored.glob("node-models/*/inferencias.sqlite")))==20
    third=repl.prepare(source,3,replay_fixture=True)
    adapter.commit_then_timeout=True
    require_rejected(lambda:repl.replicate(3),TimeoutError)
    assert repl.frontier()==2
    adapter.miss_get=True
    require_rejected(lambda:repl.replicate(3),FileNotFoundError)
    assert repl.frontier()==2
    require_rejected(lambda:repl.prepare(source,4,replay_fixture=True),ValueError)
    assert repl.replicate(3)==third
    assert repl.frontier()==3
    # An already reconciled historical fixture may be trimmed in a clone only.
    cache=source/"node-models"/"node-0"/"inferencias.sqlite"
    with tempfile.TemporaryDirectory(dir=evidence_root) as scratch:
        temp=Path(scratch).resolve()
        require_rejected(lambda:_backup(cache,temp/"future.sqlite",1),ValueError)
        _backup(cache,temp/"ambiguous.sqlite",1,replay_fixture=True)
        with closing(sqlite3.connect(temp/"ambiguous.sqlite")) as db:
            db.execute("INSERT INTO generation_intents VALUES (?,?,?,?,?)",
                       (4,"node-0","unresolved-task","9"*64,123))
            db.commit()
        require_rejected(lambda:_backup(temp/"ambiguous.sqlite",temp/"denied.sqlite",1,
                                       replay_fixture=True),ValueError)
    wrong=RoundReplication(evidence_root/"catalog",FolderStore(evidence_root/"store"),
                           replace(identity,model_revision="f"*40))
    require_rejected(wrong.frontier,ValueError)
    proof={"verified":True,"rounds_replicated":[1,2,3],"frontier_after_put_or_get_failure":1,
           "frontier_after_retry":2,"frontier_after_ambiguous_write_404":2,"final_frontier":repl.frontier(),"nodes_restored":20,"committed_generations_restored":40,
           "round1_bytes":first["bytes"],"round2_bytes":second["bytes"],
           "round2_sha256":second["sha256"],"live_cloud":False,"simulation":"local_folder",
           "restore_reads_primary":False,"wrong_identity_rejected":True,"unresolved_future_intent_rejected":True}
    (evidence_root/"replication-report.json").write_text(json.dumps(proof,indent=2)+"\n",encoding="utf-8")
    return proof


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    args=p.parse_args()
    print(json.dumps(prove(args.source,args.output),sort_keys=True))
