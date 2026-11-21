"""Offline replication and independent verification of durable pilot rounds.

No real storage integration, credentials, inference, or automatic live resume.
"""
from contextlib import closing
from dataclasses import asdict
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile, ZipInfo
import csv
import io
import json
import os
import re
import sqlite3
import time

import yaml

from sistema.core.topology import build_graph
from sistema.orchestrator.run import _protocol_config
from .artifact_store import json_bytes, write_atomic
from .checkpoint import CheckpointStore, LOGS, NODES, replay_replica, verify_log_prefixes


SCHEMA = "tcc-pilot-round-replica/v1"
MAX_OBJECT = 48 * 1024**2
MAX_MEMBER = 16 * 1024**2


def _read(path, cap=MAX_MEMBER):
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError("Unexpected file")
    with path.open("rb") as f:
        data = f.read(cap + 1)
    if not 0 < len(data) <= cap:
        raise ValueError("File too large or empty")
    return data


def _digest(data):
    return sha256(data).hexdigest()


def _config(raw, identity):
    cfg = yaml.safe_load(raw)
    if cfg["checkpoint_identity"] != asdict(identity):
        raise ValueError("Effective config keeps a different checkpoint identity")
    core = {k:v for k,v in cfg.items() if k != "checkpoint_identity"}
    if _digest(json_bytes(core)) != identity.config_sha256:
        raise ValueError("Effective configuration checksum mismatch")
    return cfg


def _backup(source, target, index, *, replay_fixture=False):
    # Online backup API obtains consistent committed pages, even in WAL mode.
    # Never copy or truncate the live database/WAL. Restrict only the clone.
    if source.is_symlink() or source.resolve(strict=True) != source or not source.is_file():
        raise ValueError("Unexpected source database")
    with closing(sqlite3.connect(source.as_uri()+"?mode=ro",uri=True,timeout=2)) as live:
        with closing(sqlite3.connect(target,timeout=2)) as copy:
            deadline = time.monotonic() + 5

            def bounded(_status,_remaining,total):
                if time.monotonic() > deadline or total > MAX_MEMBER // 512:
                    raise TimeoutError("SQLite backup exceeded its offline budget")

            live.backup(copy, pages=32, progress=bounded, sleep=.025)
            copy.execute("PRAGMA journal_mode=DELETE")
            # Every intent, including those past the selected frontier, must
            # have a matching committed generation. Ambiguity is not resumable.
            fields = "round_index,node_id,task_id,question_hash,seed"
            intents = copy.execute(f"SELECT {fields} FROM generation_intents ORDER BY round_index").fetchall()
            gens = copy.execute(f"SELECT {fields} FROM generations ORDER BY round_index").fetchall()
            if intents != gens:
                raise ValueError("Unresolved or mismatched SQLite generation intent")
            if not replay_fixture and any(r[0]>index for r in gens):
                raise ValueError("Source moved past the fenced active round")
            copy.execute("DELETE FROM generation_intents WHERE round_index > ?",(index,))
            copy.execute("DELETE FROM responses WHERE round_index > ?",(index,))
            copy.execute("DELETE FROM generations WHERE round_index > ?",(index,))
            copy.commit()
            copy.execute("VACUUM")
    if target.with_name(target.name+"-wal").exists():
        raise ValueError("Snapshot unexpectedly retained WAL")


def _validate_db(path, identity, node, tasks, answers):
    with closing(sqlite3.connect(path.as_uri()+"?mode=ro",uri=True,timeout=2)) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("Damaged SQLite backup")
        m,=db.execute("SELECT config FROM meta WHERE id=1").fetchone()
        meta=json.loads(m)
        if (meta.get("run_id"),meta.get("node_id"),meta.get("revision")) != (
            identity.run_id,node,identity.model_revision
        ):
            raise ValueError("Snapshot provenance mismatch")
        gens=db.execute("SELECT round_index,node_id,task_id,question_hash,seed FROM generations ORDER BY round_index").fetchall()
        intents=db.execute("SELECT round_index,node_id,task_id,question_hash,seed FROM generation_intents ORDER BY round_index").fetchall()
        if intents != gens:
            raise ValueError("Restored SQLite intents differ from committed generations")
        responses=db.execute("SELECT round_index,answer,base_node FROM responses ORDER BY round_index").fetchall()
    if len(gens)!=len(tasks) or len(responses)!=len(tasks):
        raise ValueError("Snapshot does not contain one generation and response per committed round")
    for i,(gen,resp) in enumerate(zip(gens,responses,strict=True)):
        seed=int.from_bytes(sha256(f"{identity.seed}:{i}:{node}".encode()).digest()[:8],"big") & ((1<<63)-1)
        if (gen[:3]!=(i,node,tasks[i]) or not re.fullmatch("[0-9a-f]{64}",gen[3]) or gen[4]!=seed
            or resp[0]!=i or resp[2] not in NODES or json.loads(resp[1]) != answers[(i,node)]):
            raise ValueError("SQLite round, seed or submitted result conflicts with checkpoint")


class FolderStore:
    """Local stand-in for independent PUT-if-absent and GET, without any network."""
    def __init__(self, root):
        self.root=Path(root).resolve(strict=True)
        if not self.root.is_dir(): raise ValueError("Store directory required")

    def _key(self,key):
        if not re.fullmatch(r"checkpoints/[a-f0-9]{32}/round-0[1-5]\.zip",key):
            raise ValueError("Unexpected pilot object key")
        return self.root / key.replace("/","__")

    def put_exact(self,key,data):
        write_atomic(self._key(key),data)

    def get(self,key):
        return _read(self._key(key),MAX_OBJECT)


class RoundReplication:
    """Use protected independent catalog and storage roots; single fenced writer."""
    def __init__(self,catalog,store,identity):
        catalog=Path(catalog)
        if identity.scenario_id!="pilot" or identity.rounds!=5 or not catalog.is_dir() or catalog.is_symlink():
            raise ValueError("Only the protected offline five-round pilot is supported")
        self.catalog=catalog.resolve(strict=True)
        self.store=store
        self.identity=identity

    def key(self,number):
        if type(number) is not int or not 1<=number<=5:
            raise ValueError("Invalid one-based pilot round")
        return f"checkpoints/{self.identity.run_id}/round-{number:02d}.zip"

    def _local(self,number,suffix):
        self.key(number)
        return self.catalog / f"{self.identity.run_id}-{number:02d}.{suffix}"

    def _members(self,number):
        return ({"config.yaml",*LOGS} |
                {f"checkpoint-{i:02d}.json" for i in range(number)} |
                {f"node-models/{n}/inferencias.sqlite" for n in NODES})

    def _validate_restored(self,path,number):
        cfg=_config(_read(path/"config.yaml"),self.identity)
        record,checksum=CheckpointStore(path,self.identity).recover()
        if record is None or record["round_index"]!=number-1:
            raise ValueError("Restored checkpoint frontier differs")
        verify_log_prefixes(path,record)
        graph=build_graph(NODES,cfg.get("topology","kregular"),
                          degree=int(cfg.get("degree",4)),seed=self.identity.seed)
        protocol=_protocol_config(cfg)
        rounds=list(csv.DictReader(io.StringIO(_read(path/"rounds.csv").decode("utf-8"))))
        if [int(r["round_index"]) for r in rounds]!=list(range(number)):
            raise ValueError("Unexpected round CSV prefix")
        rows=list(csv.DictReader(io.StringIO(_read(path/"per_node.csv").decode("utf-8"))))
        answers={(int(r["round_index"]),r["node_id"]):json.loads(r["answer"]) if r["answer"]!="" else None
                 for r in rows}
        if len(rows)!=20*number or set(answers)!={(i,n) for i in range(number) for n in NODES}:
            raise ValueError("Incomplete committed per-node log")
        for node in sorted(NODES):
            replay_replica(record["replicas"][node],number-1,protocol,graph)
            _validate_db(path/"node-models"/node/"inferencias.sqlite",self.identity,node,
                         [r["task_id"] for r in rounds],answers)
        return checksum

    def _open(self,data,number,parent):
        if not 0 < len(data) <= MAX_OBJECT:
            raise ValueError("Unexpected package size")
        path=parent/self.identity.run_id
        path.mkdir(exist_ok=False)
        with ZipFile(BytesIO(data)) as archive:
            info=archive.infolist()
            if (len(info)!=len(self._members(number)) or {i.filename for i in info}!=self._members(number)
                or any(not 0<i.file_size<=MAX_MEMBER or i.compress_type!=0 for i in info)
                or sum(i.file_size for i in info)>MAX_OBJECT):
                raise ValueError("Unexpected ZIP members or sizes")
            for item in info:
                target=path/item.filename
                target.parent.mkdir(parents=True,exist_ok=True)
                write_atomic(target,archive.read(item))
        return path,self._validate_restored(path,number)

    def _proof(self,number,data,marker):
        return {"schema":SCHEMA, "key":self.key(number),"round":number,"nodes":20,
                "identity":asdict(self.identity),"bytes":len(data),"sha256":_digest(data),"checkpoint_sha256":marker}

    def _receipt(self,number):
        path=self._local(number,"receipt.json")
        return json.loads(_read(path)) if path.exists() else None

    def frontier(self):
        count=0
        for i in range(1,6):
            item=self._receipt(i)
            if item is None: break
            if (item.get("schema")!=SCHEMA or item.get("identity")!=asdict(self.identity)
                or item.get("key")!=self.key(i) or item.get("round")!=i or item.get("nodes")!=20
                or not re.fullmatch("[0-9a-f]{64}",item.get("sha256",""))):
                raise ValueError("Invalid protected replication receipt")
            count=i
        if any(self._receipt(i) is not None for i in range(count+2,6)):
            raise ValueError("Non-contiguous protected receipts")
        return count

    def prepare(self,run_dir,number,*,replay_fixture=False):
        self.key(number)
        run_dir=Path(run_dir).resolve(strict=True)
        if run_dir.name!=self.identity.run_id or self.catalog.is_relative_to(run_dir):
            raise ValueError("Catalog cannot live in the primary run")
        if number!=self.frontier()+1:
            raise ValueError("Cannot stage a round after an unverified previous round")
        pending=self._local(number,"zip")
        if pending.exists():
            data=_read(pending,MAX_OBJECT)
            with TemporaryDirectory(dir=self.catalog) as tmp:
                _,marker=self._open(data,number,Path(tmp))
            proof=self._proof(number,data,marker)
            write_atomic(self._local(number,"expected.json"),json_bytes(proof))
            return proof
        latest,_=CheckpointStore(run_dir,self.identity).recover()
        if latest is None or latest["round_index"]<number-1:
            raise ValueError("No complete checkpoint for requested round")
        selected=json.loads(_read(run_dir/f"checkpoint-{number-1:02d}.json"))["data"]
        with TemporaryDirectory(dir=self.catalog) as tmp:
            snapshots=Path(tmp)
            files={"config.yaml":_read(run_dir/"config.yaml")}
            for i in range(number):
                name=f"checkpoint-{i:02d}.json"; files[name]=_read(run_dir/name)
            for name,spec in selected["log_prefixes"].items():
                if spec["bytes"]>MAX_MEMBER: raise ValueError("Log prefix exceeds package budget")
                p=run_dir/name
                if p.is_symlink() or not p.is_file(): raise ValueError("Unexpected log path")
                with p.open("rb") as f: raw=f.read(spec["bytes"])
                if len(raw)!=spec["bytes"] or _digest(raw)!=spec["sha256"]: raise ValueError("Original log prefix differs")
                files[name]=raw
            for node in NODES:
                name=f"node-models/{node}/inferencias.sqlite"
                target=snapshots/(node+".sqlite")
                _backup(run_dir/name,target,number-1,replay_fixture=replay_fixture)
                files[name]=_read(target)
            if sum(map(len,files.values()))>MAX_OBJECT: raise ValueError("Package exceeds budget")
            archive=BytesIO()
            with ZipFile(archive,"w") as z:
                for name,data in sorted(files.items()):
                    z.writestr(ZipInfo(name,(2026,1,1,0,0,0)),data)
            data=archive.getvalue()
            (snapshots/"verify").mkdir()
            _,marker=self._open(data,number,snapshots/"verify")
        proof=self._proof(number,data,marker)
        write_atomic(pending,data)
        write_atomic(self._local(number,"expected.json"),json_bytes(proof))
        return proof

    def replicate(self,number):
        prior=self.frontier()
        if number<=prior:
            receipt=self._receipt(number)
            read=self.store.get(self.key(number))
            if len(read)!=receipt["bytes"] or _digest(read)!=receipt["sha256"]:
                raise ValueError("Stored verified package no longer matches the protected receipt")
            return receipt
        if number!=prior+1:
            raise ValueError("Replication order would skip an unverified round")
        expected=json.loads(_read(self._local(number,"expected.json")))
        data=_read(self._local(number,"zip"),MAX_OBJECT)
        if self._proof(number,data,expected["checkpoint_sha256"])!=expected:
            raise ValueError("Prepared bytes no longer match original digest")
        self.store.put_exact(self.key(number),data)
        read=self.store.get(self.key(number))
        if len(read)!=expected["bytes"] or _digest(read)!=expected["sha256"]:
            raise ValueError("Store returned different bytes")
        with TemporaryDirectory(dir=self.catalog) as tmp:
            _, marker=self._open(read,number,Path(tmp))
        if self._proof(number,read,marker)!=expected:
            raise ValueError("Independent reopen returned another checkpoint")
        write_atomic(self._local(number,"receipt.json"),json_bytes(expected))
        return expected

    def restore(self,number,destination_root):
        if number>self.frontier():
            raise ValueError("Cannot restore a round that lacks a verified receipt")
        root=Path(destination_root).resolve(strict=True)
        target=root/self.identity.run_id
        if target.exists() or target.is_symlink(): raise FileExistsError(target)
        receipt=self._receipt(number)
        data=self.store.get(self.key(number))
        if len(data)!=receipt["bytes"] or _digest(data)!=receipt["sha256"]:
            raise ValueError("Remote package does not match trusted proof")
        with TemporaryDirectory(dir=root) as tmp:
            path,marker=self._open(data,number,Path(tmp))
            if self._proof(number,data,marker)!=receipt: raise ValueError("Restore proof mismatch")
            path.rename(target)
        return target
