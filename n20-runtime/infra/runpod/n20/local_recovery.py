"""Fail-closed local continuation; cloud fencing must be independently qualified."""
from contextlib import closing
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from . import artifact_store as a, checkpoint as c


def read_marker(work, identity, index, digest):
    """Child bootstrap reads one exact supervisor-verified immutable marker."""
    i = c.Identity(**identity) if isinstance(identity, dict) else identity
    root = Path(work).resolve(strict=True)
    if root.name != i.run_id or not 0 <= index < i.rounds - 1 or not c._hex(digest, 64):
        raise ValueError("Invalid child recovery frontier")
    path = root / f"checkpoint-{index:02d}.json"
    if path.resolve(strict=True) != path or path.stat().st_size > c.MAX_CHECKPOINT:
        raise ValueError("Unsafe checkpoint source")
    v = json.loads(path.read_bytes())
    data = v["data"]
    if (v["sha256"] != digest or a.sha(a.json_bytes(data)) != digest
            or data["identity"] != asdict(i) or data["round_index"] != index):
        raise ValueError("Marker bound by supervisor does not match")
    return data


def load_request(root):
    raw = os.environ.get("N20_RESTORE_FRONTIER")
    if not raw:
        return None
    data = json.loads(raw)
    if set(data) != {"identity", "index", "digest"} or data["identity"]["run_id"] != os.environ.get("N20_CHECKPOINT_RUN_ID"):
        raise ValueError("Inherited recovery scope not valid")
    return read_marker(root, data["identity"], data["index"], data["digest"])


def prepare(work, identity, tasks, expected_model_scope, *, accepted_digest):
    """Validate all 20 caches before writing; never initialize a missing cache."""
    work = Path(work)
    marker, digest = c.CheckpointStore(work, identity).recover()
    if not marker or digest != accepted_digest or marker["round_index"] >= identity.rounds - 1:
        raise ValueError("Trusted frontier absent, mismatched, or already final")
    c.verify_log_prefixes(work, marker)
    index = marker["round_index"]
    if len(tasks) != identity.rounds:
        raise ValueError("Recovery must be bound to the exact task collection")
    resolved = work.resolve(strict=True)
    for node in sorted(c.NODES):
        dbp = resolved / "node-models" / node / "inferencias.sqlite"
        if dbp.resolve(strict=True) != dbp or not dbp.is_file():
            raise ValueError("Missing or redirected generation cache")
        with closing(sqlite3.connect(dbp.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ValueError("Invalid generation database")
            meta = db.execute("SELECT config FROM meta WHERE id=1").fetchone()
            if not meta or json.loads(meta[0]) != {**expected_model_scope, "node_id":node, "run_id":identity.run_id}:
                raise ValueError("Generation database belongs to a different run")
            intents = db.execute("SELECT round_index,node_id,task_id,question_hash,seed FROM generation_intents").fetchall()
            rows = db.execute("SELECT round_index,node_id,task_id,question_hash,seed FROM generations").fetchall()
            responses = {r[0] for r in db.execute("SELECT round_index FROM responses")}
        if set(intents) != set(rows):
            raise ValueError("Ambiguous or unwitnessed model invocation; cannot resume")
        complete = {r[0] for r in rows}
        if (not set(range(index+1)) <= responses or not responses <= complete
                or not complete <= set(range(index+2))):
            raise ValueError("Node caches do not match the verified committed frontier")
        for r, n, task_id, question_hash, seed in rows:
            task = tasks[r]
            expected_seed = int.from_bytes(hashlib.sha256(f"{identity.seed}:{r}:{node}".encode()).digest()[:8], "big") & (2**63-1)
            if (n, task_id, question_hash, seed) != (node, task["id"], a.sha(task["question"].encode()), expected_seed):
                raise ValueError("Question, seed or node changed in recovery")
    return {"identity":asdict(identity), "index":index, "digest":digest}, marker


def quarantine(work, marker, digest):
    """Preserve forensic copies first; never delete the initial attempt."""
    archive = work / f"interrupted-{digest[:16]}"
    archive.mkdir(exist_ok=False)
    sources = (*sorted(c.LOGS), "config.yaml", "orchestrator.log", *(f"{n}.log" for n in sorted(c.NODES)))
    evidence = {}
    for name in sources:
        raw = a.read_file(work, name)
        a.write_atomic(archive/name, raw)
        evidence[name] = a.sha(raw)
    a.write_atomic(archive/"archive-proof.json", a.json_bytes(evidence))
    for name in sorted(c.LOGS):
        prefix = (archive / name).read_bytes()[:marker["log_prefixes"][name]["bytes"]]
        a.write_atomic(work/name, prefix, replace=True)
    c.verify_log_prefixes(work, marker)
    return archive


def external_permit(path, work, *, expected, now, provider_deadline):
    """Load an explicit short-lived fence attestation from an independent Linux UID.

    This verifies a protected record, not the provider's actual fence. Only
    deployment evidence may qualify that authority; the worker cannot self-arm.
    """
    import stat
    path=Path(path)
    if not path.is_absolute() or path.resolve(strict=True)!=path:
        raise ValueError("Recovery permit must be an absolute nonredirected file")
    if path.is_relative_to(work.parent) or path.is_relative_to(Path(__file__).resolve().parents[4]):
        raise ValueError("Recovery permit cannot come from code or result storage")
    if not hasattr(os,"geteuid") or os.geteuid()==0:
        raise ValueError("Recovery requires separate unprivileged Linux runner")
    euid=os.geteuid()
    for part in (path,*path.parents):
        st=part.stat(follow_symlinks=False)
        if st.st_uid==euid or st.st_mode & (stat.S_IWGRP|stat.S_IWOTH):
            raise ValueError("Recovery permit path is not independently protected")
    if not path.is_file() or path.stat().st_size>8192:
        raise ValueError("Invalid recovery permit file")
    permits=json.loads(path.read_text("utf-8"))
    return check_permit(permits,expected=expected,now=now,provider_deadline=provider_deadline)


def check_permit(record, *, expected, now, provider_deadline):
    required={"schema","run_id","scenario_id","resource_id","git_sha","snapshot_revision",
              "marker_sha256","old_processes_fenced","issued_epoch","expires_epoch"}
    if (not isinstance(record,dict) or set(record)!=required or
        record["schema"]!="tcc-n20-local-recovery-permit/v1" or record["old_processes_fenced"] is not True
        or any(record.get(k)!=v for k,v in expected.items())
        or not c._hex(record["marker_sha256"],64)
        or type(record["issued_epoch"]) not in (int,float)
        or type(record["expires_epoch"]) not in (int,float)
        or not (now-300 <= record["issued_epoch"] <= now < record["expires_epoch"]
                <= min(record["issued_epoch"]+300,provider_deadline))):
        raise ValueError("Recovery permit is stale, unscoped, or has no independent fence attestation")
    return record["marker_sha256"]


def acquire_executor(work):
    """Linux advisory single writer; closure releases lock even on process death."""
    import fcntl
    import stat
    path=work/".executor.lock"
    fd=os.open(path,os.O_NOFOLLOW|os.O_CREAT|os.O_RDWR,0o600)
    held=os.fdopen(fd,"rb+")
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Invalid executor lock file")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BaseException:
        held.close()
        raise
    return held


def reject_unfenced_ports(urls):
    import socket
    from urllib.parse import urlsplit
    for url in urls:
        with socket.socket() as client:
            client.settimeout(.2)
            if client.connect_ex(("127.0.0.1",urlsplit(url).port))==0:
                raise ValueError("A previous or unrelated worker still holds an experiment port")
