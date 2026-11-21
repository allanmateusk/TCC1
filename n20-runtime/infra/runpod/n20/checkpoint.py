"""Durable, contiguous round checkpoints. Capture is distinct from resume."""
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
import json
import os
import re

from sistema.core.ledger import Ledger, canonical_hash
from sistema.core.protocol import apply_record
from sistema.core.replica import Replica

from .artifact_store import json_bytes, write_atomic
from .campaign import IDS


NODES = frozenset(f"node-{i}" for i in range(20))
LOGS = frozenset(("audit-events.jsonl", "leadership.csv", "per_node.csv",
                  "reputation_history.csv", "reputation-updates.jsonl", "rounds.csv"))
SCHEMA = "tcc-n20-round-checkpoint/v2"
MAX_CHECKPOINT = 16 * 1024 * 1024
ZERO = "0" * 64


def _hex(value, digits):
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{digits}}}", value) is not None


@dataclass(frozen=True)
class Identity:
    run_id: str
    experiment_id: str
    scenario_id: str
    seed: int
    rounds: int
    git_sha: str
    model_revision: str
    config_sha256: str
    tasks_sha256: str
    audit_sha256: str

    def __post_init__(self):
        if (not _hex(self.run_id, 32) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.experiment_id)
            or type(self.seed) is not int or self.seed != 0
            or type(self.rounds) is not int
            or not ((self.scenario_id == "pilot" and self.rounds == 5)
                    or (self.scenario_id in IDS and self.rounds == 50))
            or not all(_hex(x, 40) for x in (self.git_sha, self.model_revision))
            or not all(_hex(x, 64) for x in (self.config_sha256, self.tasks_sha256, self.audit_sha256))):
            raise ValueError("Unbound or invalid checkpoint identity")


def _export_state(replica):
    s = replica.state
    return {"reputation": s.snapshot(), "presence": s.presence,
            "last_leader": s.last_leader, "rotation": s.rotation}


def export_replica(replica):
    """Capture at a quiescent boundary under the future runtime's exclusive fence."""
    return json.loads(json_bytes({"node_id": replica.node_id, "members": replica.members,
                                  "head": replica.head, "records": replica.ledger.to_json(),
                                  "state": _export_state(replica)}))


def _ledger(payload, node, round_index):
    if (payload.get("node_id") != node or type(payload.get("members")) is not list
        or node not in payload["members"] or len(set(payload["members"])) != len(payload["members"])
        or not set(payload["members"]) <= NODES or type(payload.get("state")) is not dict):
        raise ValueError("Invalid replica identity or membership")
    chain = Ledger.from_json(payload["records"])
    records = chain.records
    if (chain.head != payload["head"] or not records or
        any(type(r.round_index) is not int or not 0 <= r.round_index <= round_index for r in records)
        or [r.round_index for r in records] != sorted(r.round_index for r in records)
        or [r.round_index for r in records if r.kind in ("round", "void", "calibration")]
           != list(range(round_index + 1))):
        raise ValueError("Replica is not at the checkpoint boundary")
    return chain


def replay_replica(payload, round_index, config, graph):
    """Rebuild and check actual derived replica state without calling inference."""
    node = payload["node_id"]
    if node not in NODES:
        raise ValueError("Unexpected node")
    chain = _ledger(payload, node, round_index)
    replica = Replica(node, NODES, config, graph)
    chain.replay(replica.state, apply_record)
    if canonical_hash(_export_state(replica)) != canonical_hash(payload["state"]):
        raise ValueError("Replayed replica state differs")
    replica.ledger = chain
    # Fork membership is checkpointed separately: Ledger.apply() does not rebuild it.
    replica.members = list(payload["members"])
    return replica


class CheckpointStore:
    """Single-writer store on a filesystem supporting atomic hard-link publication.

    Immutable round files are the authority; the pointer is the highest
    verified contiguous file, never a CSV length or an assumption of a completed
    model request. A temporary file is not a committed round.
    """
    def __init__(self, run_dir: Path, identity: Identity):
        if run_dir.is_symlink() or run_dir.name != identity.run_id or not run_dir.is_dir():
            raise ValueError("Checkpoint must be bound to the protected run directory")
        self.root = run_dir.resolve(strict=True)
        self.identity = identity
        self._writer_frontier = None

    def _file(self, i):
        return self.root / f"checkpoint-{i:02d}.json"

    def _verify(self, content, i, digest, prior):
        if (content.get("schema") != SCHEMA or content.get("identity") != asdict(self.identity)
            or type(content.get("round_index")) is not int or content["round_index"] != i
            or content.get("previous") != digest or set(content.get("replicas", {})) != NODES
            or set(content.get("log_prefixes", {})) != LOGS
            or set(content.get("groups", {})) != NODES
            or any(type(x) is not int or x < 0 for x in content["groups"].values())
            or type(content.get("next_gid")) is not int or content["next_gid"] <= max(content["groups"].values())):
            raise ValueError("Checkpoint identity, continuity or fields do not match")
        for node, payload in content["replicas"].items():
            chain = _ledger(payload, node, i)
            if prior:
                old = prior["replicas"][node]["records"]
                if [r.hash for r in chain.records[:len(old)]] != [r["hash"] for r in old]:
                    raise ValueError("Replica rewrites a committed chain prefix")
        for log, prefix in content["log_prefixes"].items():
            if (type(prefix.get("bytes")) is not int or not 0 < prefix["bytes"] <= 256 * 1024 * 1024 or not _hex(prefix.get("sha256"), 64)
                or (prior and prefix["bytes"] <= prior["log_prefixes"][log]["bytes"])):
                raise ValueError("Invalid log prefix frontier")

    def recover(self):
        """Return the last verified checkpoint and its digest; fail closed on a gap/corruption."""
        found = sorted(self.root.glob("checkpoint-*.json"))
        if len(found) > self.identity.rounds:
            raise ValueError("Unexpected checkpoint count")
        last, digest = None, ZERO
        for i, p in enumerate(found):
            if p != self._file(i) or p.is_symlink() or not p.is_file():
                raise ValueError("Duplicate, redirected or noncontiguous checkpoint")
            with p.open("rb") as stream:
                raw = stream.read(MAX_CHECKPOINT + 1)
            if len(raw) > MAX_CHECKPOINT:
                raise ValueError("Checkpoint too large")
            seal = json.loads(raw)
            data = seal["data"]
            observed = sha256(json_bytes(data)).hexdigest()
            if seal["sha256"] != observed:
                raise ValueError("Checkpoint integrity mismatch")
            self._verify(data, i, digest, last)
            last, digest = data, observed
        return last, digest

    def publish(self, round_index, *, replicas, groups, next_gid, log_prefixes):
        """Validate a prepared boundary then publish once; identical replays are no-ops."""
        # Only the fenced coordinator uses this instance to append. A new
        # process always scans the immutable chain independently.
        prior, prev_digest = self._writer_frontier or self.recover()
        i = 0 if prior is None else prior["round_index"] + 1
        value = dict(schema=SCHEMA, identity=asdict(self.identity), round_index=round_index,
                     previous=prev_digest if round_index == i else (prior or {}).get("previous"),
                     replicas=replicas, groups=groups, next_gid=next_gid, log_prefixes=log_prefixes)
        if type(round_index) is not int or not 0 <= round_index < self.identity.rounds:
            raise ValueError("Round index is outside the bound run")
        if round_index == i - 1 and prior == value:
            return prev_digest
        if round_index != i:
            raise ValueError("Checkpoint append is not the next contiguous round")
        self._verify(value, i, prev_digest, prior)
        checksum = sha256(json_bytes(value)).hexdigest()
        data = json_bytes({"data": value, "sha256": checksum})
        if len(data) > MAX_CHECKPOINT:
            raise ValueError("Checkpoint too large")
        write_atomic(self._file(i), data)
        self._writer_frontier=(value,checksum)
        return checksum


def capture_log_prefixes(output: Path):
    """Read the closed round prefixes after all writers have flushed that round."""
    out = {}
    root = output.resolve(strict=True)
    for name in sorted(LOGS):
        path=root / name
        if path.resolve(strict=True)!=path or not path.is_file():
            raise ValueError("Unexpected checkpoint log path")
        total=0
        digest=sha256()
        with path.open("r+b") as stream:
            os.fsync(stream.fileno())
            for data in iter(lambda:stream.read(64*1024),b""):
                digest.update(data)
                total+=len(data)
                if total>256*1024*1024:
                    raise ValueError("Checkpoint log limit exceeded")
        if not total:
            raise ValueError("Empty checkpoint log")
        out[name]={"bytes":total,"sha256":digest.hexdigest()}
    return out


def verify_log_prefixes(output: Path, checkpoint: dict):
    """Verify exactly the committed bytes; leave any interrupted suffix untouched."""
    root = output.resolve(strict=True)
    if set(checkpoint["log_prefixes"]) != LOGS:
        raise ValueError("Unexpected log names")
    for name, prefix in checkpoint["log_prefixes"].items():
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or redirected checkpoint log")
        left = prefix["bytes"]
        if type(left) is not int or not 0 < left <= 256 * 1024 * 1024:
            raise ValueError("Unexpected log prefix size")
        digest = sha256()
        with path.open("rb") as stream:
            while left:
                raw = stream.read(min(left, 64 * 1024))
                if not raw:
                    raise ValueError("Log is truncated before the committed boundary")
                digest.update(raw)
                left -= len(raw)
        if digest.hexdigest() != prefix["sha256"]:
            raise ValueError("Log prefix mismatch")
