"""Safe, small, finalized N20 pilot evidence; no network and no raw model outputs."""
from __future__ import annotations

import csv
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
NODES = tuple(f"node-{n}" for n in range(20))
RUNTIME = tuple(f"node-models/{n}/model-runtime.json" for n in NODES)
LEDGERS = tuple(f"ledgers/{n}.json" for n in NODES)
METRICS = ("rounds.csv", "per_node.csv", "leadership.csv", "reputation_history.csv", "audit-events.jsonl", *LEDGERS, *RUNTIME)
MANIFEST = "live-run.json"
ARCHIVE_FILES = (MANIFEST, *METRICS)
MAX_FILE = 256 * 1024
MAX_ZIP = 2 * 1024 * 1024
ARCHIVE = "r2-pilot.zip"
DOWNLOADED = "r2-downloaded.zip"
RECEIPT = "r2-verified.json"
SENSITIVE = re.compile(
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    rb"\bgh[pousr]_[A-Za-z0-9]{24,}|\bgithub_pat_[A-Za-z0-9_]{30,}|X-Amz-(?:Credential|Signature|Security-Token)", re.I
)


def durable_run(root, run_id, *, repo=None):
    """Require an existing mount root, not its creation or an implicit temp path."""
    if not RUN_ID.fullmatch(run_id or ""):
        raise ValueError("Run ID must be 32 lowercase hex characters")
    if root is None or not Path(root).is_absolute():
        raise ValueError("An absolute, existing durable mount is required")
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or (repo and root.is_relative_to(Path(repo).resolve())):
        raise ValueError("Durable mount must be outside the Git worktree")
    path = root / run_id
    if path.is_symlink() or path.resolve() != path:
        raise ValueError("The run directory must be a direct child, not a redirect")
    return path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _sync_dir(root):
    if os.name == "posix":
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write_atomic(path, raw, *, replace=False):
    """Fsync content, then publish an atomic name; default no replacement."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing a symlink artifact")
    fd, scratch = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(scratch, path)
        else:
            try:
                os.link(scratch, path)
            except FileExistsError:
                if path.is_symlink() or not path.is_file() or path.stat().st_size != len(raw) or path.read_bytes() != raw:
                    raise ValueError(f"Refusing to overwrite distinct {path.name}") from None
        _sync_dir(path.parent)
    finally:
        Path(scratch).unlink(missing_ok=True)


def create_run_directory(path):
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    _sync_dir(path.parent)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def read_file(root, name):
    root = root.resolve(strict=True)
    path = root / name
    if path.resolve(strict=True) != path or not path.is_file():
        raise ValueError("Artifact redirected or missing")
    with path.open("rb") as source:
        raw = source.read(MAX_FILE + 1)
    if not raw or len(raw) > MAX_FILE or SENSITIVE.search(raw):
        raise ValueError("Unexpected pilot artifact size or unsafe content")
    return raw


def _csv(raw):
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8"), newline="")))
    if not rows or any(None in r or None in r.values() for r in rows):
        raise ValueError("Malformed required pilot CSV")
    return rows


def validate_files(files, run_id):
    if set(files) != set(ARCHIVE_FILES):
        raise ValueError("Wrong artifact set")
    m = json.loads(files[MANIFEST])
    if (
        m.get("run_id") != run_id or m.get("status") != "verified_local" or m.get("completed") is not True
        or m.get("nodes") != 20 or m.get("rounds") != 5 or m.get("run_kind") != "pilot"
        or m.get("verified_own_generations") != 100 or m.get("scenario_id") != "pilot"
        or m.get("model_is_stand_in") is not False or m.get("dtype") != "bfloat16"
        or m.get("quantization") != "none" or m.get("seed") != 0
        or m.get("model") != "HuggingFaceTB/SmolLM3-3B"
        or m.get("model_revision") != "a07cc9a04f16550a088caea529712d1d335b0ac1"
        or not re.fullmatch(r"[0-9a-f]{40}", m.get("git_sha", ""))
    ):
        raise ValueError("Only a verified, real Smol BF16 20x5 pilot may be sent")
    if m.get("pilot_artifacts_sha256") != {n: sha(files[n]) for n in METRICS}:
        raise ValueError("Pilot artifact differs from finalized hash")
    rounds = _csv(files["rounds.csv"])
    if [int(row["round_index"]) for row in rounds] != list(range(5)) or any(
        row["num_nodes"]!="20" or row["calibration"]!="0" or row["is_test"]!="0"
        or row["audited"] != ("1" if r==2 else "0") for r,row in enumerate(rounds)
    ):
        raise ValueError("Wrong pilot rounds or audit coverage")
    cells = _csv(files["per_node.csv"])
    if Counter((int(row["round_index"]),row["node_id"]) for row in cells) != Counter(
        (r,n) for r in range(5) for n in NODES
    ) or any(row["profile"]!="honest" or row["task_id"]!=rounds[int(row["round_index"])]["task_id"] for row in cells):
        raise ValueError("Wrong pilot node/round evidence")
    leadership = _csv(files["leadership.csv"])
    refs = [row for row in leadership if row["is_reference"]=="1"]
    if [int(row["round_index"]) for row in refs] != list(range(5)) or any(
        row["leader"] not in NODES or row["auditor"] not in NODES or row["outcome"] not in {"accepted","voided"}
        or not 0 <= float(row["confirmed_mass"]) <= float(row["total_mass"])
        or not float(row["total_mass"]) > 0
        or row["oracle"] != ("applied" if row["round_index"]=="2" else "") for row in refs
    ):
        raise ValueError("Missing or invalid reference quorum evidence")
    hist = _csv(files["reputation_history.csv"])
    if Counter((int(row["checkpoint"]),row["node_id"]) for row in hist) != Counter(
        (r,n) for r in range(6) for n in NODES
    ) or any(not 0 <= float(row["reputation"]) <= 1 for row in hist):
        raise ValueError("Missing pilot reputation evidence")
    events = [json.loads(line) for line in files["audit-events.jsonl"].splitlines()]
    if [row["round"] for row in events] != list(range(1,6)) or any(
        row["complete"] is not True or row["planned"] != (r==3) or row["genesis"] or row["preempted"]
        or row["simulated_absences"] or row["oracle_by_node"] != ({n:"applied" for n in NODES} if r==3 else {})
        for r,row in enumerate(events,1)
    ):
        raise ValueError("Missing or invalid pilot audit events")
    from sistema.core.ledger import Ledger
    for n in NODES:
        l = json.loads(files[f"ledgers/{n}.json"])
        runtime = json.loads(files[f"node-models/{n}/model-runtime.json"])
        if (l.get("node_id")!=n or l.get("valid") is not True
            or not Ledger.from_json(l["records"]).verify_chain()):
            raise ValueError("Pilot node ledger failed hash verification")
        if ([r["round_index"] for r in l["records"] if r["kind"]=="oracle"] != [2]
            or [r["round_index"] for r in l["records"] if r["kind"] in {"round","void"}] != list(range(5))):
            raise ValueError("Pilot node ledger has wrong rounds or oracle record")
        if (
            runtime.get("node_id") != n or runtime.get("run_id") != m.get("experiment_id")
            or runtime.get("loaded_model_dtype") != "torch.bfloat16" or runtime.get("quantization") != "none"
            or runtime.get("dtype") != "bfloat16" or type(runtime.get("peak_reserved_bytes")) is not int
            or runtime["peak_reserved_bytes"] <= 0 or type(runtime.get("kv_cache")) is not bool
        ):
            raise ValueError("Pilot node runtime does not prove actual BF16 loading")
    return {"rounds":5, "nodes":20, "verified_own_generations":100, "verified_ledgers":20,
            "verified_quorum_rounds":5, "verified_audit_rounds":[3]}


def finalize_pilot(root, manifest):
    files = {name:read_file(root,name) for name in METRICS}
    manifest = {**manifest,"pilot_artifacts_sha256":{n:sha(raw) for n,raw in files.items()}}
    validate_files({**files,MANIFEST:json_bytes(manifest)}, manifest["run_id"])
    return manifest


def build_archive(root, run_id):
    files = {name:read_file(root,name) for name in ARCHIVE_FILES}
    validate_files(files, run_id)
    buf = io.BytesIO()
    with ZipFile(buf,"w") as archive:
        for name in ARCHIVE_FILES:
            archive.writestr(ZipInfo(name),files[name],compress_type=ZIP_DEFLATED)
    return buf.getvalue()


def verify_archive(data, run_id):
    if not 0 < len(data) <= MAX_ZIP:
        raise ValueError("Wrong ZIP size")
    with ZipFile(io.BytesIO(data)) as archive:
        info = archive.infolist()
        if (sorted(i.filename for i in info) != sorted(ARCHIVE_FILES)
            or any(not 0 < i.file_size <= MAX_FILE or (i.external_attr >> 16) & 0o170000 == 0o120000 for i in info)):
            raise ValueError("Unrecognized ZIP members or sizes")
        sizes = sum(i.file_size for i in info)
        if sizes > 4*MAX_ZIP:
            raise ValueError("Unrecognized uncompressed size")
        files = {i.filename:archive.read(i) for i in info}
    if any(SENSITIVE.search(raw) for raw in files.values()):
        raise ValueError("Unexpected credential-shaped content in download")
    return validate_files(files, run_id)
