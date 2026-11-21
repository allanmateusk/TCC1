"""Safe, small, finalized N20 run evidence; no network and no raw model outputs."""
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
GENERATIONS = "verified-generations.csv"
REPUTATION_TRACE = "reputation-updates.jsonl"
METRICS = (GENERATIONS, REPUTATION_TRACE, "rounds.csv", "per_node.csv", "leadership.csv", "reputation_history.csv", "audit-events.jsonl", *LEDGERS, *RUNTIME)
MANIFEST = "live-run.json"
ARCHIVE_FILES = (MANIFEST, *METRICS)
MAX_FILE = 1024 * 1024
MAX_ZIP = 6 * 1024 * 1024
ARCHIVE = "r2-pilot.zip"
OFFICIAL_ARCHIVE = "r2-official.zip"
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
        raise ValueError("Unexpected run artifact size or unsafe content")
    return raw


def _csv(raw):
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8"), newline="")))
    if not rows or any(None in r or None in r.values() for r in rows):
        raise ValueError("Malformed required run CSV")
    return rows



def _definition(m):
    from . import campaign
    profile = json.loads(Path(__file__).with_name("profile.json").read_text(encoding="utf-8"))
    scenarios = {row["id"]: row for row in (*profile["scenarios"], profile["pilot"])}
    tag = m.get("scenario_id")
    kind = "pilot" if tag=="pilot" else "official"
    n_rounds = 5 if kind=="pilot" else 50
    if tag not in scenarios or m.get("run_kind") != kind or m.get("rounds") != n_rounds:
        raise ValueError("Unknown or inconsistent campaign phase and scenario")
    row = scenarios[tag]
    expected = campaign.plan(profile,row,0,n_rounds)
    actual = m.get("scenario",{}).get("audit_plan",{})
    if json.loads(json.dumps(expected)) != json.loads(json.dumps(actual)):
        raise ValueError("Archived audit/absence plan differs from the pinned campaign")
    if m.get("scenario",{}).get("nota") != row.get("score",profile["protocol"]["score"]):
        raise ValueError("Archived grading rule differs from scenario")
    expid = f"{'pilot' if kind=='pilot' else 'live'}-n20-r{n_rounds}-{tag}-s0"
    if m.get("experiment_id") != expid:
        raise ValueError("Wrong experiment identity")
    path = Path(__file__).resolve().parents[3] / profile["task_file"]
    raw = path.read_bytes().replace(b"\r\n",b"\n")
    if sha(raw) != profile["task_sha256"]:
        raise ValueError("Pinned task digest differs")
    task_ids = [entry["id"] for entry in json.loads(raw)["tarefas"]][:n_rounds]
    return row, expected, n_rounds, task_ids


def validate_files(files, run_id):
    if set(files) != set(ARCHIVE_FILES):
        raise ValueError("Wrong artifact set")
    m = json.loads(files[MANIFEST])
    if (
        m.get("run_id") != run_id or m.get("status") != "verified_local" or m.get("completed") is not True
        or m.get("nodes") != 20 or m.get("model_is_stand_in") is not False or m.get("dtype") != "bfloat16"
        or m.get("quantization") != "none" or m.get("seed") != 0
        or m.get("model") != "HuggingFaceTB/SmolLM3-3B"
        or m.get("model_revision") != "a07cc9a04f16550a088caea529712d1d335b0ac1"
        or not re.fullmatch(r"[0-9a-f]{40}", m.get("git_sha", ""))
    ):
        raise ValueError("Only a verified, real Smol BF16 run may be sent")
    scenario, plan, n_rounds, tasks = _definition(m)
    if m.get("verified_own_generations") != 20*n_rounds:
        raise ValueError("Wrong count of verified fresh generations")
    if m.get("artifacts_sha256") != {n: sha(files[n]) for n in METRICS}:
        raise ValueError("Artifact differs from finalized hash")
    tests, genesis, audits = (set(plan[key]) for key in ("fixed_test_rounds","genesis_rounds","planned_rounds"))
    routine = set(range(1,n_rounds+1))-genesis
    rounds = _csv(files["rounds.csv"])
    if [int(row["round_index"]) for row in rounds] != list(range(n_rounds)) or any(
        row["num_nodes"]!="20" or row["task_id"] != tasks[r-1]
        or row["calibration"]!=str(int(r in genesis)) or row["is_test"]!=str(int(r in tests))
        or row["audited"]!=str(int(r in audits)) for r,row in enumerate(rounds,1)
    ):
        raise ValueError("Wrong rounds, questions, genesis or audit coverage")
    expected_cells = Counter((r,n) for r in range(n_rounds) for n in NODES)
    cells = _csv(files["per_node.csv"])
    malicious = set(NODES[:scenario["malicious_nodes"]])
    omissions = {(r-1,n) for r,names in plan["simulated_absences"].items() for n in names}
    if Counter((int(row["round_index"]),row["node_id"]) for row in cells) != expected_cells or any(
        row["profile"]!=("malicious" if row["node_id"] in malicious else "honest")
        or row["task_id"]!=tasks[int(row["round_index"])]
        or row["mechanism"]!=scenario.get("mechanism","ema_slow_up")
        or row["answered"]!=str(int(row["answer"]!="")) for row in cells
    ):
        raise ValueError("Wrong node/round evidence")
    by_cell = {(int(row["round_index"]),row["node_id"]):row for row in cells}
    evidence = _csv(files[GENERATIONS])
    if Counter((int(row["round_index"]),row["node_id"]) for row in evidence) != expected_cells:
        raise ValueError("Generation evidence does not cover all independent generations")
    used = set()
    for row in evidence:
        index,node = int(row["round_index"]),row["node_id"]
        seed = int.from_bytes(hashlib.sha256(f"0:{index}:{node}".encode()).digest()[:8], "big") & ((1<<63)-1)
        if (row["seed"]!=str(seed) or seed in used or row["task_id"]!=tasks[index]
            or row["intentional_absence"]!=str(int((index,node) in omissions))
            or row["submitted"]!=by_cell[index,node]["answered"]
            or ((index,node) in omissions and row["submitted"]!="0")):
            raise ValueError("Inconsistent independent seed, response or omission evidence")
        used.add(seed)
    leadership = _csv(files["leadership.csv"])
    refs = {int(row["round_index"])+1:row for row in leadership if row["is_reference"]=="1"}
    if set(refs) != routine|genesis or sum(row["is_reference"]=="1" for row in leadership)!=n_rounds:
        raise ValueError("Missing or duplicate reference quorum evidence")
    for r,row in refs.items():
        confirmed,total = float(row["confirmed_mass"]),float(row["total_mass"])
        if r in genesis:
            okay = not row["leader"] and not row["auditor"] and row["outcome"]=="calibration" and confirmed==total==0 and row["oracle"]=="calibration"
        else:
            okay = (row["leader"] in NODES and row["auditor"] in (*NODES,"")
                    and row["outcome"] in {"accepted","voided"} and 0 <= confirmed <= total
                    and row["oracle"] == ("applied" if r in audits else ""))
        if not okay:
            raise ValueError("Invalid reference quorum evidence")
    hist = _csv(files["reputation_history.csv"])
    if Counter((int(row["checkpoint"]),row["node_id"]) for row in hist) != Counter(
        (r,n) for r in range(n_rounds+1) for n in NODES
    ) or any(not 0 <= float(row["reputation"]) <= 1 for row in hist):
        raise ValueError("Missing reputation evidence")
    events = [json.loads(line) for line in files["audit-events.jsonl"].splitlines()]
    if [row["round"] for row in events] != list(range(1,n_rounds+1)) or any(
        row["complete"] is not True or row["planned"] != (r in audits) or row["genesis"] != (r in genesis)
        or row["preempted"]!=(r in plan["preempted_rounds"])
        or row["simulated_absences"]!=plan["simulated_absences"].get(r,[])
        or row["oracle_by_node"] != ({n:"applied" for n in NODES} if r in audits|genesis else {})
        for r,row in enumerate(events,1)
    ):
        raise ValueError("Missing or invalid audit/genesis events")
    traces = [json.loads(line) for line in files[REPUTATION_TRACE].splitlines()]
    if [row["round_index"] for row in traces] != list(range(n_rounds)) or any(set(row["nodes"])!=set(NODES) for row in traces):
        raise ValueError("Missing round or node in authoritative reputation trace")
    from sistema.core.ledger import Ledger
    for n in NODES:
        l = json.loads(files[f"ledgers/{n}.json"])
        runtime = json.loads(files[f"node-models/{n}/model-runtime.json"])
        if (l.get("node_id")!=n or l.get("valid") is not True or not Ledger.from_json(l["records"]).verify_chain()):
            raise ValueError("Node ledger failed hash verification")
        by_hash = {r["hash"]:(i,r["kind"],r["round_index"]) for i,r in enumerate(l["records"])}
        for index,trace in enumerate(traces):
            rows = trace["nodes"][n]
            last,order = {},-1
            cell = by_cell[index,n]
            for e in rows:
                rec = by_hash.get(e["record_hash"])
                track = e["track"]
                op = e["operation"]
                alpha = e["alpha_used"]
                if (rec is None or rec[0]<order or rec[1:]!=(e["kind"],index) or e["node_id"]!=n
                    or track not in {"consensus","power"} or e["mechanism"]!=cell["mechanism"]
                    or op not in {"update","skip","snapshot_without_ema"}
                    or not all(0 <= e[k] <= 1 for k in ("before","after"))
                    or (track in last and abs(last[track]-e["before"])>2e-6)):
                    raise ValueError("Invalid reputation event provenance, state or order")
                if ((op=="update" and (alpha is None or not (0 <= alpha <= 1))) or
                    (op!="update" and alpha is not None) or
                    (op=="skip" and (e["before"]!=e["after"] or e["signal"] is not None))):
                    raise ValueError("Invalid alpha or absence in reputation trace")
                last[track],order=e["after"],rec[0]
            scores=[e for e in rows if e["track"]=="consensus"]
            scalar=[e["alpha_used"] for e in scores if e["operation"]!="skip"]
            expected_scalar=scalar[0] if len(scalar)==1 else None
            got_scalar=float(cell["alpha_used"]) if cell["alpha_used"]!="" else None
            if got_scalar!=expected_scalar or (scores and (
                abs(float(cell["reputation_before"])-scores[0]["before"])>2e-6 or
                abs(float(cell["reputation_after"])-scores[-1]["after"])>2e-6
            )) or (not scores and cell["reputation_before"]!=cell["reputation_after"]):
                raise ValueError("CSV reputation/alpha disagrees with the applied trace")
        for kinds, expected in (({"round","void"},routine),({"calibration"},genesis),({"oracle"},audits)):
            observed = [r["round_index"]+1 for r in l["records"] if r["kind"] in kinds]
            if observed != sorted(expected):
                raise ValueError("Node ledger has wrong rounds or truth record")
        if (
            runtime.get("node_id") != n or runtime.get("run_id") != m.get("experiment_id")
            or runtime.get("loaded_model_dtype") != "torch.bfloat16" or runtime.get("quantization") != "none"
            or runtime.get("dtype") != "bfloat16" or type(runtime.get("peak_reserved_bytes")) is not int
            or runtime["peak_reserved_bytes"] <= 0 or type(runtime.get("kv_cache")) is not bool
        ):
            raise ValueError("Node runtime does not prove actual BF16 loading")
    return {"run_kind":m["run_kind"],"scenario_id":m["scenario_id"],"rounds":n_rounds,"nodes":20,
            "verified_own_generations":20*n_rounds,"verified_ledgers":20,"verified_quorum_rounds":len(routine),
            "verified_audit_rounds":sorted(audits),"verified_genesis_rounds":sorted(genesis),
            "verified_intentional_absences":len(omissions)}


def _seal_generation_evidence(root, manifest):
    root = root.resolve(strict=True)
    from contextlib import closing
    import sqlite3
    _, plan, n_rounds, _ = _definition(manifest)
    out = io.StringIO(newline="")
    cols = ("round_index","node_id","task_id","seed","submitted","intentional_absence")
    writer = csv.DictWriter(out, fieldnames=cols)
    writer.writeheader()
    for n in NODES:
        db = root/"node-models"/n/"inferencias.sqlite"
        if db.resolve(strict=True) != db or not db.is_file():
            raise ValueError("Generation evidence source is not the expected quiescent DB")
        with closing(sqlite3.connect(db.as_uri()+"?mode=ro", uri=True)) as src:
            g = src.execute("""SELECT g.round_index,g.node_id,g.task_id,g.seed,r.answer
                             FROM generations g JOIN responses r USING(round_index)
                             ORDER BY g.round_index""").fetchall()
        if [r[0] for r in g] != list(range(n_rounds)) or any(row[1]!=n for row in g):
            raise ValueError("Missing independently generated or submitted record")
        for index,node,task,seed,answer in g:
            cited = json.loads(answer) is not None
            intentional = node in plan["simulated_absences"].get(index+1, ())
            writer.writerow(dict(zip(cols,(index,node,task,seed,int(cited),int(intentional)),strict=True)))
    write_atomic(root/GENERATIONS,out.getvalue().encode("utf-8"))


def finalize_run(root, manifest):
    _seal_generation_evidence(root,manifest)
    files = {name:read_file(root,name) for name in METRICS}
    manifest = {**manifest,"artifacts_sha256":{n:sha(raw) for n,raw in files.items()}}
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


def verify_archive(data, run_id, *, expected_manifest=None):
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
    if expected_manifest is not None and files[MANIFEST] != expected_manifest:
        raise ValueError("ZIP does not match the finalized local manifest")
    if any(SENSITIVE.search(raw) for raw in files.values()):
        raise ValueError("Unexpected credential-shaped content in download")
    return validate_files(files, run_id)
