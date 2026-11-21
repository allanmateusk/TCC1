"""Prepare an offline non-authorizing Cloudflare cutoff proposal."""
from __future__ import annotations

import argparse
from dataclasses import fields
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

from .incremental_batch_protection import BatchProtection

REPO = Path(__file__).resolve().parents[4]
GUARD = Path(__file__).with_name("cloudflare_batch_cutoff")
FILES = ("wrangler.jsonc", "src/index.mjs", "src/batch-guard.mjs", "src/runpod-transport.mjs")
SAFE_KEYS = {"resource_id","owner_id","datacenter_id","pod_name","batch_id","status","cloud","stop_enabled","observed_at"}


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")


def facts_hash(repo=REPO, guard=GUARD):
    files=[guard/name for name in FILES]
    rel=[p.relative_to(repo).as_posix() for p in files]
    args=["git","-C",str(repo)]
    def read(cmd):
        return subprocess.run(args+cmd,capture_output=True,check=True,text=True,timeout=10).stdout.strip()
    head=read(["rev-parse","HEAD"])
    if not re.fullmatch(r"[0-9a-f]{40}",head):
        raise ValueError("Release revision unavailable")
    read(["diff","--quiet","HEAD","--",*rel])
    read(["ls-files","--error-unmatch","--",*rel])
    if any(p.is_symlink() or not p.is_file() for p in files):
        raise ValueError("Expected original checked-in guard files")
    if not re.search(rb"\bconst APPROVED\s*=\s*null\s*;",files[1].read_bytes()):
        raise ValueError("Source is not disarmed")
    config=json.loads(files[0].read_bytes())
    if (config["name"]!="tcc-runpod-batch-guard-candidate" or config["workers_dev"] is not False
        or config["preview_urls"] is not False or config["routes"]!=[] or "triggers" in config
        or "vars" in config or [w["name"] for w in config["workflows"]] !=
        ["tcc-runpod-batch-cutoff-candidate","tcc-runpod-batch-terminal-candidate"]):
        raise ValueError("Unexpected live wiring or route")
    return head,{name:hashlib.sha256(p.read_bytes()).hexdigest() for name,p in zip(FILES,files)}


def prepare(data, *, release, source_hashes, now):
    if type(data) is not dict or set(data)!={"protection","operator_observation"}:
        raise ValueError("Use only the documented input fields")
    spec,obs=data["protection"],data["operator_observation"]
    if type(spec) is not dict or set(spec)!={f.name for f in fields(BatchProtection)}:
        raise ValueError("Missing or unsupported protection fields")
    if type(obs) is not dict or set(obs)!=SAFE_KEYS:
        raise ValueError("Missing or unsupported operator observation fields")
    p=BatchProtection(**spec)
    batch=uuid.UUID(hex=p.batch_id)
    if batch.version!=4 or batch.variant!=uuid.RFC_4122:
        raise ValueError("Use an exact version-4 batch UUID from approved planning")
    if p.git_sha!=release:
        raise ValueError("Git SHA doesn't match the current checked-in release")
    if type(now) is not int or type(obs["observed_at"]) is not int or not (
         p.opened_at<=obs["observed_at"]<=now<=p.opened_at+300 and now-obs["observed_at"]<=60):
        raise ValueError("Operator observation must be recent and within five minutes of start")
    for key in ("resource_id","owner_id","datacenter_id","pod_name","batch_id"):
        if obs[key]!=getattr(p,key):
            raise ValueError("Operator observation does not match exact bound Pod and batch")
    if obs["status"]!="RUNNING" or obs["cloud"]!="SECURE" or obs["stop_enabled"] is not True:
        raise ValueError("Operator must confirm a running Secure Cloud Pod with STOP available")
    if p.hard_deadline-p.stop_at!=300:
        raise ValueError("Use the shared five-minute shutdown verification reserve")
    binding={"batch":str(batch),"pod":p.resource_id,"owner":p.owner_id,"datacenter":p.datacenter_id,
        "name":p.pod_name,"startedAt":iso(p.opened_at),"stopAt":iso(p.stop_at),"deadline":iso(p.hard_deadline),
        "gitSha":p.git_sha,"profileSha256":p.profile_sha256,"terminalPubKey":None}
    return {
        "schema":"tcc-cloudflare-batch-proposal-offline/v1","state":"unarmed_draft",
        "source_modified":False,"authenticated_provider_observed":False,"eligible_for_live_admission":False,
        "real_stop_verified":False,"manual_observation_as_of":iso(obs["observed_at"]),
        "source_sha256":source_hashes,"protection_sha256":p.digest,
        "nominal_cost_ceiling_microusd":p.cost_ceiling_microusd,"approved_cap_microusd":p.approved_cap_microusd,
        "work_to_verify_separately":["exact provider account and pod", "exact Cloudflare rollout and workflow version",
           "unfinished absolute-batch-cutoff exact UTC","protected Linux admission","independent STOP/EXITED response"],
        "workflow_instance_id_proposal":str(batch),"unarmed_payload_proposal":binding,
    }


def no_duplicates(pairs):
    out={}
    for k,v in pairs:
        if k in out:
            raise ValueError("Duplicate input fields are not allowed")
        out[k]=v
    return out


def write_proposal(path, body, repo=REPO):
    if not path.is_absolute():
        raise ValueError("Use an absolute path outside the checkout")
    parent=path.parent.resolve(strict=True)
    if parent.is_relative_to(repo.resolve()) or path.suffix!=".json" or path.name in (
            "live-run.json","approved-plan.json","controller-state.json","r2-verified.json"):
        raise ValueError("Use a new offline JSON filename outside the checkout")
    dest=parent/path.name
    fd,name=tempfile.mkstemp(prefix=".tcc-offline-proposal-",dir=parent)
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as fh:
            json.dump(body,fh,indent=2,sort_keys=True,allow_nan=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.link(name,dest)  # atomic and exclusive; never replace prior evidence
    finally:
        Path(name).unlink(missing_ok=True)


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--operator-facts",type=Path,required=True)
    cli.add_argument("--out",type=Path,required=True)
    a=cli.parse_args()
    try:
        if a.operator_facts.is_symlink() or not a.operator_facts.is_file() or a.operator_facts.stat().st_size>16384:
            raise ValueError("Expected a small local JSON file, without credentials")
        facts=json.loads(a.operator_facts.read_text(encoding="utf-8"),object_pairs_hook=no_duplicates)
        head,hashes=facts_hash()
        result=prepare(facts,release=head,source_hashes=hashes,now=int(time.time()))
        write_proposal(a.out,result)
    except (ValueError,TypeError,KeyError,OSError,subprocess.SubprocessError):
        # Don't print supplied contents or import access/secret values.
        cli.exit(2,"Offline proposal not written: check exact scope, approved economics, observation freshness, and a new output path.\n")
    print("offline_proposal_written; unarmed; no_live_admission; no_external_actions")


if __name__=="__main__":
    main()
