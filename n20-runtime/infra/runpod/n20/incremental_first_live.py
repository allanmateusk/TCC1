"""Default-deny Linux launcher for the first incremental BF16 case only."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from .incremental_batch_protection import SHORT_MODE, short_window
from . import artifact_store, benchmark, campaign_profiles, local_recovery, r2_verified_pilot

CASE="e4-c0-m00-p10-exact-u00-s0"
SERVICE=Path("/etc/tcc-n20-incremental")
TRUST_KEYS={"batch_id","resource_id","owner_id","datacenter_id","pod_name","git_sha","profile_sha256",
            "snapshot_revision","workflow_id","workflow_version","worker_version","cloudflare_account_id",
            "opened_at","stop_at","hard_deadline","durable_root","snapshot","peak_vram_mib","service_uid"}
SIGNED=set(TRUST_KEYS)-{"durable_root","snapshot","service_uid"} | {
    "schema","run_id","scenario_id","workflow_instance_id","armed_at_ms","observed_at","expires_at","status","cloud",
    "provider_phase","stop_enabled","sleep"}
LOCAL_ENV={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8"}
GIT="/usr/bin/git"


def trust_fields(t):
    if type(t) is not dict:
        raise ValueError("Expected protected trust mapping")
    if "qualification_mode" in t:
        if t["qualification_mode"]!=SHORT_MODE:
            raise ValueError("Unknown protected qualification mode")
        return TRUST_KEYS|{"qualification_mode"}
    return TRUST_KEYS


def _hex(x,n):
    return isinstance(x,str) and re.fullmatch(rf"[a-f0-9]{{{n}}}",x) is not None


def _guid(v):
    try:
        return isinstance(v,str) and str(uuid.UUID(v))==v
    except (ValueError,AttributeError,TypeError):
        return False


def _load(data):
    def duplicate_pairs(pairs):
        d={}
        for k,v in pairs:
            if k in d:
                raise ValueError("Duplicate field")
            d[k]=v
        return d
    return json.loads(data,object_pairs_hook=duplicate_pairs,parse_constant=lambda _k:(_ for _ in ()).throw(
        ValueError("Non-finite JSON value")))


def _iso(t):
    return datetime.fromtimestamp(t,timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")


def verify_evidence(e,t,*,now,profile):
    # Caller must first authenticate signature with protected root-owned anchor.
    if (type(e) is not dict or type(t) is not dict or set(t)!=trust_fields(t) or set(e)!=(SIGNED|(trust_fields(t)-TRUST_KEYS))
        or e["schema"]!="tcc-incremental-first-case-trusted-observation/v2" or e["scenario_id"]!=CASE):
        raise ValueError("No trusted first-case observation")
    needed=trust_fields(t)-{"durable_root","snapshot","service_uid"}
    if any(type(t[k]) is not type(e[k]) or e[k]!=t[k] for k in needed):
        raise ValueError("Mismatched provider, workflow or release binding")
    if (not _hex(e["git_sha"],40) or not _hex(e["profile_sha256"],64) or not _hex(e["cloudflare_account_id"],32)
        or not _hex(e["batch_id"],32) or not _hex(e["run_id"],32) or e["batch_id"]==e["run_id"]
        or any(not _guid(e[k]) for k in ("workflow_id","workflow_version","worker_version","workflow_instance_id"))
        or any(not isinstance(e[k],str) or not re.fullmatch("[A-Za-z0-9][A-Za-z0-9_-]{1,127}",e[k])
               for k in ("resource_id","owner_id","datacenter_id"))
        or e["pod_name"]!="tcc-n20-batch-"+e["batch_id"]):
        raise ValueError("Unrecognized provider or release identity")
    batch=uuid.UUID(hex=e["batch_id"])
    run=uuid.UUID(hex=e["run_id"])
    if batch.version!=4 or run.version!=4 or e["workflow_instance_id"]!=str(batch):
        raise ValueError("Workflow instance must equal the exact pinned batch UUID")
    if (e["profile_sha256"],e["snapshot_revision"]) != (
        campaign_profiles.digest(profile),profile["model_revision"]
    ):
        raise ValueError("Profile or snapshot does not match local fixed release")
    if any(type(e[x]) is not int for x in ("opened_at","stop_at","hard_deadline","armed_at_ms",
                                          "observed_at","expires_at","peak_vram_mib")):
        raise ValueError("Observation timing and capacity must use exact integers")
    opened_ms=e["opened_at"]*1000
    opened,stop,end=(e[k] for k in ("opened_at","stop_at","hard_deadline"))
    window=short_window(opened,stop,end) if t.get("qualification_mode")==SHORT_MODE else (
        opened>0 and 4*3600<=end-opened<=7*3600 and end-stop==300)
    if (not window
        or not (opened_ms<=e["armed_at_ms"]<=opened_ms+300_000
                and e["armed_at_ms"]<=e["observed_at"]*1000)
        or not (e["observed_at"]<=now<e["expires_at"]<=e["observed_at"]+60)
        or e["stop_at"]-now<300 or not 5900<=e["peak_vram_mib"]<=200000):
        raise ValueError("Late first arm, expired observation, insufficient cutoff margin or inadequate capacity")
    if (e["cloud"],e["provider_phase"],e["stop_enabled"])!=("SECURE","RUNNING",True) or e["stop_enabled"] is not True:
        raise ValueError("Exact RunPod state not independently confirmed")
    if e["status"] not in ("running","waiting") or type(e["sleep"]) is not dict or e["sleep"] != {
        "name":"absolute-batch-cutoff-1","type":"sleep","finished":False,"end":_iso(e["stop_at"]),"error":None
    } or e["sleep"]["finished"] is not False:
        raise ValueError("Expected one uniquely attested pending sleep at exact approved UTC")
    return e


def _root_only(path,cap):
    # No arbitrary trust path, symlink, caller-controlled directory or writable parent.
    if path.resolve(strict=True)!=path:
        raise ValueError("Controller path redirected")
    for ancestor in path.parents:
        m=ancestor.stat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022:
            raise ValueError("Controller parent must be root-owned and not writable by service")
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    with os.fdopen(fd,"rb") as handle:
        m=os.fstat(handle.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022 or not 0<m.st_size<=cap:
            raise ValueError("Expected bounded root-owned controller file")
        data=handle.read(cap+1)
    if not 0<len(data)<=cap:
        raise ValueError("Controller file too large")
    return data


def _verify_signature(evidence,signature,pem):
    with tempfile.TemporaryDirectory(prefix="n20-public-proof-") as scratch:
        d=Path(scratch)
        for f,data in (("payload",artifact_store.json_bytes(evidence)),("sig",signature),("pub",pem)):
            (d/f).write_bytes(data)
        result=subprocess.run(["/usr/bin/openssl","pkeyutl","-verify","-pubin","-inkey",str(d/"pub"),
                   "-rawin","-in",str(d/"payload"),"-sigfile",str(d/"sig")],
                  env=LOCAL_ENV,stdin=subprocess.DEVNULL,capture_output=True,timeout=5,check=False)
    if result.returncode!=0:
        raise ValueError("Independent Ed25519 observer signature invalid")


def load_verified_handoff(profile):
    if sys.platform!="linux" or os.getuid()==0 or os.getuid()!=os.geteuid():
        raise ValueError("Protected Linux non-root service launcher required")
    trust=_load(_root_only(SERVICE/"first-case-trust.json",16384))
    if type(trust) is not dict or set(trust)!=trust_fields(trust) or type(trust["service_uid"]) is not int or trust["service_uid"]!=os.getuid():
        raise ValueError("Untrusted first-case Linux service identity")
    envelope=_load(_root_only(SERVICE/"first-case-handoff.json",32768))
    if type(envelope) is not dict or set(envelope)!={"evidence","signature_ed25519_base64"}:
        raise ValueError("Expected signed dedicated controller observation (no fixtures)")
    signature=base64.b64decode(envelope["signature_ed25519_base64"],validate=True)
    if len(signature)!=64:
        raise ValueError("Wrong Ed25519 signature length")
    e=envelope["evidence"]
    pem=_root_only(SERVICE/"observer-ed25519.pem",4096)
    _verify_signature(e,signature,pem)
    verify_evidence(e,trust,now=time.time(),profile=profile)
    return e,trust


def _verify_release(git_sha):
    p=benchmark.ROOT.parent
    if p.resolve(strict=True)!=p or p.stat().st_uid!=0 or p.stat().st_mode&0o022:
        raise ValueError("Use the protected Linux release checkout")
    def cmd(*args):
        return subprocess.run([GIT,"-c",f"safe.directory={p}","-C",str(p),*args],check=True,
                              env=LOCAL_ENV,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10).stdout.strip()
    if cmd("rev-parse","HEAD")!=git_sha:
        raise ValueError("Release commit differs from the signed observation")
    cmd("diff","--quiet","HEAD","--","n20-runtime")
    if cmd("ls-files","--others","--exclude-standard","--","n20-runtime"):
        raise ValueError("Untracked sources in the release runtime")


def run():
    profile,scenarios=benchmark.load_profile("incremental-v1")
    e,trust=load_verified_handoff(profile)
    if "qualification_mode" in trust:
        raise ValueError("Short qualification requires the protected two-case warm supervisor")
    _verify_release(e["git_sha"])
    scope=campaign_profiles.scope(profile)
    scenario=scenarios[CASE]
    config,entry=benchmark.scenario_args(profile,scenario,0)
    if (entry["rounds"],profile["nodes"],entry["audit_plan"]["planned_rounds"],
        entry["audit_plan"]["simulated_absences"],entry["audit_plan"]["genesis_rounds"])!=(50,20,[10,20,30,40,50],{},[]):
        raise ValueError("Unexpected first incremental scenario mapping")
    mount=Path(trust["durable_root"])
    model=Path(trust["snapshot"])
    if not mount.is_absolute() or not model.is_absolute() or model.resolve(strict=True)!=model:
        raise ValueError("Controller must pin exact durable root and model snapshot")
    out=artifact_store.durable_run(mount,e["run_id"],repo=benchmark.ROOT.parent)
    if out.exists() or out.is_symlink():
        raise ValueError("Attempt already consumed; no retry or resume in this entry")
    local_recovery.reject_unfenced_ports(benchmark.worker.URLS.values())
    snapshot,peak,required,free,devices,torch=benchmark.verify_cuda_hardware(
        profile,model,measured_peak_gib=e["peak_vram_mib"]/1024)
    # Time and source remain bound after CUDA preflight; never reload a changed receipt mid-launch.
    verify_evidence(e,trust,now=time.time(),profile=profile)
    entry["checkpoint_capture"]={"run_id":e["run_id"],"git_sha":e["git_sha"],
                "tasks_sha256":profile["task_sha256"],"scenario_id":CASE,**scope}
    artifact_store.create_run_directory(out)
    with local_recovery.acquire_executor(out):
        artifact_store.write_atomic(out/"first-case-launch-evidence-sha256.json",artifact_store.json_bytes({
            "schema":"tcc-first-case-launch-identity/v1","run_id":e["run_id"],
            "evidence_sha256":artifact_store.sha(artifact_store.json_bytes(e))}))
        benchmark._execute_live(out,entry,config,profile,scenario,0,snapshot,50,e["git_sha"],e["run_id"],
                e["stop_at"],peak,required,free,devices,torch,None)
        data,key=r2_verified_pilot.prepare(out,e["run_id"])
    return {"status":"verified_local_no_transfer","run_id":e["run_id"],"scenario_id":CASE,
            "archive_path":str(out/artifact_store.CANDIDATE_ARCHIVE),"candidate_key":key,
            "sha256":artifact_store.sha(data),"bytes":len(data),"real_r2_verified":False,
            "next_case_authorized":False,"launch_evidence_sha256":artifact_store.sha(artifact_store.json_bytes(e)),**scope}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        result=run()
    except (MemoryError, ValueError, TypeError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        sys.exit("First incremental case not completed; inspect protected admission or durable local logs. "+type(exc).__name__)
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
