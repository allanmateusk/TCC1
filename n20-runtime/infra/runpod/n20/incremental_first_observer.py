"""Controller-side GET-only Cloudflare/RunPod observer and first-case signer.

No CLI, remote deployment, Linux installer, token discovery or status printing.
Use only from the protected independent controller, never on the Pod.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hmac
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import tempfile
import time
import uuid
from urllib.parse import urlencode, urlsplit
from urllib.request import build_opener, HTTPSHandler, ProxyHandler, Request

from . import artifact_store as store, campaign_profiles, incremental_first_live as live
from .r2_grants import _NoRedirect
from .incremental_batch_protection import SHORT_MODE, short_window

CF_HOST = "api.cloudflare.com"
RUNPOD_HOST = "api.runpod.io"
CF_WORKER = "tcc-runpod-batch-guard-candidate"
CF_WORKFLOW = "tcc-runpod-batch-cutoff-candidate"
CF_SHORT_WORKER = "tcc-runpod-qualification-60m-guard-candidate"
CF_SHORT_WORKFLOW = "tcc-runpod-qualification-60m-cutoff-candidate"
CF_CLASS = "RunPodBatchCutoff"
ARM = "bind-exact-batch-1"
SLEEP = "absolute-batch-cutoff-1"
PLAN_SCHEMA = "tcc-incremental-first-observer-approved/v1"
SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")
MAX_RESPONSE = 128 * 1024


def _terminal_key(raw):
    if raw is None:
        return True
    if type(raw) is not str or re.fullmatch(r"[A-Za-z0-9_-]{43}",raw) is None:
        return False
    decoded=base64.urlsafe_b64decode(raw+"=")
    return len(decoded)==32 and base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")==raw


def _approved(raw, wanted):
    if (type(raw) is not bytes or not 0 < len(raw) <= 16384 or not live._hex(wanted, 64)
            or not hmac.compare_digest(store.sha(raw), wanted)):
        raise ValueError("Exact independently approved observer file digest is required")
    plan = live._load(raw)
    if type(plan) is not dict or set(plan) != {"schema", "linux_trust", "run_id", "worker_deployment_id",
                                             "observer_spki_sha256", "terminal_pub_key"}:
        raise ValueError("Wrong approved observer document shape")
    t = plan["linux_trust"]
    if (plan["schema"] != PLAN_SCHEMA or type(t) is not dict or set(t) != live.trust_fields(t)
            or not live._guid(plan["worker_deployment_id"])
            or not live._hex(plan["observer_spki_sha256"],64)
            or not _terminal_key(plan["terminal_pub_key"])
            or (t.get("qualification_mode")==SHORT_MODE and plan["terminal_pub_key"] is not None)
            or not live._hex(t["cloudflare_account_id"],32) or not live._hex(t["batch_id"],32)
            or not live._hex(plan["run_id"],32) or not live._hex(t["git_sha"],40)
            or not all(live._guid(t[k]) for k in ("workflow_id","workflow_version","worker_version"))
            or not all(type(t[k]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,127}", t[k])
                       for k in ("resource_id","owner_id","datacenter_id"))
            or not all(type(t[k]) is int and 0<t[k]<4102444800
                       for k in ("opened_at","stop_at","hard_deadline"))
            or (t.get("qualification_mode")==SHORT_MODE and not short_window(*(t[k] for k in ("opened_at","stop_at","hard_deadline"))))):
        raise ValueError("Invalid pinned observer identity, window or approval")
    return plan


def _opener():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return build_opener(ProxyHandler({}),HTTPSHandler(context=ctx),_NoRedirect()).open


def _read(opener, host, path, token, deadline):
    if (host not in {CF_HOST,RUNPOD_HOST} or not path.startswith("/") or path.startswith("//")
            or type(token) is not str or not re.fullmatch(r"[A-Za-z0-9_.~-]{16,1024}", token)):
        raise ValueError("Invalid protected read credential or exact destination")
    url = "https://" + host + path
    parsed = urlsplit(url)
    if parsed.netloc != host or parsed.scheme != "https" or parsed.fragment:
        raise ValueError("Invalid pinned HTTPS provider destination")
    request = Request(url,headers={"Authorization":"Bearer "+token,"Accept":"application/json",
                                    "Cache-Control":"no-cache"},method="GET")
    try:
        limit = deadline-time.monotonic()
        if limit<=0:
            raise TimeoutError
        with opener(request, timeout=min(limit,3)) as reply:
            if reply.status!=200 or reply.geturl()!=url or reply.headers.get_content_type()!="application/json":
                raise ValueError("Unverified provider response")
            body=bytearray()
            while True:
                if time.monotonic()>=deadline:
                    raise TimeoutError
                chunk=reply.read1(min(16384,MAX_RESPONSE+1-len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body)>MAX_RESPONSE:
                    raise ValueError("Provider response exceeds bound")
    except OSError as err:
        if hasattr(err, "close"):
            err.close()
        raise ValueError("Authenticated provider GET failed") from None
    try:
        return live._load(body)
    except (ValueError,TypeError):
        raise ValueError("Invalid provider JSON response") from None


def _result(body):
    if type(body) is not dict or body.get("success") is not True or body.get("errors")!=[]:
        raise ValueError("Cloudflare did not confirm the authenticated GET")
    if type(body.get("result")) is not dict:
        raise ValueError("Cloudflare result not independently available")
    return body["result"]


def _step(body):
    # The published endpoint describes a flat status body and the SDK describes
    # the normal result envelope. Accept either documented shape, never log previews.
    if type(body) is dict and "success" in body:
        body=_result(body)
    if (type(body) is not dict or set(body)!={"status","error","output"} or
            (body["status"],body["error"])!=("complete",None) or type(body["output"]) is not dict):
        raise ValueError("Full successful binding result not authenticated")
    return body["output"]


def _start_epoch(value):
    if (type(value) is not str or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z",value)):
        raise ValueError("Exact RunPod start timestamp not authenticated")
    return int(datetime.fromisoformat(value[:-1]+"+00:00").timestamp())


def _payload(t, instance, terminal_pub_key=None):
    return {"batch":instance,"pod":t["resource_id"],"owner":t["owner_id"],
            "datacenter":t["datacenter_id"],"name":t["pod_name"],"startedAt":live._iso(t["opened_at"]),
            "stopAt":live._iso(t["stop_at"]),"deadline":live._iso(t["hard_deadline"]),
            "gitSha":t["git_sha"],"profileSha256":t["profile_sha256"],"terminalPubKey":terminal_pub_key,
            **({"qualificationMode":SHORT_MODE} if t.get("qualification_mode")==SHORT_MODE else {})}


def _collect(plan, cf_token, pod_token):
    t=plan["linux_trust"]
    instance=str(uuid.UUID(hex=t["batch_id"]))
    base=f"/client/v4/accounts/{t['cloudflare_account_id']}"
    short=t.get("qualification_mode")==SHORT_MODE
    worker_name,workflow_name=(CF_SHORT_WORKER,CF_SHORT_WORKFLOW) if short else (CF_WORKER,CF_WORKFLOW)
    wf=f"{base}/workflows/{workflow_name}"
    instance_path=f"{wf}/instances/{instance}"
    deploy_path=f"{base}/workers/scripts/{worker_name}/deployments/{plan['worker_deployment_id']}"
    before=time.time()
    clock=time.monotonic()
    limit=clock+18
    opener=_opener()
    cf=lambda p: _read(opener,CF_HOST,p,cf_token,limit)
    pod=lambda p: _read(opener,RUNPOD_HOST,p,pod_token,limit)
    wf_info=_result(cf(wf))
    wf_ver=_result(cf(f"{wf}/versions/{t['workflow_version']}"))
    active=_result(cf(deploy_path))
    if ((wf_info.get("id"),wf_info.get("name"),wf_info.get("script_name"),wf_info.get("class_name")) !=
            (t["workflow_id"],workflow_name,worker_name,CF_CLASS)
            or wf_info.get("script_deleted",False) is not False
            or (wf_ver.get("id"),wf_ver.get("workflow_id"),wf_ver.get("class_name"),wf_ver.get("language")) !=
               (t["workflow_version"],t["workflow_id"],CF_CLASS,"javascript")
            or (active.get("id"),active.get("strategy"),active.get("versions")) !=
               (plan["worker_deployment_id"],"percentage",[{"version_id":t["worker_version"],"percentage":100}])):
        raise ValueError("Cloudflare rollout and Workflow release do not match the exact pins")
    arm=_step(cf(instance_path+"/step?"+urlencode({"name":ARM,"type":"step"})))
    payload=_payload(t,instance,plan["terminal_pub_key"])
    bind={"batch":instance,"pod":t["resource_id"],"stopAt":payload["stopAt"],
          "deadline":payload["deadline"],"gitSha":t["git_sha"],"profileSha256":t["profile_sha256"],
          "workerVersion":t["worker_version"],**({"qualificationMode":SHORT_MODE} if short else {})}
    if set(arm)!=set(bind)|{"armedAtMs"} or any(arm.get(k)!=v for k,v in bind.items()):
        raise ValueError("Full binding result lacks exact runtime Worker version or released identity")
    account=pod("/v2/account")
    resource=pod(f"/v2/pods/{t['resource_id']}")
    if (type(account) is not dict or account.get("id")!=t["owner_id"]
            or type(resource) is not dict or (resource.get("id"),resource.get("name"),resource.get("dataCenterId"),
                 resource.get("status"),resource.get("cloud")) != (t["resource_id"],t["pod_name"],
                 t["datacenter_id"],"RUNNING","SECURE")
            or type(resource.get("actions")) is not list or "stop" not in resource["actions"]
            or _start_epoch(resource.get("startedAt"))!=t["opened_at"]):
        raise ValueError("RunPod account or exact running STOP-capable Pod not proved")
    # Read the actually parked instance last. Identity is implicit in the exact
    # authenticated URL, not guessed from undocumented response identifier fields.
    record=_result(cf(instance_path))
    steps=record.get("steps")
    if (record.get("versionId")!=t["workflow_version"] or record.get("status") not in ("running","waiting")
            or "end" not in record or record["end"] is not None or "error" not in record or record["error"] is not None
            or record.get("params")!=payload or type(steps) is not list or len(steps)!=2
            or any(type(item) is not dict for item in steps)):
        raise ValueError("No exact untouched pending cutoff instance")
    a,s=steps
    if ((a.get("name"),a.get("type"))!=(ARM,"step") or a.get("success") is not True
            or (s.get("name"),s.get("type"),s.get("end"))!=(SLEEP,"sleep",payload["stopAt"])
            or s.get("finished") is not False or "error" not in s or s["error"] is not None):
        raise ValueError("Expected exactly the successful bind and pending absolute sleep")
    wall=time.time()
    elapsed=time.monotonic()-clock
    if not 0<=elapsed<18 or not 0<=wall-before<19 or abs((wall-before)-elapsed)>2:
        raise ValueError("Trusted observer clock changed or request window elapsed")
    now=int(wall)
    ev={k:t[k] for k in live.trust_fields(t)-{"durable_root","snapshot","service_uid"}}
    ev.update(schema="tcc-incremental-first-case-trusted-observation/v2",run_id=plan["run_id"],
              scenario_id=live.CASE,workflow_instance_id=instance,armed_at_ms=arm["armedAtMs"],
              observed_at=now,expires_at=now+60,status=record["status"],cloud="SECURE",
              provider_phase="RUNNING",stop_enabled=True,
              sleep={k:s[k] for k in ("name","type","finished","end","error")})
    profile=campaign_profiles.resolve("incremental-v1")
    return live.verify_evidence(ev,t,now=wall,profile=profile)


def _sign(evidence, key, openssl, pinned_spki):
    # External provisioning owns the Windows NTFS ACL and the Controller key;
    # this routine does not discover credentials, make keys or change ACLs.
    for path in (key,openssl):
        if not path.is_absolute() or path.resolve(strict=True)!=path or not path.is_file():
            raise ValueError("Use protected canonical signing key and OpenSSL paths")
    if openssl.name.lower() not in {"openssl","openssl.exe"}:
        raise ValueError("Expected trusted OpenSSL")
    if os.name=="posix" and (key.stat().st_uid!=os.getuid() or stat.S_IMODE(key.stat().st_mode)&0o077):
        raise ValueError("Observer key must be private to the trusted controller user")
    def cmd(args):
        try:
            return subprocess.run([str(openssl),*args],stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True,timeout=4).stdout
        except (OSError,subprocess.SubprocessError):
            raise ValueError("Protected observer signing unavailable") from None
    der=cmd(["pkey","-in",str(key),"-pubout","-outform","DER"])
    if (len(der)!=44 or not der.startswith(SPKI_ED25519) or
            not hmac.compare_digest(store.sha(der),pinned_spki)):
        raise ValueError("Observer signing key does not match approved Ed25519 SPKI")
    with tempfile.TemporaryDirectory(prefix="tcc-observer-public-evidence-") as scratch:
        path=Path(scratch)/"evidence.json"
        path.write_bytes(store.json_bytes(evidence))
        sig=cmd(["pkeyutl","-sign","-inkey",str(key),"-rawin","-in",str(path)])
    if len(sig)!=64:
        raise ValueError("Invalid Ed25519 signature length")
    return {"evidence":evidence,"signature_ed25519_base64":base64.b64encode(sig).decode("ascii")}


def collect_and_sign(*, approved_bytes, approved_sha256, cloudflare_read_token,
                     runpod_read_token, key: Path, openssl: Path):
    """Authenticate providers then sign; only the protected controller may export the envelope."""
    plan=_approved(approved_bytes,approved_sha256)
    ev=_collect(plan,cloudflare_read_token,runpod_read_token)
    envelope=_sign(ev,key,openssl,plan["observer_spki_sha256"])
    if not ev["observed_at"]<=time.time()<ev["expires_at"]:
        raise ValueError("Observation expired while signing")
    return envelope
