"""Two-case Linux warm worker seam, default-deny without protected authorities."""
from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path
import time

from . import artifact_store as store, benchmark, campaign_profiles as cp, incremental_first_live as first
from . import local_recovery, r2_verified_pilot
from .incremental_batch_protection import BatchProtection
from .incremental_campaign import IDS
from .incremental_warm_journal import Authorities, GET, LEASE, Scope
from sistema.scripts.resident_pool import ResidentPool

COMMITTED="tcc-warm-controller-committed-transition/v1"
COMMITTED_FIELDS={"schema","scope_sha256","receipt_sha256","lease_sha256","index",
                  "run_id","committed_at","expires_at"}
POLICY="tcc-qualified-two-case-residency/v1"


@dataclass(frozen=True)
class Seal:
    run_id: str
    scenario_id: str
    sha256: str
    size: int


def verify_transition(authorities, relay, *, prior, seal, now):
    """Recheck controller's signed one-shot relay against local immutable seal."""
    if type(authorities) is not Authorities or type(relay) is not dict or set(relay)!={"readback","next_lease","committed"} \
            or type(seal) is not Seal or prior["index"]!=0 or seal.scenario_id!=IDS[0]:
        raise ValueError("Only a committed transition from case one to case two is supported")
    readback,readback_sha=authorities.validate(relay["readback"],GET,now)
    next_case,lease_sha=authorities.validate(relay["next_lease"],LEASE,now)
    commit=relay["committed"]
    if (type(commit) is not dict or set(commit)!={"evidence","signature_ed25519_base64"}
            or type(commit["evidence"]) is not dict or set(commit["evidence"])!=COMMITTED_FIELDS):
        raise ValueError("Missing signed controller commit")
    ev=commit["evidence"]
    if ((ev["schema"],ev["scope_sha256"],ev["receipt_sha256"],ev["lease_sha256"],ev["index"],ev["run_id"])
        != (COMMITTED,authorities.scope.digest,readback_sha,lease_sha,1,next_case["run_id"])
        or type(ev["index"]) is not int or type(ev["committed_at"]) is not int or type(ev["expires_at"]) is not int
        or not next_case["observed_at"]<=ev["committed_at"]<=now<ev["expires_at"]
               <=min(readback["expires_at"],next_case["expires_at"],ev["committed_at"]+60)
        or not readback["observed_at"]<=next_case["observed_at"] or not now<prior["case_deadline"]
        or (readback["index"],readback["run_id"],readback["scenario_id"],readback["sha256"],readback["size"])
           != (0,prior["run_id"],seal.scenario_id,seal.sha256,seal.size)
        or seal.run_id!=prior["run_id"] or next_case["index"]!=1 or next_case["run_id"]==prior["run_id"]
        or next_case["prior_readback_sha256"]!=readback_sha):
        raise ValueError("Committed transition does not match the independently verified local seal/next lease")
    authorities.verify_signature(ev,commit["signature_ed25519_base64"],kind=LEASE)
    return next_case


def _protected(name,cap=32768):
    return first._root_only(first.SERVICE/name,cap)


class WarmAdmission:
    """No application-visible constructor flags or mock authorization."""

    def __init__(self,profile):
        observation,trust=first.load_verified_handoff(profile)
        first._verify_release(observation["git_sha"])
        policy=first._load(_protected("warm-resident-release.json"))
        if type(policy) is not dict or set(policy)!={"schema","scope","approved_scope_sha256","qualifier_report_sha256"} \
            or policy["schema"]!=POLICY or not first._hex(policy["qualifier_report_sha256"],64):
            raise ValueError("Independent resident qualification not installed")
        raw=policy["scope"]
        if type(raw) is not dict or set(raw)!={f.name for f in fields(Scope)}:
            raise ValueError("Unexpected protected warm scope")
        scope=Scope(**{**raw,"allocation":BatchProtection(**raw["allocation"])})
        p=scope.allocation
        if policy["approved_scope_sha256"]!=scope.digest or (
            p.batch_id,p.resource_id,p.owner_id,p.datacenter_id,p.pod_name,p.git_sha,p.profile_sha256,
            p.opened_at,p.stop_at,p.hard_deadline,scope.guard_instance_id,scope.guard_version_id,scope.worker_version_id
        ) != (
            observation["batch_id"],observation["resource_id"],observation["owner_id"],observation["datacenter_id"],
            observation["pod_name"],observation["git_sha"],observation["profile_sha256"],observation["opened_at"],
            observation["stop_at"],observation["hard_deadline"],observation["workflow_instance_id"],
            observation["workflow_version"],observation["worker_version"]
        ):
            raise ValueError("Qualified warm release and initial signed guard do not match")
        self.authorities=Authorities(scope,_protected("warm-lease-ed25519.pem",4096),
                                    _protected("warm-get-ed25519.pem",4096),Path("/usr/bin/openssl").resolve(strict=True))
        self.initial,self.initial_trust=observation,trust
        lease,_=self.authorities.validate(first._load(_protected("warm-first-lease.json")),LEASE,time.time())
        if (lease["index"],lease["run_id"],lease["guard_observation_sha256"]) != (
            0,observation["run_id"],store.sha(store.json_bytes(observation))
        ):
            raise ValueError("Initial warm lease does not anchor to the genuine guard observation")
        self.current=lease
        self.released=None

    @property
    def cutoff(self):
        return self.authorities.scope.allocation.stop_at

    def check(self):
        if time.time()>=min(self.current["case_deadline"],self.cutoff):
            raise InterruptedError("External warm case deadline elapsed")
        # A protected external cancellation marker stops local computation;
        # it cannot create or extend an authorization.
        if (first.SERVICE/"cancel-warm-batch").exists():
            raise InterruptedError("Independent operator requested local cancellation")

    def assert_identity(self,identity,deadline):
        self.check()
        s=self.authorities.scope.allocation
        if (identity.scenario_id,identity.run_id,identity.campaign_id,identity.profile_sha256,identity.git_sha,
                identity.rounds,identity.seed,deadline) != (
            self.current["scenario_id"],self.current["run_id"],cp.INCREMENTAL_SCHEMA,s.profile_sha256,s.git_sha,
            50,0,self.current["case_deadline"]):
            raise ValueError("Exact active warm lease does not match resident request")

    def await_next(self,seal,path):
        while True:
            self.check()
            try:
                relay=first._load(_protected("warm-next-transition.json"))
            except FileNotFoundError:
                time.sleep(.5)
                continue
            body=store.read_file(path,store.CANDIDATE_ARCHIVE)
            if (store.sha(body),len(body))!=(seal.sha256,seal.size):
                raise ValueError("Sealed local result changed after finalization")
            next_case=verify_transition(self.authorities,relay,prior=self.current,seal=seal,now=time.time())
            self.released=(self.current["run_id"],self.current["scenario_id"])
            self.current=next_case
            return next_case

    def matches_release(self,previous):
        self.check()
        return self.current["index"]==1 and self.released is not None and self.released==previous


def _run_case(pool,admission,profile,scenarios,snapshot,root):
    e=admission.current
    admission.check()
    sid=e["scenario_id"]
    cfg,entry=benchmark.scenario_args(profile,scenarios[sid],0)
    if (entry["rounds"],profile["nodes"],e["index"],sid)!=(50,20,IDS.index(sid),IDS[e["index"]]):
        raise ValueError("Unexpected reviewed scenario identity")
    run=e["run_id"]
    scope=cp.scope(profile)
    a=admission.authorities.scope.allocation
    out=store.durable_run(root,run,repo=benchmark.ROOT.parent)
    if out.exists() or out.is_symlink():
        raise ValueError("Attempt already exists; no automatic restart")
    local_recovery.reject_unfenced_ports(benchmark.worker.URLS.values())
    snapshot,peak,required,free,devices,torch=benchmark.verify_cuda_hardware(profile,snapshot,
           resident_pool=pool,measured_peak_gib=admission.initial["peak_vram_mib"]/1024)
    admission.check()
    if time.time()>=e["expires_at"]:
        raise ValueError("New lease expired before launch")
    entry["checkpoint_capture"]={"run_id":run,"git_sha":a.git_sha,"tasks_sha256":profile["task_sha256"],
                                 "scenario_id":sid,**scope}
    store.create_run_directory(out)
    with local_recovery.acquire_executor(out):
        # Preserve the exact marker consumed by the separately scoped R2 sealer.
        store.write_atomic(out/"first-case-launch-evidence-sha256.json",store.json_bytes({
            "schema":"tcc-first-case-launch-identity/v1","run_id":run,
            "evidence_sha256":e["guard_observation_sha256"]}))
        benchmark._execute_live(out,entry,cfg,profile,scenarios[sid],0,snapshot,50,a.git_sha,run,
                                e["case_deadline"],peak,required,free,devices,torch,None,
                                resident_pool=pool,warm_case=admission)
        raw,_=r2_verified_pilot.prepare(out,run)
    return Seal(run,sid,store.sha(raw),len(raw)),out


def supervise_two_cases():
    """Protected callable only; no public CLI, deploy, provider or R2-write adapter."""
    profile,scenarios=benchmark.load_profile("incremental-v1")
    admission=WarmAdmission(profile)  # deny before consulting CUDA or opening a resident
    root=Path(admission.initial_trust["durable_root"])
    snapshot=Path(admission.initial_trust["snapshot"])
    if (not root.is_absolute() or root.resolve(strict=True)!=root or not snapshot.is_absolute()
        or snapshot.resolve(strict=True)!=snapshot or not snapshot.is_dir()):
        raise ValueError("Exact durable mount and pinned local model snapshot needed")
    with ResidentPool(root,deadline=admission.cutoff,incremental_admission=admission) as pool:
        seal_one,out_one=_run_case(pool,admission,profile,scenarios,snapshot,root)
        admission.await_next(seal_one,out_one)
        pool._accept_incremental_readback(admission)
        seal_two,out_two=_run_case(pool,admission,profile,scenarios,snapshot,root)
    return {"status":"two_cases_verified_local","seals":[(seal_one,out_one),(seal_two,out_two)],
            "first_independent_get_verified":True,"second_independent_get_verified":False,
            "next_case_authorized":False,"provider_stop_asserted":False}
