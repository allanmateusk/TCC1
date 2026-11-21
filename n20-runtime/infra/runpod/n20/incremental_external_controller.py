"""Independent first-to-second-case controller; publication and launch remain separate.

No CLI, token storage, Pod launch, STOP, or unsigned/mocked receipt promotion.
The deployment owns ACLs and role-separated credentials outside the Pod.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import math
from pathlib import Path
import time

from . import artifact_store as store, incremental_first_live as live
from . import incremental_first_observer as observer, incremental_first_transfer as transfer
from . import incremental_warm_journal as warm

COMMITTED="tcc-warm-controller-committed-transition/v1"
APPROVAL="tcc-warm-flight-controller-approval/v1"
FIRST_FILE="controller-first.json"
SEAL_FILE="controller-first-seal.json"
RELAY_FILE="controller-second-relay.json"
SECOND_SEAL_FILE="controller-second-seal.json"
FINAL_FILE="controller-two-case-terminal.json"
QUALIFIED="tcc-warm-two-case-qualification-terminal/v1"


@dataclass(frozen=True)
class Controller:
    journal: warm.Journal
    state_dir: Path
    approved_observer: bytes
    approved_observer_sha256: str
    endpoint: str
    publication_spki_sha256: str
    approval_sha256: str
    observer_key: Path
    lease_key: Path
    readback_key: Path

    def __post_init__(self):
        if type(self.journal) is not warm.Journal:
            raise ValueError("Use only the exact protected journal")
        d=transfer._protected_directory(self.state_dir)
        if self.journal.path.parent!=d:
            raise ValueError("Keep journal and control files on the exact protected controller mount")
        p=self._plan()
        t=p["linux_trust"]
        s=self.journal.authorities.scope
        a=s.allocation
        binds=("batch_id","resource_id","owner_id","datacenter_id","pod_name","git_sha",
               "profile_sha256","opened_at","stop_at","hard_deadline")
        if (any(t[name]!=getattr(a,name) for name in binds)
                or (t["workflow_version"],t["worker_version"])!=(s.guard_version_id,s.worker_version_id)
                or not warm._uuid(p["run_id"]) or p["run_id"]==a.batch_id):
            raise ValueError("Cold observer approval and warm scope do not match")
        pins=(p["observer_spki_sha256"],s.lease_key_sha256,s.readback_key_sha256,self.publication_spki_sha256)
        if len(set(pins))!=4 or not all(warm._hex(k,64) for k in pins):
            raise ValueError("Observer, lease, readback and publication keys must be distinct")
        transfer.r2_grants.validate_config({"endpoint":self.endpoint,"bucket":"tcc",
                                             "region":"auto","prefix":"tcc/prod"},"official")
        approval={"schema":APPROVAL,"scope_sha256":s.digest,"observer_sha256":self.approved_observer_sha256,
                  "endpoint":self.endpoint,"publication_spki_sha256":self.publication_spki_sha256}
        if (not warm._hex(self.approval_sha256,64)
                or not hmac.compare_digest(store.sha(store.json_bytes(approval)),self.approval_sha256)):
            raise ValueError("Independent controller approval pin is absent or changed")

    @property
    def _scope(self):
        return self.journal.authorities.scope

    def _plan(self):
        return observer._approved(self.approved_observer,self.approved_observer_sha256)

    def _now(self):
        # Controller signs only with its own host clock, not a worker, transport,
        # or injected journal clock. Journal independently checks on commit.
        now=time.time()
        if not 0<now<self._scope.allocation.stop_at:
            raise ValueError("Guarded execution window expired")
        return now

    def _sign(self,record,kind):
        a=self.journal.authorities
        key,pin=(self.readback_key,self._scope.readback_key_sha256) if kind==warm.GET else (
            self.lease_key,self._scope.lease_key_sha256)
        return observer._sign(record,key,a.openssl,pin)

    def _observe(self,cf_read_token,pod_read_token):
        return observer.collect_and_sign(approved_bytes=self.approved_observer,
            approved_sha256=self.approved_observer_sha256,cloudflare_read_token=cf_read_token,
            runpod_read_token=pod_read_token,key=self.observer_key,openssl=self.journal.authorities.openssl)

    def _load(self,name):
        p=self.state_dir/name
        if p.is_symlink() or not p.is_file() or p.stat().st_size>32768:
            raise ValueError("Protected controller state missing or invalid; do not relaunch")
        record=live._load(p.read_bytes())
        if type(record) is not dict:
            raise ValueError("Invalid protected controller state")
        return record

    def _write(self,name,value):
        store.write_atomic(self.state_dir/name,store.json_bytes(value))

    def _lease(self,index,run_id,guard,prior):
        e=guard["evidence"]
        stamp=e["observed_at"]
        cutoff=min(stamp+self._scope.allocation.max_attempt_seconds,self._scope.allocation.stop_at)
        expires=min(e["expires_at"],cutoff)
        if not stamp<=self._now()<expires:
            raise ValueError("Exact guard observation expired before lease issuance")
        return {"schema":warm.LEASE,"scope_sha256":self._scope.digest,"index":index,"scenario_id":warm.IDS[index],
                "run_id":run_id,"observed_at":stamp,"expires_at":expires,"case_deadline":cutoff,
                "guard_observation_sha256":store.sha(store.json_bytes(e)),"prior_readback_sha256":prior}

    def first(self,*,cf_read_token,pod_read_token):
        if self.journal.status() or (self.state_dir/FIRST_FILE).exists():
            raise ValueError("Initial release already journaled; do not relaunch")
        guard=self._observe(cf_read_token,pod_read_token)
        e=self._lease(0,self._plan()["run_id"],guard,None)
        lease=self._sign(e,warm.LEASE)
        digest=self.journal.first(lease)
        if self.journal.status()!=[{"idx":0,"run_id":e["run_id"],"lease_sha":digest,"receipt_sha":None}]:
            raise ValueError("First lease not durably isolated")
        pkg={"observation":guard,"first_lease":lease}
        self._write(FIRST_FILE,pkg)
        return pkg

    def _first_entry(self):
        p=self._load(FIRST_FILE)
        if set(p)!={"observation","first_lease"}:
            raise ValueError("Missing exact protected first admission")
        e=p["first_lease"]["evidence"]
        guard=p["observation"]["evidence"]
        lease_sha=store.sha(store.json_bytes(e))
        guard_sha=store.sha(store.json_bytes(guard))
        if (self.journal.status()!=[{"idx":0,"run_id":e["run_id"],"lease_sha":lease_sha,"receipt_sha":None}]
                or e["run_id"]!=self._plan()["run_id"] or e["guard_observation_sha256"]!=guard_sha):
            raise ValueError("No unconsumed first-case transition")
        return e,guard_sha

    def _transfer_trust(self,tr,e,guard_sha):
        p=self._scope.allocation
        r=transfer.PinnedRelease(p.batch_id,p.resource_id,p.owner_id,p.datacenter_id,p.pod_name,p.git_sha,
              p.profile_sha256,e["run_id"],guard_sha,self._scope.guard_instance_id,
              self._scope.guard_version_id,p.stop_at)
        if (type(tr) is not transfer.TransferTrust or tr.release!=r or tr.endpoint!=self.endpoint
                or tr.openssl!=self.journal.authorities.openssl
                or not hmac.compare_digest(store.sha(warm._key_der(tr.authority_pem)),self.publication_spki_sha256)):
            raise ValueError("This is not the pinned publication release and authority")

    def seal_first(self,*,archive,transfer_trust):
        """Controller independently validates fetched ZIP before granting Pod PUT."""
        e,guard_sha=self._first_entry()
        self._transfer_trust(transfer_trust,e,guard_sha)
        proof=transfer.inspect_sealed_archive(archive,transfer_trust.release)
        self.journal.seal_active(e["run_id"],**proof)
        record={"run_id":e["run_id"],"guard_observation_sha256":guard_sha,**proof}
        self._write(SEAL_FILE,record)
        return record

    def second(self,*,next_run_id,transfer_trust,get_envelope,get_url,cf_read_token,pod_read_token):
        """Obtain real authenticated GET and advance *once*; return only committed proof."""
        e,guard_sha=self._first_entry()
        self._transfer_trust(transfer_trust,e,guard_sha)
        if (not warm._uuid(next_run_id) or next_run_id in (e["run_id"],self._scope.allocation.batch_id)
                or self._now()>=e["case_deadline"] or (self.state_dir/RELAY_FILE).exists()):
            raise ValueError("Expected one fresh second attempt before the live first cutoff")
        seal=self._load(SEAL_FILE)
        if (set(seal)!={"run_id","guard_observation_sha256","sha256","size"}
                or (seal["run_id"],seal["guard_observation_sha256"])!=(e["run_id"],guard_sha)):
            raise ValueError("Missing protected pre-upload seal")
        # Do not even attempt an alternate protected GET. Only verify_at_controller
        # may establish authenticity; none of the caller's assertions are proof.
        grant=get_envelope.get("evidence") if type(get_envelope) is dict else None
        if (type(grant) is not dict or (grant.get("sha256"),grant.get("size"))!=(seal["sha256"],seal["size"])
                or type(grant.get("deadline")) is not int or grant["deadline"]>e["case_deadline"]):
            raise ValueError("GET grant does not match the protected pre-upload seal and case deadline")
        proof=transfer.verify_at_controller(trust=transfer_trust,get_envelope=get_envelope,
                                            get_url=get_url,receipt_dir=self.state_dir)
        if (proof["schema"]!=transfer.READBACK or proof["run_id"]!=e["run_id"] or
                (proof["sha256"],proof["bytes"])!=(seal["sha256"],seal["size"])):
            raise ValueError("Readback is not fresh proof for the protected seal")
        verified_at=self._now()
        # Journal compares integer observation timestamps with a real sub-second
        # seal time. At most one second before issuing the transition signatures.
        next_tick=math.ceil(verified_at)
        if next_tick>=e["case_deadline"]:
            raise ValueError("No time for an independently verified transition")
        if next_tick>verified_at:
            time.sleep(next_tick-verified_at)
        observed=int(self._now())
        r={"schema":warm.GET,"scope_sha256":self._scope.digest,"index":0,"scenario_id":warm.IDS[0],
           "run_id":e["run_id"],"observed_at":observed,"expires_at":min(observed+60,e["case_deadline"]),
           "method":"GET","bucket":"tcc","key":proof["key"],"sha256":proof["sha256"],"size":proof["bytes"],
           "verified_own_generations":1000,"verified_ledgers":20,"rounds":50,"nodes":20,
           "archive_verified":True,"independent_get":True}
        readback=self._sign(r,warm.GET)
        receipt_sha=store.sha(store.json_bytes(r))
        guard=self._observe(cf_read_token,pod_read_token)
        if guard["evidence"]["observed_at"]<observed:
            raise ValueError("Guard observation moved before the independent readback")
        lease_record=self._lease(1,next_run_id,guard,receipt_sha)
        next_lease=self._sign(lease_record,warm.LEASE)
        # Second guard evidence is retained privately, not an alternate entrance.
        self._write("controller-fresh-guard-"+lease_record["guard_observation_sha256"]+".json",guard)
        lease_sha=self.journal.transition(readback,next_lease)
        status=self.journal.status()
        if len(status)!=2 or status[0]["receipt_sha"]!=receipt_sha or status[1]!={
            "idx":1,"run_id":next_run_id,"lease_sha":lease_sha,"receipt_sha":None}:
            raise ValueError("Journal did not durably commit the exact two-case transition")
        committed=int(self._now())
        expires=min(r["expires_at"],lease_record["expires_at"])
        if committed>=expires-1:
            raise ValueError("Transition committed but too late to relay; do not rerun")
        attestation={"schema":COMMITTED,"scope_sha256":self._scope.digest,"receipt_sha256":receipt_sha,
             "lease_sha256":lease_sha,"index":1,"run_id":next_run_id,"committed_at":committed,"expires_at":expires}
        relay={"readback":readback,"next_lease":next_lease,"committed":self._sign(attestation,warm.LEASE)}
        if self._now()>=expires:
            raise ValueError("Committed relay expired before publication; do not rerun")
        self._write(RELAY_FILE,relay)
        return relay

    def _second_entry(self):
        relay=self._load(RELAY_FILE)
        if set(relay)!={"readback","next_lease","committed"}:
            raise ValueError("Missing exact committed second lease")
        r,e,c=(relay[k]["evidence"] for k in ("readback","next_lease","committed"))
        receipt_sha=store.sha(store.json_bytes(r))
        lease_sha=store.sha(store.json_bytes(e))
        status=self.journal.status()
        if (len(status)!=2 or c.get("receipt_sha256")!=receipt_sha or c.get("lease_sha256")!=lease_sha
                or status[0]["idx"]!=0 or status[0]["receipt_sha"]!=receipt_sha
                or status[1]!={"idx":1,"run_id":e["run_id"],"lease_sha":lease_sha,"receipt_sha":None}
                or e["index"]!=1 or e["scenario_id"]!=warm.IDS[1]
                or self._now()>=e["case_deadline"]):
            raise ValueError("No unfinalized exact second case before cutoff")
        return e,receipt_sha

    def seal_second(self,*,archive,transfer_trust):
        """Validate case two independently before a publisher grants its one PUT."""
        e,_=self._second_entry()
        guard_sha=e["guard_observation_sha256"]
        self._transfer_trust(transfer_trust,e,guard_sha)
        proof=transfer.inspect_second_archive(archive,transfer_trust.release)
        self.journal.seal_active(e["run_id"],**proof)
        record={"run_id":e["run_id"],"guard_observation_sha256":guard_sha,**proof}
        self._write(SECOND_SEAL_FILE,record)
        return record

    def finalize_second(self,*,transfer_trust,get_envelope,get_url,cf_read_token,pod_read_token):
        """Finish the two-case qualification only after exact second archive GET."""
        e,prior_receipt=self._second_entry()
        guard_sha=e["guard_observation_sha256"]
        self._transfer_trust(transfer_trust,e,guard_sha)
        if (self.state_dir/FINAL_FILE).exists():
            raise ValueError("Already finalized; do not rerun")
        seal=self._load(SECOND_SEAL_FILE)
        grant=get_envelope.get("evidence") if type(get_envelope) is dict else None
        if (set(seal)!={"run_id","guard_observation_sha256","sha256","size"}
                or (seal["run_id"],seal["guard_observation_sha256"])!=(e["run_id"],guard_sha)
                or type(grant) is not dict or (grant.get("sha256"),grant.get("size"))!=(seal["sha256"],seal["size"])
                or type(grant.get("deadline")) is not int or grant["deadline"]>e["case_deadline"]):
            raise ValueError("Second GET grant does not match the protected seal and case cutoff")
        proof=transfer.verify_second_at_controller(trust=transfer_trust,get_envelope=get_envelope,
                                                   get_url=get_url,receipt_dir=self.state_dir)
        if (proof["schema"]!=transfer.SECOND_READBACK or proof["run_id"]!=e["run_id"] or
                (proof["sha256"],proof["bytes"])!=(seal["sha256"],seal["size"])):
            raise ValueError("Exact second-case readback unavailable")
        verified_at=self._now()
        after=math.ceil(verified_at)
        if after>=e["case_deadline"]:
            raise ValueError("Second verification expired before terminal proof")
        if after>verified_at:
            time.sleep(after-verified_at)
        observed=int(self._now())
        guard=self._observe(cf_read_token,pod_read_token)
        if guard["evidence"]["observed_at"]<observed:
            raise ValueError("Final guard observation precedes second readback")
        record={"schema":warm.GET,"scope_sha256":self._scope.digest,"index":1,"scenario_id":warm.IDS[1],
                "run_id":e["run_id"],"observed_at":observed,"expires_at":min(observed+60,e["case_deadline"]),
                "method":"GET","bucket":"tcc","key":proof["key"],"sha256":proof["sha256"],"size":proof["bytes"],
                "verified_own_generations":1000,"verified_ledgers":20,"rounds":50,"nodes":20,
                "archive_verified":True,"independent_get":True}
        signed_readback=self._sign(record,warm.GET)
        digest=self.journal.finalize_second(signed_readback)
        status=self.journal.status()
        if (len(status)!=2 or status[0]["receipt_sha"]!=prior_receipt
                or (status[1]["idx"],status[1]["run_id"],status[1]["receipt_sha"])!=(1,e["run_id"],digest)):
            raise ValueError("No durable terminal confirmation for exactly two cases")
        g=guard["evidence"]
        final={"schema":QUALIFIED,"scope_sha256":self._scope.digest,"run_id":e["run_id"],
               "first_receipt_sha256":prior_receipt,"second_receipt_sha256":digest,
               "verified_cases":2,"next_case_authorized":False,"stop_authorized":False,
               "guard_observation_sha256":store.sha(store.json_bytes(g)),"committed_at":int(self._now())}
        self._write("controller-fresh-guard-"+final["guard_observation_sha256"]+".json",guard)
        result={"readback":signed_readback,"qualified":self._sign(final,warm.LEASE)}
        self._write(FINAL_FILE,result)
        return result
