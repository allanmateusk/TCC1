"""One supervised official case handoff. No launch, STOP or provider provisioning."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hmac
import os
from pathlib import Path
import re
import subprocess
import threading
from urllib.parse import urlsplit

from . import artifact_store as store, incremental_external_controller as external
from . import incremental_first_live as live, incremental_first_observer as observer
from . import incremental_first_transfer as transfer, incremental_warm_journal as warm
from . import r2_grants, r2_pilot_prompt

BRIDGE="tcc-official-ssh-controller-bridge/v1"
STEP="tcc-official-case-one-shot-dispatch/v1"
FRAME_CAP=16384


@dataclass(frozen=True)
class StorageRole:
    access_id: str = field(repr=False)
    secret: str = field(repr=False)

    def __post_init__(self):
        if (type(self.access_id) is not str or not re.fullmatch("[A-Za-z0-9]{16,128}",self.access_id)
                or type(self.secret) is not str or not re.fullmatch("[A-Za-z0-9+/=]{32,128}",self.secret)):
            raise ValueError("Expected an already provisioned scoped R2 identity")


@dataclass(frozen=True)
class OpenSSH:
    """A pinned Windows/Linux OpenSSH client for one independently installed bridge."""
    scope_sha256: str
    resource_id: str
    host: str
    port: int
    user: str
    ssh: Path
    identity: Path
    known_hosts: Path
    known_hosts_sha256: str
    approval_sha256: str

    def __post_init__(self):
        if (not warm._hex(self.scope_sha256,64) or not warm._hex(self.known_hosts_sha256,64)
                or type(self.host) is not str or not re.fullmatch("[A-Za-z0-9][A-Za-z0-9.-]{0,252}",self.host)
                or type(self.port) is not int or not 1<=self.port<=65535
                or type(self.user) is not str or not re.fullmatch("[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}",self.user)
                or not re.fullmatch("[A-Za-z0-9][A-Za-z0-9_-]{1,127}",self.resource_id)
                or self.ssh.name.lower() not in ("ssh","ssh.exe")):
            raise ValueError("Expected exact independently verified Pod SSH identity")
        for path in (self.ssh,self.identity,self.known_hosts):
            if (not path.is_absolute() or path.resolve(strict=True)!=path or not path.is_file()
                    or any(c in str(path) for c in ('"',"%","\r","\n"))):
                raise ValueError("Expected canonical protected OpenSSH paths")
        public={"schema":BRIDGE,"scope_sha256":self.scope_sha256,"resource_id":self.resource_id,
                "host":self.host,"port":self.port,"user":self.user,"known_hosts_sha256":self.known_hosts_sha256}
        if (not warm._hex(self.approval_sha256,64)
                or not hmac.compare_digest(self.approval_sha256,store.sha(store.json_bytes(public)))):
            raise ValueError("Missing separately approved controller SSH scope")
        self._host_key()

    def _host_key(self):
        with self.known_hosts.open("rb") as reader:
            raw=reader.read(4097)
        if not 0<len(raw)<=4096 or store.sha(raw)!=self.known_hosts_sha256:
            raise ValueError("Pinned SSH host key material changed")
        host=self.host if self.port==22 else f"[{self.host}]:{self.port}"
        parts=raw.strip().split()
        if (len(raw.strip().splitlines())!=1 or len(parts)!=3 or parts[:2]!=[host.encode("ascii"),b"ssh-ed25519"]):
            raise ValueError("Use one independently verified ED25519 entry for the exact host and port")

    def _args(self):
        self._host_key()
        return [str(self.ssh),"-F","none","-T","-p",str(self.port),"-i",str(self.identity),
            "-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","IdentityAgent=none",
            "-o","IdentitiesOnly=yes","-o","HostKeyAlgorithms=ssh-ed25519","-o","UpdateHostKeys=no",
            "-o","GlobalKnownHostsFile=none","-o",f'UserKnownHostsFile="{self.known_hosts}"',
            "-o","ClearAllForwardings=yes","-o","ConnectTimeout=5","-o","ConnectionAttempts=1",
            self.user+"@"+self.host,"tcc-official-case-bridge"]

    def _invoke(self,body,cap):
        raw=store.json_bytes(body)
        if len(raw)>FRAME_CAP:
            raise ValueError("Authenticated bridge request exceeds its cap")
        # Do not put presigned URLs in argv, environment, logs, or a temporary file.
        result=bytearray()
        failures=[]
        try:
            with subprocess.Popen(self._args(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL,bufsize=0) as proc:
                def send():
                    try:
                        with proc.stdin:
                            unsent=memoryview(raw)
                            while unsent:
                                n=proc.stdin.write(unsent)
                                if not n:
                                    raise OSError("Incomplete stdin write")
                                unsent=unsent[n:]
                    except OSError:
                        failures.append("input")
                def receive():
                    try:
                        while True:
                            piece=proc.stdout.read(min(16384,cap+1-len(result)))
                            if not piece:
                                break
                            result.extend(piece)
                            if len(result)>cap:
                                failures.append("cap")
                                proc.kill()
                                break
                    except OSError:
                        failures.append("output")
                a=threading.Thread(target=send,daemon=True)
                b=threading.Thread(target=receive,daemon=True)
                a.start()
                b.start()
                try:
                    code=proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                    raise ValueError("Authenticated bridge response timed out") from None
                a.join(2)
                b.join(2)
                if code!=0 or failures or a.is_alive() or b.is_alive() or len(result)>cap:
                    raise ValueError("Authenticated bridge operation not verified")
        except OSError:
            raise ValueError("Unable to open the pinned SSH bridge") from None
        return bytes(result)

    def _request(self,operation,run_id,**fields):
        if not warm._uuid(run_id):
            raise ValueError("Use exact admitted run ID")
        return {"schema":BRIDGE,"operation":operation,"scope_sha256":self.scope_sha256,
                "resource_id":self.resource_id,"run_id":run_id,**fields}

    def fetch_archive(self,run_id):
        return self._invoke(self._request("fetch_archive",run_id),store.MAX_ZIP)

    def send_put(self,run_id,frame):
        if type(frame) is not dict or set(frame)!={"put_envelope","put_url"}:
            raise ValueError("Expected exactly one role-specific anonymous pipe frame")
        result=self._invoke(self._request("send_put",run_id,frame=frame),16)
        if result!=b"QUEUED\n":
            raise ValueError("PUT delivery uncertain; reconcile only by GET")

    def install_relay(self,run_id,index,relay):
        # The receiver validates scope and signatures; these names are not caller paths.
        if type(index) is not int or not 1<=index<20:
            raise ValueError("Only relay to the exact next case in this lot")
        body=self._request("install_relay",run_id,index=index,relay=relay)
        sha=store.sha(store.json_bytes(relay))
        if self._invoke(body,65)!=(sha+"\n").encode("ascii"):
            raise ValueError("Protected relay install not independently read back")


@dataclass(frozen=True)
class CaseStep:
    controller: external.Controller
    channel: OpenSSH
    publication_key: Path
    publication_pem: bytes

    def __post_init__(self):
        if (type(self.controller) is not external.Controller or type(self.channel) is not OpenSSH
                or self.controller._scope.mode!=warm.OFFICIAL
                or (self.channel.scope_sha256,self.channel.resource_id)!=(
                self.controller._scope.digest,self.controller._scope.allocation.resource_id)
                or store.sha(warm._key_der(self.publication_pem))!=self.controller.publication_spki_sha256):
            raise ValueError("Independent publication key, exact official scope and pinned bridge required")

    def _release(self,e):
        s=self.controller._scope
        a=s.allocation
        r=transfer.FullCaseRelease(a.batch_id,a.resource_id,a.owner_id,a.datacenter_id,a.pod_name,
             a.git_sha,a.profile_sha256,e["run_id"],e["guard_observation_sha256"],s.guard_instance_id,
             s.guard_version_id,a.stop_at,s.digest,e["index"],e["case_deadline"])
        return transfer.TransferTrust(r,self.publication_pem,store.sha(self.publication_pem),
                   self.controller.endpoint,self.controller.journal.authorities.openssl)

    def _permit(self,tr, seal, guard, role, method):
        r=tr.release
        e=guard["evidence"]
        now=self.controller._now()
        stamp=int(now)
        if (e["batch_id"],e["resource_id"],e["stop_at"],e["owner_id"],e["workflow_instance_id"])!=(
                r.batch_id,r.resource_id,r.stop_at,r.owner_id,r.guard_instance_id):
            raise ValueError("Fresh authenticated observation is for a different allocation")
        deadline=min(r.case_deadline,e["expires_at"],stamp+45)
        if not e["observed_at"]<=now<deadline-3:
            raise ValueError("Insufficient live guard window for scoped R2 grant")
        key=f"tcc/prod/incremental-v1/n20-{r.run_id}.zip"
        when=datetime.fromtimestamp(stamp,timezone.utc)
        url=r2_pilot_prompt._presign(method,host=urlsplit(tr.endpoint).netloc,path="/tcc/"+key,
                     region="auto",access_key_id=role.access_id,secret_key=role.secret,now=when,expires=deadline-stamp)
        r2_grants.validate_url(tr.config(),key,url,method=method,now=when,key_pattern=transfer.tx.KEY)
        proof={"schema":transfer.FULL_SCHEMA,"release":asdict(r),"method":method,"scenario_id":r.case,
               "campaign_id":warm.CAMPAIGN,"bucket":"tcc","key":key,"sha256":seal["sha256"],"size":seal["size"],
               "deadline":deadline,"observed_at":e["observed_at"],"guard_phase":e["status"],
               "sleep_name":"absolute-batch-cutoff","sleep_end":r.stop_at,"url_sha256":store.sha(url.encode("ascii"))}
        envelope=observer._sign(proof,self.publication_key,tr.openssl,self.controller.publication_spki_sha256)
        return envelope,url

    def execute(self,*,write_role,read_role,cf_read_token,pod_read_token,next_run_id=None):
        """One case only. On an uncertain PUT, subsequent calls reconcile GET only."""
        if (type(write_role) is not StorageRole or type(read_role) is not StorageRole
                or write_role.access_id==read_role.access_id or write_role.secret==read_role.secret):
            raise ValueError("Use distinct R2 writer and read-only identities")
        c=self.controller
        e,tips=c._active_full()
        if e["index"]:
            expected=f"warm-transition-{e['index']+1:02d}.json"
            marker=c.state_dir/(expected+".delivered.json")
            if not marker.is_file() or marker.is_symlink() or c._load(marker.name)!={
                "filename":expected,"sha256":store.sha(store.json_bytes(c._load(expected)))}:
                raise ValueError("Deliver and verify the already committed relay before continuing")
        last=e["index"]+1==c._scope.case_limit
        if (last and next_run_id is not None or not last and (
                not warm._uuid(next_run_id) or next_run_id==c._scope.allocation.batch_id
                or any(row["run_id"]==next_run_id for row in tips))):
            raise ValueError("Expected a fresh next case UUID, and no UUID after case 20")
        tr=self._release(e)
        rid=e["run_id"]
        fname=f"archive-{rid}.zip"
        zip_path=c.state_dir/fname
        if zip_path.is_symlink():
            raise ValueError("Refuse redirected archive")
        if not zip_path.is_file():
            body=self.channel.fetch_archive(rid)
            transfer.inspect_full_archive(body,tr.release)
            store.write_atomic(zip_path,body)
        with zip_path.open("rb") as f:
            body=f.read(store.MAX_ZIP+1)
        seal=c.seal_full_case(archive=body,transfer_trust=tr)
        g=c._observe(cf_read_token,pod_read_token)
        marker=c.state_dir/f"dispatch-{rid}.json"
        record={"schema":STEP,"scope_sha256":tr.release.scope_sha256,"run_id":rid,
                "index":e["index"],"sha256":seal["sha256"],"size":seal["size"]}
        should_send=False
        if not marker.exists():
            prepared,put_url=self._permit(tr,seal,g,write_role,"PUT")
            # Journal the attempt by exclusive name, before any possibly delivered pipe frame.
            try:
                flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
                fd=os.open(marker,flags,0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd,"wb") as stream:
                    stream.write(store.json_bytes(record))
                    stream.flush()
                    os.fsync(stream.fileno())
                store._sync_dir(c.state_dir)
                should_send=True
        if c._load(marker.name)!=record:
            raise ValueError("Uncertain publication journal; do not release or resend")
        if should_send:
            try:
                self.channel.send_put(rid,{"put_envelope":prepared,"put_url":put_url})
            except ValueError:
                # Receipt and object are independent; lost response never reopens PUT.
                pass
        read_envelope,get_url=self._permit(tr,seal,g,read_role,"GET")
        result=c.accept_full_case(transfer_trust=tr,get_envelope=read_envelope,get_url=get_url,
              cf_read_token=cf_read_token,pod_read_token=pod_read_token,next_run_id=next_run_id)
        if not last:
            self.deliver_existing(index=e["index"]+1)
        return result

    def deliver_existing(self,*,index):
        """Recover only already committed same bytes; never request a fresh lease."""
        if type(index) is not int or not 1<=index<self.controller._scope.case_limit:
            raise ValueError("Expected exact previously issued relay index")
        c=self.controller
        e,_=c._active_full()
        if index!=e["index"]:
            raise ValueError("Refuse relay against a different active case")
        filename=f"warm-transition-{index+1:02d}.json"
        r=c._load(filename)
        now=c._now()
        receipt,receipt_sha=c.journal.authorities.validate(r["readback"],warm.GET,now)
        lease,lease_sha=c.journal.authorities.validate(r["next_lease"],warm.LEASE,now)
        commit=r["committed"]
        rec=commit["evidence"]
        fixed={"schema":external.COMMITTED,"scope_sha256":c._scope.digest,
               "receipt_sha256":receipt_sha,"lease_sha256":lease_sha,"run_id":e["run_id"],"index":index}
        if (type(rec) is not dict or set(rec)!=set(fixed)|{"committed_at","expires_at"}
                or any(rec[k]!=v for k,v in fixed.items()) or type(rec["index"]) is not int
                or type(rec["committed_at"]) is not int or type(rec["expires_at"]) is not int
                or not lease["observed_at"]<=rec["committed_at"]<=now<rec["expires_at"]
                         <=min(receipt["expires_at"],lease["expires_at"])):
            raise ValueError("Committed relay expired; no automatic re-admission")
        c.journal.authorities.verify_signature(rec,commit["signature_ed25519_base64"],kind=warm.LEASE)
        self.channel.install_relay(e["run_id"],index,r)
        c._write(filename+".delivered.json",{"filename":filename,"sha256":store.sha(store.json_bytes(r))})
