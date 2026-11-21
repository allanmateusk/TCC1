"""Linux controller bridge: fixed SSH data-plane ops and protected worker parent."""
from __future__ import annotations

import argparse
import base64
from pathlib import Path
import json
import os
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

from . import artifact_store as store, benchmark, incremental_first_live as first
from . import incremental_first_transfer as transfer, incremental_warm_start as start
from .incremental_external_controller import APPROVAL
from .incremental_warm_live import FULL_POLICY, Seal, verify_transition
from .incremental_batch_protection import protection_for
from .incremental_warm_journal import Authorities, LEASE, OFFICIAL, Scope, _key_der, _uuid
from .incremental_official_case_step import BRIDGE, FRAME_CAP

RUNTIME=Path("/run/tcc-n20-incremental")
SOCKET=RUNTIME/"bridge.sock"
BASE={"schema","operation","scope_sha256","resource_id","run_id"}
OPS={"fetch_archive":set(),"send_put":{"frame"},"install_relay":{"relay","index"}}
INSTALL="tcc-warm-linux-bridge-install/v1"


def _read_stream(read,cap):
    result=bytearray()
    while True:
        chunk=read(min(16384,cap+1-len(result)))
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result)>cap:
            raise ValueError("Bridge input or response exceeded its cap")


def _parse(data):
    rec=first._load(data)
    if type(rec) is not dict or type(rec.get("operation")) is not str or rec["operation"] not in OPS \
            or set(rec)!=BASE|OPS[rec["operation"]] or rec["schema"]!=BRIDGE or not _uuid(rec["run_id"]):
        raise ValueError("Expected exact narrow bridge operation")
    return rec


def _archive(root,run_id):
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY
    r=os.open(root,flags)
    try:
        d=os.open(run_id,flags,dir_fd=r)
        try:
            f=os.open(store.CANDIDATE_ARCHIVE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d)
            with os.fdopen(f,"rb") as file:
                m=os.fstat(file.fileno())
                if not stat.S_ISREG(m.st_mode) or not 0<m.st_size<=store.MAX_ZIP:
                    raise ValueError("Expected bounded regular archive")
                body=file.read(store.MAX_ZIP+1)
            if not 0<len(body)<=store.MAX_ZIP:
                raise ValueError("Expected bounded archive")
            return body
        finally:
            os.close(d)
    finally:
        os.close(r)


def _install(index,raw,service_gid):
    name=f"warm-transition-{index+1:02d}.json"
    out=first.SERVICE/name
    tmp_fd,tmp=tempfile.mkstemp(prefix=".transition-",dir=first.SERVICE)
    try:
        with os.fdopen(tmp_fd,"wb") as f:
            os.fchown(f.fileno(),0,service_gid)
            os.fchmod(f.fileno(),0o440)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.link(tmp,out)  # exclusive; never replace a relay
        store._sync_dir(first.SERVICE)
    finally:
        Path(tmp).unlink(missing_ok=True)
    if first._root_only(out,FRAME_CAP)!=raw:
        raise ValueError("Protected relay differs after commit")


class Bridge:
    """Serial exact-run gate. No shell, provider methods, signer or GET key."""
    def __init__(self,scope,authorities,current,root,pem,endpoint,service_gid,write_fd):
        self.scope,self.authorities,self.current=scope,authorities,current
        self.root,self.pem,self.endpoint,self.service_gid,self.fd=root,pem,endpoint,service_gid,write_fd
        self.delivered={}
        self.put_attempted=set()

    def _trust(self):
        a,e=self.scope.allocation,self.current
        release=transfer.FullCaseRelease(a.batch_id,a.resource_id,a.owner_id,a.datacenter_id,a.pod_name,
              a.git_sha,a.profile_sha256,e["run_id"],e["guard_observation_sha256"],self.scope.guard_instance_id,
              self.scope.guard_version_id,a.stop_at,self.scope.digest,e["index"],e["case_deadline"])
        return transfer.TransferTrust(release,self.pem,store.sha(self.pem),self.endpoint,self.authorities.openssl)

    def _verified_archive(self):
        body=_archive(self.root,self.current["run_id"])
        transfer.inspect_full_archive(body,self._trust().release)
        return body

    def handle(self,data):
        req=_parse(data)
        now=time.time()
        if (req["scope_sha256"],req["resource_id"])!=(self.scope.digest,self.scope.allocation.resource_id) \
                or now>=self.scope.allocation.stop_at:
            raise ValueError("Wrong protected allocation")
        op,rid=req["operation"],req["run_id"]
        if op=="install_relay":
            i=req["index"]
            if type(i) is not int or not 1<=i<self.scope.case_limit:
                raise ValueError("No relay for this index")
            raw=store.json_bytes(req["relay"])
            if len(raw)>FRAME_CAP:
                raise ValueError("Relay too large")
            proof_hash=store.sha(raw)
            if self.delivered.get(i)==(rid,proof_hash):
                name=f"warm-transition-{i+1:02d}.json"
                if first._root_only(first.SERVICE/name,FRAME_CAP)==raw:
                    return (proof_hash+"\n").encode("ascii")
                raise ValueError("Previously installed relay changed")
            if i!=self.current["index"]+1 or now>=self.current["case_deadline"]:
                raise ValueError("No protected active previous case")
            body=self._verified_archive()
            seal=Seal(self.current["run_id"],self.current["scenario_id"],store.sha(body),len(body))
            next_case=verify_transition(self.authorities,req["relay"],prior=self.current,seal=seal,now=time.time())
            if (next_case["index"],next_case["run_id"])!=(i,rid):
                raise ValueError("Relay does not match exact requested child")
            if time.time()>=min(next_case["expires_at"],self.current["case_deadline"]):
                raise ValueError("Relay expired during verification")
            _install(i,raw,self.service_gid)
            self.delivered[i]=(rid,proof_hash)
            self.current=next_case
            return (proof_hash+"\n").encode("ascii")
        if rid!=self.current["run_id"] or now>=self.current["case_deadline"]:
            raise ValueError("Only the active admitted case may use bridge data")
        body=self._verified_archive()
        if op=="fetch_archive":
            return body
        frame=start._decode_frame(json.dumps(req["frame"],separators=(",",":"),ensure_ascii=True).encode("ascii"))
        n,_,_=transfer._authorize_envelope(self._trust(),frame["put_envelope"],frame["put_url"],"PUT",
                                           now=time.time(),case=self.current["scenario_id"],full=True)
        if (n.sha256,n.size)!=(store.sha(body),len(body)):
            raise ValueError("Publication grant does not match exact ZIP")
        raw=json.dumps(frame,separators=(",",":"),ensure_ascii=True).encode("ascii")+b"\n"
        # One write no larger than PIPE_BUF; never attempt after uncertain delivery.
        if len(raw)>os.fpathconf(self.fd,"PC_PIPE_BUF") or rid in self.put_attempted:
            raise ValueError("No repeat or oversized pipe frame; reconcile by GET")
        self.put_attempted.add(rid)
        if os.write(self.fd,raw)!=len(raw):
            raise ValueError("PUT delivery uncertain; reconcile by GET")
        return b"QUEUED\n"


def _protected_inputs():
    if sys.platform!="linux" or os.geteuid()!=0 or os.getuid()!=0:
        raise ValueError("Independent root supervisor needed")
    path=first.SERVICE
    read=lambda name,cap=32768:first._root_only(path/name,cap)
    load=lambda name:first._load(read(name))
    profile,_=benchmark.load_profile("incremental-v1")
    trust=load("first-case-trust.json")
    e=load("first-case-handoff.json")
    if type(e) is not dict or set(e)!={"evidence","signature_ed25519_base64"}:
        raise ValueError("No signed observation installed")
    signature=base64.b64decode(e["signature_ed25519_base64"],validate=True)
    if len(signature)!=64:
        raise ValueError("Invalid observer signature")
    observer=read("observer-ed25519.pem",256)
    first._verify_signature(e["evidence"],signature,observer)
    first.verify_evidence(e["evidence"],trust,now=time.time(),profile=profile)
    obs=e["evidence"]
    first._verify_release(obs["git_sha"])
    q=load("warm-resident-release.json")
    if set(q)!={"schema","scope","approved_scope_sha256","qualifier_report_sha256"} or q["schema"]!=FULL_POLICY \
            or not first._hex(q["qualifier_report_sha256"],64):
        raise ValueError("Exact qualified release not installed")
    raw=q["scope"]
    scope=Scope(**{**raw,"allocation":protection_for(raw["allocation"])})
    a=scope.allocation
    if (q["approved_scope_sha256"]!=scope.digest or scope.mode!=OFFICIAL or
        any(getattr(a,k)!=obs[k] for k in ("batch_id","resource_id","owner_id","datacenter_id","pod_name",
                                           "git_sha","profile_sha256","opened_at","stop_at","hard_deadline"))
        or (scope.guard_instance_id,scope.guard_version_id,scope.worker_version_id)!=(
             obs["workflow_instance_id"],obs["workflow_version"],obs["worker_version"])):
        raise ValueError("Scope and signed first release do not match")
    authorities=Authorities(scope,read("warm-lease-ed25519.pem",256),
                      read("warm-get-ed25519.pem",256),Path("/usr/bin/openssl").resolve(strict=True))
    current,_=authorities.validate(load("warm-first-lease.json"),LEASE,time.time())
    if (current["index"],current["run_id"],current["guard_observation_sha256"])!=(
            0,obs["run_id"],store.sha(store.json_bytes(obs))):
        raise ValueError("No fresh exact first lease")
    permission=load("warm-publication-trust.json")
    if (set(permission)!={"schema","scope_sha256","observer_sha256","endpoint","publication_spki_sha256"}
            or (permission["schema"],permission["scope_sha256"])!=(APPROVAL,scope.digest)
            or not first._hex(permission["observer_sha256"],64)):
        raise ValueError("Publication role is not independently pinned")
    public=read("warm-publication-ed25519.pem",256)
    p=store.sha(_key_der(public))
    if p!=permission["publication_spki_sha256"] or len({p,store.sha(_key_der(observer)),
                                              scope.lease_key_sha256,scope.readback_key_sha256})!=4:
        raise ValueError("Use distinct publication key")
    settings=load("warm-linux-bridge.json")
    if (set(settings)!={"schema","scope_sha256","service_gid","ssh_uid","ssh_gid"} or
            (settings["schema"],settings["scope_sha256"])!=(INSTALL,scope.digest)):
        raise ValueError("Dedicated bridge principals not installed")
    ids=(trust["service_uid"],settings["service_gid"],settings["ssh_uid"],settings["ssh_gid"])
    if any(type(x) is not int or not 1<=x<=2**31-1 for x in ids) or ids[0]==ids[2] or ids[1]==ids[3]:
        raise ValueError("Require separate nonroot service and SSH identities")
    root=Path(trust["durable_root"])
    if not root.is_absolute() or root.resolve(strict=True)!=root or not root.is_dir() or RUNTIME.resolve(strict=True)!=RUNTIME:
        raise ValueError("Exact controller and data plane directories required")
    m=RUNTIME.stat()
    if not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022:
        raise ValueError("Runtime directory must not be writable by the SSH account or Pod worker")
    out=store.durable_run(root,current["run_id"],repo=benchmark.ROOT.parent)
    if out.exists() or out.is_symlink() or any((path/f"warm-transition-{i:02d}.json").exists()
                                               for i in range(2,21)):
        raise ValueError("Attempt or relay already exists; no automatic restart")
    return scope,authorities,current,root,public,permission["endpoint"],ids


def _safe_socket_remove(inode):
    try:
        m=SOCKET.lstat()
        if stat.S_ISSOCK(m.st_mode) and (m.st_dev,m.st_ino)==inode:
            SOCKET.unlink()
    except FileNotFoundError:
        pass


def serve():
    scope,authorities,current,root,pem,endpoint,ids=_protected_inputs()
    uid,gid,ssh_uid,ssh_gid=ids
    r,w=os.pipe2(os.O_CLOEXEC)
    os.set_blocking(w,False)
    proc=None
    inode=None
    try:
        b=Bridge(scope,authorities,current,root,pem,endpoint,gid,w)
        b._trust()  # validate private R2 pin before startup; no provider request
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
            listener.bind(str(SOCKET))  # existing socket is never overwritten
            bound=SOCKET.lstat()
            inode=(bound.st_dev,bound.st_ino)
            os.chown(SOCKET,0,ssh_gid)
            os.chmod(SOCKET,0o660)
            listener.listen(4)
            listener.settimeout(.35)
            proc=subprocess.Popen([sys.executable,"-B","-m","infra.runpod.n20.incremental_warm_start",
                      "run","--publish-fd",str(r)],cwd=benchmark.ROOT,env={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8",
                      "PYTHONNOUSERSITE":"1"},stdin=subprocess.DEVNULL,pass_fds=(r,),user=uid,group=gid,
                      extra_groups=[],start_new_session=True)
            os.close(r); r=-1
            while proc.poll() is None and time.time()<scope.allocation.stop_at:
                try:
                    peer,_=listener.accept()
                except TimeoutError:
                    continue
                with peer:
                    peer.settimeout(8)
                    try:
                        _,pu,pg=struct.unpack("3i",peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
                        if (pu,pg)!=(ssh_uid,ssh_gid):
                            raise ValueError("Unexpected bridge peer")
                        reply=b.handle(_read_stream(peer.recv,FRAME_CAP))
                        if not 0<len(reply)<=store.MAX_ZIP:
                            raise ValueError("Bridge response exceeds bound")
                        peer.sendall(b"\x00"+reply)
                    except Exception:
                        # No token, presigned URL, traceback or filesystem info to peer.
                        try:
                            peer.sendall(b"\x01")
                        except OSError:
                            pass
            if proc.poll() is None or proc.returncode!=0:
                raise ValueError("The worker stopped or did not finish under protected deadline")
    finally:
        for fd in (r,w):
            if fd>=0:
                os.close(fd)
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid,signal.SIGTERM)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL)
                proc.wait(timeout=5)
        if inode is not None:
            _safe_socket_remove(inode)


def request():
    if sys.platform!="linux" or os.geteuid()==0 or os.environ.get("SSH_ORIGINAL_COMMAND")!="tcc-official-case-bridge":
        raise ValueError("Only the dedicated forced nonroot SSH command is supported")
    raw=_read_stream(sys.stdin.buffer.read,FRAME_CAP)
    _parse(raw)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(15)
        conn.connect(str(SOCKET))
        conn.sendall(raw)
        conn.shutdown(socket.SHUT_WR)
        framed=_read_stream(conn.recv,store.MAX_ZIP+1)
    if not framed.startswith(b"\x00") or len(framed)<=1:
        raise ValueError("Protected data plane request failed")
    sys.stdout.buffer.write(framed[1:])
    sys.stdout.buffer.flush()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("operation",choices=("serve","request"))
    a=p.parse_args()
    try:
        (serve if a.operation=="serve" else request)()
        return 0
    except (Exception,KeyboardInterrupt):
        print("Protected Linux bridge did not complete.",file=sys.stderr)
        return 1


if __name__=="__main__":
    raise SystemExit(main())
