"""Protected Linux startup for the full warm campaign; no new signing authority."""
from __future__ import annotations

import argparse
import hmac
import json
import os
from pathlib import Path
import select
import stat
import sys
import subprocess
import time

from . import artifact_store as store, incremental_first_live as first, incremental_first_transfer as transfer
from . import local_recovery
from .incremental_external_controller import APPROVAL
from .incremental_warm_journal import _key_der

MAX_FRAME=16384


def _check_fd(fd):
    if sys.platform!="linux" or type(fd) is not int or fd<3:
        raise ValueError("Provide a dedicated inherited Linux read pipe, not stdin")
    import fcntl
    if (not stat.S_ISFIFO(os.fstat(fd).st_mode) or
        not os.readlink(f"/proc/self/fd/{fd}").startswith("pipe:[") or
        fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY):
        raise ValueError("Expected an anonymous read-only publisher pipe")
    poll=select.poll()
    poll.register(fd,select.POLLIN|select.POLLERR|select.POLLHUP|select.POLLNVAL)
    if poll.poll(0):
        raise ValueError("Publisher pipe is closed or already has an unexpected frame")
    os.set_inheritable(fd,False)  # Inference children may not read bearer grants.
    os.set_blocking(fd,False)
    return poll


def _decode_frame(line):
    if not 0<len(line)<=MAX_FRAME:
        raise ValueError("Missing or oversized scoped publication envelope")
    item=first._load(line)
    if (type(item) is not dict or set(item)!={"put_envelope","put_url"} or
        type(item["put_envelope"]) is not dict or type(item["put_url"]) is not str
        or not 0<len(item["put_url"])<4096):
        raise ValueError("Expected one signed PUT envelope for the sealed case")
    return item


class PutRelay:
    """One inherited writer channel; authority still lives in existing signatures."""
    def __init__(self,fd,admission):
        self._admission=admission
        from .incremental_warm_live import WarmAdmission
        if type(admission) is not WarmAdmission or not admission.full:
            raise ValueError("Full protected warm admission required")
        self._poll=_check_fd(fd)
        self._fd=fd
        self._pending=bytearray()
        self._keys,self._endpoint=self._protected_publication()
        self._trust()  # pin first-case R2 release+public key without acquiring any URL or using network

    def _protected_publication(self):
        load=first._root_only
        base=first.SERVICE
        approved=first._load(load(base/"warm-publication-trust.json",8192))
        if (type(approved) is not dict or set(approved)!={"schema","scope_sha256","observer_sha256","endpoint",
              "publication_spki_sha256"} or approved["schema"]!=APPROVAL
            or approved["scope_sha256"]!=self._admission.authorities.scope.digest
            or not first._hex(approved["observer_sha256"],64)
            or not first._hex(approved["publication_spki_sha256"],64)):
            raise ValueError("Exact root-owned publication approval is absent")
        public=load(base/"warm-publication-ed25519.pem",256)
        pin=store.sha(_key_der(public))
        origin=store.sha(_key_der(load(base/"observer-ed25519.pem",256)))
        scope=self._admission.authorities.scope
        if (not hmac.compare_digest(pin,approved["publication_spki_sha256"])
            or len({pin,origin,scope.lease_key_sha256,scope.readback_key_sha256})!=4):
            raise ValueError("Publication role does not have its independent approved key")
        return public,approved["endpoint"]

    def _trust(self):
        scope=self._admission.authorities.scope
        a=scope.allocation
        e=self._admission.current
        release=transfer.FullCaseRelease(a.batch_id,a.resource_id,a.owner_id,a.datacenter_id,a.pod_name,
            a.git_sha,a.profile_sha256,e["run_id"],e["guard_observation_sha256"],scope.guard_instance_id,
            scope.guard_version_id,a.stop_at,scope.digest,e["index"],e["case_deadline"])
        return transfer.TransferTrust(release,self._keys,store.sha(self._keys),self._endpoint,
                                      self._admission.authorities.openssl)

    def _receive(self):
        while b"\n" not in self._pending:
            self._admission.check()
            left=self._admission.current["case_deadline"]-time.time()
            if left<=0:
                raise InterruptedError("PUT grant was not delivered before the case deadline")
            events=self._poll.poll(max(1,int(min(left,.5)*1000)))
            if not events:
                continue
            if (len(events)!=1 or events[0][0]!=self._fd or
                events[0][1]&(select.POLLERR|select.POLLNVAL)):
                raise ValueError("Publication relay is no longer valid")
            try:
                chunk=os.read(self._fd,min(4096,MAX_FRAME+1-len(self._pending)))
            except BlockingIOError:
                continue
            if not chunk:
                raise ValueError("Publication relay closed before giving a signed PUT")
            self._pending.extend(chunk)
            if len(self._pending)>MAX_FRAME:
                raise ValueError("Oversized publication frame")
        line,_,rest=self._pending.partition(b"\n")
        self._pending=rest
        return _decode_frame(line)

    def publish(self,admission,seal,path):
        from .incremental_warm_live import _read_sealed_zip
        if admission is not self._admission or (seal.run_id,seal.scenario_id)!=(
              admission.current["run_id"],admission.current["scenario_id"]):
            raise ValueError("PUT relay does not own this worker and seal")
        admission.check()
        trust=self._trust()
        archive=_read_sealed_zip(path)
        if (store.sha(archive),len(archive))!=(seal.sha256,seal.size):
            raise ValueError("Local ZIP changed since finalization")
        print(json.dumps({"status":"sealed_for_external_put","run_id":seal.run_id,
             "scenario_id":seal.scenario_id,"sha256":seal.sha256,"bytes":seal.size},sort_keys=True),flush=True)
        frame=self._receive()
        try:
            state=transfer.publish_full_case_from_pod(trust=trust,put_envelope=frame["put_envelope"],
                                 put_url=frame["put_url"],archive=archive,journal_dir=path)
        finally:
            # Grant never resides in files, logs, environment variables or argv.
            frame.clear()
        if state not in ("put_ack_not_verified","ambiguous_get_only","already_attempted_get_only"):
            raise ValueError("Unverified publication response")
        print(json.dumps({"status":state,"run_id":seal.run_id,"independent_get_verified":False},sort_keys=True),
              flush=True)


def prepare(fd):
    from . import benchmark
    from .incremental_warm_live import WarmAdmission, _validate_storage
    profile,_=benchmark.load_profile("incremental-v1")
    admission=WarmAdmission(profile,full=True)  # signed first proof and exact clean Git release
    root,_=_validate_storage(admission,profile)
    out=store.durable_run(root,admission.current["run_id"],repo=benchmark.ROOT.parent)
    if out.exists() or out.is_symlink():
        raise ValueError("Attempt is already consumed; no replay")
    local_recovery.reject_unfenced_ports(benchmark.worker.URLS.values())
    return admission,PutRelay(fd,admission)


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("operation",choices=("preflight","run"))
    cli.add_argument("--publish-fd",type=int,required=True)
    a=cli.parse_args()
    try:
        admission,publisher=prepare(a.publish_fd)
        if a.operation=="preflight":
            a_scope=admission.authorities.scope
            result={"status":"protected_local_preflight_passed","git_sha":a_scope.allocation.git_sha,
                    "case_limit":a_scope.case_limit,"queued_gpu_work":False,"remote_channel_verified":False}
        else:
            from .incremental_warm_live import supervise_full_campaign
            outcome=supervise_full_campaign(admission=admission,publication=publisher)
            result={k:v for k,v in outcome.items() if k!="seals"}
            result["sealed_cases"]=len(outcome["seals"])
        print(json.dumps(result,sort_keys=True),flush=True)
    except (ValueError,TypeError,KeyError,OSError,RuntimeError,subprocess.SubprocessError,KeyboardInterrupt):
        # An exception must not echo grant URLs/provider headers. Runtime logs contain no bearer.
        print("Warm campaign not admitted or not completed. Check protected release, relay, and external cutoff.",
              file=sys.stderr)
        return 1
    finally:
        if a.publish_fd>=3:
            try:
                os.close(a.publish_fd)
            except OSError:
                pass
    return 0


if __name__=="__main__":
    # A module loaded with -m also has a __main__ identity; use the canonical
    # implementation so the protected relay type matches the supervisor check.
    from infra.runpod.n20.incremental_warm_start import main as launcher
    raise SystemExit(launcher())
