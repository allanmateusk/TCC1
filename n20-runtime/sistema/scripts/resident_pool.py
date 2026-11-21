"""Supervisor for opted-in per-node model processes; protocol apps still start per case."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import Path
from queue import Empty, Queue
import secrets
import subprocess
import sys
from threading import Lock, Thread
import time
from types import SimpleNamespace

from sistema.node.resident import ResidentError, exchange


class ResidentPool:
    """Own process lifetime and one lease at a time. No cloud calls here."""

    def __init__(self, root, *, deadline, start_process=None):
        root=Path(root)
        if not root.is_absolute() or root.resolve(strict=True)!=root or not root.is_dir():
            raise ValueError("Resident pool needs an exact durable root")
        if not math.isfinite(deadline) or not time.time()<deadline<=time.time()+168*3600:
            raise ValueError("Resident pool needs a bounded absolute deadline")
        self.root=root
        self.deadline=deadline
        # The private test transport only substitutes the subprocess launch, not the worker.
        self._spawn=start_process or subprocess.Popen
        self.test_transport=start_process is not None
        self._lock=Lock()
        self.children={}
        self.scope_options=None
        self.campaign_scope=None
        self.closed=False
        self.previous=None
        self.state=None
        self.attempts=set()

    def __enter__(self):
        return self

    def __exit__(self,*_):
        self.stop()

    def stop(self):
        from .runpod_worker import stop_processes
        self.closed=True
        try:
            stop_processes([child.process for child in self.children.values()])
        finally:
            for child in self.children.values():
                if child.process.stdout is not None:
                    child.process.stdout.close()

    def _healthy(self, check):
        check()
        if self.closed or time.time()>=self.deadline:
            raise InterruptedError("Resident pool closed or reached hard deadline")
        if any(child.process.poll() is not None for child in self.children.values()):
            raise ResidentError("A dedicated resident exited; no cold fallback")

    def _launch(self,node,gpu,options,cwd,env,check):
        check()
        admin=secrets.token_hex(32)
        # Body contains local technical configuration and an ephemeral capability only.
        process=self._spawn([sys.executable,"-B","-m","sistema.node.resident"],cwd=cwd,
                            env={**env,"CUDA_VISIBLE_DEVICES":gpu},stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,encoding="utf-8")
        child=SimpleNamespace(process=process,admin=admin,port=None)
        self.children[node]=child
        try:
            process.stdin.write(json.dumps(dict(node=node,admin=admin,root=str(self.root),model_config=options))+"\n")
            process.stdin.flush()
        finally:
            process.stdin.close()
        ready=Queue(maxsize=1)
        def bootstrap():
            try: ready.put(process.stdout.readline(1024))
            except (OSError,ValueError): ready.put("")
        Thread(target=bootstrap,daemon=True).start()
        until=time.monotonic()+20
        while time.monotonic()<until:
            self._healthy(check)
            try:
                reply=json.loads(ready.get(timeout=.25))
            except Empty:
                continue
            if reply.get("node")!=node or reply.get("pid")!=process.pid or type(reply.get("port")) is not int:
                raise ResidentError("Invalid or stale resident subprocess identity")
            child.port=reply["port"]
            return
        raise ResidentError("Timed out waiting for private resident boot")

    def _admin(self,node,op,*,timeout=10,**payload):
        child=self.children[node]
        reply=exchange(child.port,child.admin,dict(op=op,node=node,**payload),timeout=timeout)
        if (reply.get("node"),reply.get("pid"),reply.get("run"),reply.get("epoch")) != (
                node,child.process.pid,payload.get("run"),payload.get("epoch")):
            raise ResidentError("Resident administration identity mismatch")
        return reply

    def stats(self):
        return {node:self._admin(node,"stats") for node in self.children}

    def mark_verified(self, binding, receipt, *, digest, size):
        """Called only *after* the independent controller verifies the byte receipt."""
        from infra.runpod.n20.watchdog import matches_receipt
        with self._lock:
            if (self.closed or self.state!="complete" or self.previous!=(binding.run_id,binding.scenario_id)
                or time.time()>=min(self.deadline,binding.deadline)
                or not matches_receipt(binding,receipt) or receipt["sha256"]!=digest
                or type(size) is not int or size<=0 or type(receipt.get("bytes")) is not int
                or receipt["bytes"]!=size):
                raise ValueError("Previous case does not have an independently verified archive")
            self.state="verified"


    def _mark_candidate_verified(self, identity, *, deadline):
        """Offline-only release after the separate candidate controller accepted readback."""
        from infra.runpod.n20 import campaign_profiles
        with self._lock:
            scope=(identity.campaign_id,identity.profile_sha256)
            if (not self.test_transport or self.closed or self.state!="complete"
                or self.previous!=(identity.run_id,identity.scenario_id)
                or time.time()>=min(self.deadline,deadline)
                or self.campaign_scope!=scope or scope[0]!=campaign_profiles.INCREMENTAL_SCHEMA):
                raise ValueError("Not an active completed offline candidate")
            self.state="verified"


    def _admission(self, identity, resume):
        case=(identity.run_id,identity.scenario_id)
        if self.closed or time.time()>=self.deadline:
            raise InterruptedError("Resident pool closed or reached hard deadline")
        if resume:
            if self.previous!=case or self.state!="interrupted":
                raise ValueError("Only the same interrupted case may reopen its SQLite")
        elif (self.previous is not None and self.state!="verified") or identity.run_id in self.attempts:
            raise ValueError("Fresh run requires verified previous receipt and a fresh UUID")
        return case

    def precheck(self,identity,*,resume):
        if not self._lock.acquire(blocking=False):
            raise ResidentError("Another scenario lease is active")
        try:
            self._admission(identity,resume)
        finally:
            self._lock.release()

    @contextmanager
    def scenario(self, work, identity, tasks, configuration, snapshot, specifications, devices, cwd, env,
                 check, *, resume=False, case_deadline=None):
        from infra.runpod.n20.local_recovery import reject_unfenced_ports
        from .runpod_worker import URLS
        if not self._lock.acquire(blocking=False):
            raise ResidentError("Another scenario lease is active")
        authorized=False
        activated=[]
        try:
            now=time.time()
            end=min(self.deadline,case_deadline if case_deadline is not None else self.deadline)
            self._healthy(check)
            if not now<end or work.parent!=self.root or work.name!=identity.run_id or work.resolve()!=work:
                raise ValueError("Run root or deadline is out of the resident pool scope")
            case=self._admission(identity,resume)
            if len(tasks)!=identity.rounds or set(specifications)!={f"node-{i}" for i in range(configuration["nodes"])}:
                raise ValueError("Incomplete resident task or node scope")
            reject_unfenced_ports(URLS[n] for n in specifications)
            options={"model_name":str(snapshot),"revision":identity.model_revision,"quantization":configuration["quantization"],
                     "device":"cuda","dtype":configuration["dtype"],"max_new_tokens":configuration["max_new_tokens"],
                     "temperature":configuration["temperature"],"top_p":configuration["top_p"]}
            if (options["quantization"],options["dtype"])!=("none","bfloat16"):
                raise ValueError("Resident mode only permits the reviewed unquantized BF16 profile")
            assignment={node:devices[gpu] for node,(gpu,_) in specifications.items()}
            campaign_scope=(identity.campaign_id,identity.profile_sha256)
            if campaign_scope[0] is not None and not self.test_transport:
                raise ValueError('Real incremental residents remain unqualified')
            pinned=(options,assignment,identity.git_sha,identity.tasks_sha256,campaign_scope)
            if self.scope_options is not None and self.scope_options!=pinned:
                raise ValueError("Resident model, revision, worker code, task fixture or GPU assignment changed")
            self.scope_options=pinned
            self.campaign_scope=campaign_scope
            self.previous=case
            self.attempts.add(identity.run_id)
            self.state="active"
            authorized=True

            per_node={}
            for n in specifications:
                if n not in self.children:
                    self._launch(n,assignment[n],options,cwd,env,check)
                self._healthy(check)
                cap,epoch=secrets.token_hex(32),secrets.token_hex(32)
                raw=[]
                for r,t in enumerate(tasks):
                    seed=int.from_bytes(hashlib.sha256(f"{identity.seed}:{r}:{n}".encode()).digest()[:8],"big")&((1<<63)-1)
                    raw.append([t["id"],t["question"],seed])
                elapsed=end-time.time()
                if elapsed<=0:
                    raise InterruptedError("Deadline reached before resident activation")
                opened=self._admin(n,"open",token=cap,epoch=epoch,run=identity.run_id,deadline=end,
                                  tasks=raw,resume=bool(resume),timeout=min(elapsed,300))
                if opened.get("loads")!=1 or opened.get("mock") is not self.test_transport:
                    raise ResidentError("Exactly one appropriately scoped model load per resident is required")
                activated.append((n,epoch))
                per_node[n]={"N20_RESIDENT_PORT":str(self.children[n].port),"N20_RESIDENT_TOKEN":cap,
                             "N20_RESIDENT_EPOCH":epoch,"N20_RESIDENT_PID":str(self.children[n].process.pid)}
            yield per_node
            self.state="complete"
        except BaseException:
            if authorized:
                # Same-run replay only if existing worker verification passes on a
                # later explicit attempt; no path from interruption to a new case.
                self.state="interrupted"
                if len(activated)!=len(self.children) or any(x.process.poll() is not None for x in self.children.values()):
                    self.stop()
            raise
        finally:
            try:
                if authorized and not self.closed:
                    for n,epoch in activated:
                        self._admin(n,"close",run=identity.run_id,epoch=epoch)
            except BaseException:
                self.stop()  # Broken IPC or an in-flight/ambiguous request invalidates the entire pool.
                raise
            finally:
                self._lock.release()
