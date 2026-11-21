"""Opt-in same-host controller bridge. No real provider or signer is configured here.

The controller/verifier are supplied by the independent protected deployment.
This module is not exposed by GitHub Actions or the normal per-case CLI.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import time
from typing import Callable
import uuid

from . import artifact_store, benchmark, campaign, r2_verified_pilot, watchdog
from .same_host_batch import SameHostBatch
from sistema.scripts.resident_pool import ResidentPool


@dataclass(frozen=True)
class WarmCase:
    run_id: str
    scenario_id: str
    resource_id: str
    git_sha: str
    profile_sha256: str
    deadline: float
    assert_active: Callable[[], None]

    def check(self):
        if time.time()>=self.deadline:
            raise InterruptedError("Independently reserved case expired")
        self.assert_active()

    def verify(self, *, resource_id, run_id, entry, scenario):
        if (run_id,scenario,resource_id,entry["run_kind"],entry["rounds"],entry["semente"])!=(
                self.run_id,self.scenario_id,self.resource_id,"official",50,0):
            raise ValueError("Reserved live case does not match the pinned batch")
        self.check()
        return self.deadline

    def verify_revision(self, git_sha, profile_sha256):
        if (git_sha,profile_sha256)!=(self.git_sha,self.profile_sha256):
            raise ValueError("Reserved warm case has a different code/profile identity")

    @classmethod
    def from_reservation(cls, issued, observer):
        if (issued.get("status"),issued.get("run_kind"),issued.get("nodes"),
            issued.get("rounds"),issued.get("seed"))!=("reserved","official",20,50,0):
            raise ValueError("The protected sequencer did not issue a fresh official reservation")
        if issued.get("scenario_id") not in campaign.IDS:
            raise ValueError("Reservation does not name an official case")
        return cls(*(issued[k] for k in ("run_id","scenario_id","resource_id","git_sha","profile_sha256","deadline")),
                   assert_active=observer)


def run_qualified(controller: SameHostBatch, durable_root: Path, snapshot: Path, *,
                  observe_exact, verify_transfer, check_scheduler):
    """Keep models while the independently verified single-host queue advances.

    The trusted plug-ins are mandatory: authenticated observer returns the exact
    owned Pod, the independent scheduler-check verifies watchdog/heartbeat and
    fencing from outside the runner, and transfer returns only an independent GET
    receipt for the sealed archive. There are no built-in live plug-ins.
    """
    if os.getenv("TCC_N20_RESIDENT_QUALIFIED")!="true" or os.getenv("TCC_LIVE_N20_APPROVED")!="true" \
       or os.getenv("TCC_N20_OFFICIAL_QUALIFIED")!="true":
        raise ValueError("Live same-host dispatch defaults to disabled")
    if type(controller) is not SameHostBatch or not all(callable(x) for x in (
            observe_exact,verify_transfer,check_scheduler)):
        raise ValueError("Independent controller and verifier are required")
    profile,scenarios=benchmark.load_profile()
    root=Path(durable_root).resolve(strict=True)
    if controller.queue.path.is_relative_to(root) or controller.queue.path.is_relative_to(benchmark.ROOT.parent):
        raise ValueError("Control journal cannot reside in the worker results or code")
    resource=controller.policy.resource_id
    cached=None
    observed=0.
    def active(*,fresh=False):
        nonlocal cached,observed
        if check_scheduler() is not True:
            raise InterruptedError("Independent scheduler is not confirmed active")
        now=time.monotonic()
        if fresh or cached is None or now-observed>=10:
            cached=observe_exact(resource)
            observed=now
        if not controller._matches(cached) or cached.phase!="active":
            raise ValueError("Externally owned resource is no longer confirmed active")
        return cached

    active(fresh=True)
    with ResidentPool(root,deadline=controller.plan.deadline) as pool:
        while True:
            observed_resource=active(fresh=True)
            started=time.time()
            attempt=controller.reserve(started,uuid.uuid4().hex,trusted=observed_resource)
            if attempt.get("status")!="reserved":
                raise ValueError("No new work allowed by the external batch controller")
            rid=attempt["run_id"]
            def assert_case():
                controller.require_active_case(time.time(),rid,trusted=active())
            scope=WarmCase.from_reservation(attempt,assert_case)
            try:
                benchmark.live(profile,scenarios[scope.scenario_id],0,snapshot,
                    durable_root=root,run_id=rid,resource_id=resource,resident_pool=pool,warm_case=scope)
                scope.check()
                out=artifact_store.durable_run(root,rid,repo=benchmark.ROOT.parent)
                data,key=r2_verified_pilot.prepare(out,rid)
                sha,n_bytes=artifact_store.sha(data),len(data)
                if not controller.seal(time.time(),rid,sha256=sha,size=n_bytes):
                    raise ValueError("Controller would not seal the exact archive")
                receipt=verify_transfer(out,run_id=rid,scenario_id=scope.scenario_id,bucket=controller.plan.bucket,
                    key=key,sha256=sha,size=n_bytes,deadline=scope.deadline)
                scope.check()
                confirmed=controller.finish(time.time(),rid,trusted_receipt=receipt,trusted=active(fresh=True))
                if confirmed.get("status")!="verified":
                    raise ValueError("Missing or invalid verified archive")
                if confirmed.get("stop_required") is True:
                    return confirmed
                binding=watchdog.Binding(rid,resource,controller.plan.bucket,scope.deadline,started,
                    controller.policy.stale_seconds,run_kind="official",scenario_id=scope.scenario_id)
                pool.mark_verified(binding,receipt,digest=sha,size=n_bytes)
            except BaseException as exc:
                # Durable controller pause is independent of local process shutdown.
                # Original exception stays visible; a scheduler detects loss of heartbeat if state cannot be updated.
                try:
                    controller.fail(time.time(),rid,"cancelled" if isinstance(exc,InterruptedError) else "failed")
                except Exception:
                    pass
                raise




def _transfer_steps(*, claim_upload, pod_upload, verify_transfer, out, **sealed):
    """Candidate callback seam; publish acknowledgement never advances the queue."""
    decision = claim_upload()
    status = decision.get("status")
    intent = decision.get("fixture_intent")
    if (status not in ("mock_put_reserved_once","get_only") or type(intent) is not dict
        or any(intent.get(k)!=sealed[k] for k in ("run_id","scenario_id","key","sha256","campaign_id","profile_sha256"))
        or intent.get("bytes")!=sealed["size"]):
        raise ValueError("The controller did not grant exact-object fixture transfer")
    if status=="mock_put_reserved_once":
        # A timeout/lost ACK may mean PUT succeeded. Never dispatch a second PUT.
        try:
            pod_upload(out, **sealed)
        except TimeoutError:
            pass
    return intent, verify_transfer(out, **sealed)


def _candidate_facts(out, entry, scope):
    import json
    plan=entry["audit_plan"]
    events=[json.loads(line) for line in (out/"audit-events.jsonl").read_text("utf-8").splitlines()]
    nodes={f"node-{i}" for i in range(20)}
    if [e["round"] for e in events]!=list(range(1,51)) or any(
        not e["complete"] or e["genesis"] or e["generation_barrier_nodes"]!=20 for e in events
    ):
        raise ValueError("Incomplete candidate audit and generation barrier evidence")
    audits=[e["round"] for e in events if e["planned"]]
    if audits!=plan["planned_rounds"] or any(
        set(e["oracle_by_node"])!=nodes or set(e["oracle_by_node"].values())!={"applied"}
        for e in events if e["planned"]
    ):
        raise ValueError("Candidate audit plan was not actually committed")
    if {e["round"]:sorted(e["simulated_absences"]) for e in events if e["simulated_absences"]} != {
        r:sorted(ids) for r,ids in plan["simulated_absences"].items()
    }:
        raise ValueError("Candidate absence evidence disagrees with the exact plan")
    summary=json.loads((out/"summary.json").read_text("utf-8"))
    if summary["config"]["ledgers_valid"] is not True:
        raise ValueError("Candidate ledgers were not verified")
    return {"run_kind":"official","scenario_id":entry["checkpoint_capture"]["scenario_id"],
            "nodes":20,"rounds":50,"verified_own_generations":1000,"verified_ledgers":20,
            "verified_genesis_rounds":[],"verified_audit_rounds":audits,
            "verified_intentional_absences":sum(len(e["simulated_absences"]) for e in events),**scope}


def run_incremental_candidate(controller, durable_root, snapshot, *, observe_exact,
                              pod_upload, verify_transfer, check_scheduler, start_test_process,
                              max_cases, observe_fixture=None):
    """Offline engineering proof; no launch or transfer to an external service.

    Real entry points remain closed. This uses the production worker and local
    resident leases, but accepts only an explicit CPU stand-in transport and
    emits non-ZIP JSON evidence. The deliberately named fixture callbacks are
    outside real benchmark admission and cannot make a live receipt.
    """
    from . import campaign_profiles, incremental_same_host as candidate
    from .checkpoint import Identity

    if type(controller) is not candidate.IncrementalSameHost or type(max_cases) is not int or not 1 <= max_cases <= 2:
        raise ValueError("Offline candidate proof requires exact local controller and a one/two-case bound")
    if not all(callable(x) for x in (observe_exact, pod_upload, verify_transfer, check_scheduler, start_test_process)):
        raise ValueError("Explicit offline fixtures are required")
    profile, scenarios = benchmark.load_profile("incremental-v1")
    scope = campaign_profiles.scope(profile)
    if controller.plan.profile_sha256 != scope["profile_sha256"]:
        raise ValueError("The local controller is bound to a different profile")
    root = Path(durable_root).resolve(strict=True)
    snap = Path(snapshot).resolve(strict=True)
    if (controller.queue.path.is_relative_to(root) or root.is_relative_to(benchmark.ROOT.parent.resolve())
        or not snap.is_relative_to(root) or not snap.is_dir() or any(snap.iterdir())):
        raise ValueError("Use external synthetic-only scratch, independent journal, and an empty model path")
    resource = controller.policy.resource_id
    reviews = []

    def active():
        if check_scheduler() is not True:
            raise InterruptedError("Simulated independent scheduler heartbeat is not confirmed")
        observation = observe_exact(resource)
        if (type(observation) is not watchdog.Resource
            or (observation.resource_id, observation.owner_run_id, observation.phase)
            != (resource,controller.plan.batch_id,"active")):
            raise InterruptedError("Offline exact-resource fixture did not match")
        return observation

    with ResidentPool(root, deadline=controller.plan.deadline, start_process=start_test_process) as pool:
        for _index in range(max_cases):
            observation = active()
            issue = controller.reserve(time.time(), uuid.uuid4().hex, trusted=observation)
            if (issue.get("status") != "reserved" or issue.get("candidate_only") is not True
                or not campaign_profiles.matches_record(issue,scope) or issue.get("scenario_id") not in scenarios
                or (issue.get("nodes"),issue.get("rounds"),issue.get("seed"),issue.get("git_sha"),issue.get("resource_id"))
                != (20,50,0,controller.plan.git_sha,resource)):
                raise ValueError("Unrecognized or rejected offline versioned grant")
            rid, sid, cutoff = (issue[k] for k in ("run_id","scenario_id","deadline"))

            last_control = -1.
            def still_active():
                nonlocal last_control
                t = time.time()
                if t >= cutoff:
                    raise InterruptedError("Offline case deadline")
                if time.monotonic()-last_control >= 1:
                    observation = active()
                    controller.require_active_case(time.time(),rid,trusted=observation)
                    last_control = time.monotonic()

            try:
                still_active()
                cfg,entry = benchmark.scenario_args(profile,scenarios[sid],0)
                entry["checkpoint_capture"] = {"run_id":rid,"git_sha":issue["git_sha"],
                    "tasks_sha256":profile["task_sha256"],"scenario_id":sid,**scope}
                out = artifact_store.durable_run(root,rid,repo=benchmark.ROOT.parent)
                artifact_store.create_run_directory(out)
                (out/"CPU_ONLY_NOT_PRODUCTION.txt").write_text("Local model stand-in; do not publish.\n",encoding="utf-8")
                # Candidate runs always use a fresh atomic UUID directory and
                # consume one nonreusable launch marker. This is not Linux
                # production's fcntl lease and does not provide recovery.
                with (out/"candidate-started.once").open("xb"):
                    pass
                benchmark.worker.execute_scenario(out,entry,cfg,snap,["",""],still_active,
                    lambda *_a,**_kw: None,resident_pool=pool,case_deadline=cutoff)
                stats = pool.stats()
                if len(stats) != 20 or any(s["mock"] is not True or s["loads"]!=1
                       or len(s["by_run"].get(rid,{}))!=50 or set(s["by_run"][rid].values())!={1}
                       for s in stats.values()):
                    raise ValueError("Expected exactly 1,000 physical CPU stand-in samples per case")
                if (list(out.glob("node-models/*/model-runtime.json")) or
                    len(list(out.glob("checkpoint-[0-9][0-9].json"))) != 50):
                    raise ValueError("Missing checkpoints or unexpected real-model attestation")
                checks = {"schema":"tcc-n20-offline-worker-proof/v1","model_is_stand_in":True,
                          "run_id":rid,"physical_samples":1000,**_candidate_facts(out,entry,scope)}
                if observe_fixture is not None:
                    observe_fixture(out,entry,stats)
                data=artifact_store.json_bytes(checks)
                artifact_store.write_atomic(out/"offline-proof.json",data)
                sha,n_bytes = artifact_store.sha(data),len(data)
                if not controller.seal(time.time(),rid,sha256=sha,size=n_bytes):
                    raise ValueError("Candidate controller rejected local proof seal")
                transport = dict(run_id=rid, scenario_id=sid,bucket=controller.plan.bucket,
                    key=campaign_profiles.candidate_key(rid),sha256=sha,size=n_bytes,deadline=cutoff,**scope)
                intent,received=_transfer_steps(claim_upload=lambda:controller.reserve_upload(time.time(),rid),
                    pod_upload=pod_upload,verify_transfer=verify_transfer,out=out,**transport)
                import json
                facts=json.loads(received) if received is not None else None
                if facts is not None and (facts.get("schema"),facts.get("model_is_stand_in"),facts.get("run_id")) != (
                        "tcc-n20-offline-worker-proof/v1",True,rid):
                    raise ValueError("Downloaded bytes are not the scoped synthetic proof")
                proof=candidate.verify_fixture_get(intent,received,facts)
                observed=active()
                confirmed=controller.finish(time.time(),rid,trusted_receipt=proof,trusted=observed)
                if confirmed.get("status")!="mock_verified":
                    raise ValueError("Independent offline readback was not verified")
                ident=Identity(**benchmark.worker.yaml.safe_load((out/"config.yaml").read_text("utf-8"))["checkpoint_identity"])
                pool._mark_candidate_verified(ident,deadline=cutoff)
                reviews.append({**checks,"pids":sorted(x["pid"] for x in stats.values())})
                if confirmed.get("stop_required") is True:
                    break
            except BaseException as exc:
                try:
                    controller.fail(time.time(),rid,"cancelled" if isinstance(exc,InterruptedError) else "failed")
                except Exception:
                    pass
                raise
        processes = [x.process for x in pool.children.values()]
    if any(p.poll() is None for p in processes):
        raise RuntimeError("Offline candidate cleanup did not close resident processes")
    return reviews
