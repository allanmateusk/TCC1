"""Run one live N20 lab scenario on an already provisioned CUDA runner."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

from sistema.scripts import runpod_worker as worker
from sistema.scripts.runner_containers import _write as write_json_atomically
from . import artifact_store, campaign, watchdog

ROOT = Path(__file__).resolve().parents[3]
from . import campaign_profiles

PROFILE = Path(__file__).with_name("profile.json")


def load_profile(selector="legacy"):
    p = campaign_profiles.resolve(selector)
    if (p["nodes"], p["rounds"], p["gpu_count"], p["models_per_gpu"],
        p["inference_layout"], p["quantization"], p["dtype"]) != (
        20, 50, 2, 10, "per_node", "none", "bfloat16"
    ):
        raise ValueError("Invalid fixed N20 CUDA profile")
    if (p["model"], p["model_type"], p["thinking"]) != ("HuggingFaceTB/SmolLM3-3B", "smollm3", False):
        raise ValueError("This scenario is pinned to SmolLM3-3B with thinking disabled.")
    if not campaign_profiles.scope(p) and p["pilot_rounds"] != [5]:
        raise ValueError("Baseline pilot length must be 5.")
    if not 0 < p["timeout_minutes"] <= 110:
        raise ValueError("The runtime limit must not exceed 110 minutes")
    taskfile = ROOT / p["task_file"]
    raw = taskfile.read_bytes().replace(b"\r\n", b"\n")  # Canonical Git LF
    if hashlib.sha256(raw).hexdigest() != p["task_sha256"]:
        raise ValueError("Task file digest mismatch")
    tasks = json.loads(raw)["tarefas"]
    if len(tasks) != 50 or len({t["id"] for t in tasks}) != 50:
        raise ValueError("Need 50 distinct fixed tasks")
    scenarios = {s["id"]: s for s in p["scenarios"]}
    if "pilot" in p:
        scenarios["pilot"] = p["pilot"]
    return p, scenarios


def scenario_args(profile, scenario, seed, rounds=None):
    pilot = scenario["id"] == "pilot"
    scope = campaign_profiles.scope(profile)
    if pilot and scope:
        raise ValueError("This campaign has no pilot phase")
    expected_rounds = profile["pilot_rounds"][0] if pilot else profile["rounds"]
    rounds = expected_rounds if rounds is None else rounds
    if rounds != expected_rounds:
        raise ValueError("Only the separate pilot supports 5 rounds; official scenarios require 50.")
    if seed not in profile["seeds"]:
        raise ValueError("Seed outside audited grid")
    protocol = {**profile["protocol"], **scenario}
    schedule = campaign_profiles.plan(profile, scenario, seed, rounds)
    if schedule["genesis_rounds"]:
        protocol["signal"] = "hybrid"
    config = {
        "nodes": profile["nodes"], "gpu_count": profile["gpu_count"],
        "models_per_gpu": profile["models_per_gpu"], "model": profile["model"],
        "model_revision": profile["model_revision"], "task_bank": profile["task_file"],
        "quantization": profile["quantization"], "dtype": profile["dtype"],
        "max_new_tokens": profile["max_new_tokens"], "temperature": profile["temperature"],
        "top_p": profile["top_p"], "noise_mode": "multiplicative",
        "noise_distance": protocol["relative_noise_distance"],
        **{k: protocol[k] for k in ("degree", "topology", "signal", "consensus_mode", "consensus_center",
                                   "mechanism", "defense", "audit_mode", "malicious_strategy")},
        "collusion_value":protocol.get("collusion_value",999),
    }
    entry = {
        "id": campaign_profiles.experiment_id(profile,scenario["id"],seed,rounds),
        "rounds": rounds, "semente": seed, "run_kind": "pilot" if pilot else "official",
        "expected_own_generations": profile["nodes"] * rounds,
        "fracao_maliciosos": scenario["malicious_nodes"] / profile["nodes"],
        "nota": protocol["score"], "honest_rounds": protocol["honest_rounds"], "audit_p": protocol["audit_p"],
        "audit_plan": schedule,
    }
    if scope:
        config.update({k: protocol[k] for k in ("noise_policy","consensus_alpha","oracle_alpha","test_every")})
        config["audit_mode"] = scenario["audit"]
        entry.update(scope,collusion=scenario["collusion"],unstable_nodes=scenario["unstable_nodes"])
    return config, entry


def check_mapping(profile, scenario, seed, root, snapshot, rounds=None):
    config, entry = scenario_args(profile, scenario, seed, rounds)
    processes, protocol = worker.scenario_configuration(config, entry, root, snapshot)
    keys = list(processes)
    per_gpu = [sum(slot == gpu for slot, _ in processes.values()) for gpu in range(profile["gpu_count"])]
    if keys != [f"node-{i}" for i in range(20)] or per_gpu != [10, 10]:
        raise ValueError("Bad node or GPU mapping")
    if len({node["url"] for node in protocol["nodes"]}) != 20:
        raise ValueError("Endpoints must be distinct")
    malicious = 0
    for node_id, (_, env) in processes.items():
        if any(env.get(k) != v for k, v in {
            "MODEL_RUN_ID": entry["id"], "MODEL_DEVICE": "cuda",
            "MODEL_QUANTIZATION": profile["quantization"], "MODEL_DTYPE": profile["dtype"],
            "ROUNDS": str(entry["rounds"]),
            "INFERENCE_MODE": "model", "MODEL_CACHE_DIR": str(root / "node-models" / node_id),
        }.items()):
            raise ValueError("Unexpected node inference runtime")
        malicious += env.get("PROFILE") == "malicious"
    if malicious != scenario["malicious_nodes"]:
        raise ValueError("Bad malicious node count")
    if protocol["audit_rounds_override"] != [r-1 for r in entry["audit_plan"]["planned_rounds"]]:
        raise ValueError("Orchestrator audit calendar differs from plan")
    for node_id, (_, env) in processes.items():
        if json.loads(env["AUDIT_ROUNDS_OVERRIDE"]) != protocol["audit_rounds_override"]:
            raise ValueError(f"Node {node_id} audit calendar differs from coordinator")


def preflight(profile, scenarios):
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        for scenario in scenarios.values():
            for seed in profile["seeds"]:
                check_mapping(profile, scenario, seed, root, root)
    if campaign_profiles.scope(profile):
        print(f"Offline candidate only: {len(scenarios)} versioned incremental cases; 20 BF16 processes, 10 per GPU.")
    else:
        print("Offline: 17 official scenarios and one separate baseline pilot; 20 BF16 processes, 10 per GPU.")


def verify_controller_arm(path, run_dir, resource_id, run_id, *, run_kind="pilot", scenario_id="pilot", now=None,
                          campaign_id=None, profile_sha256=None):
    """Require separately owned controller state; deployment must also prove scheduler/TTL."""
    if path is None or not Path(path).is_absolute() or Path(path).is_symlink():
        raise ValueError("An independent controller arm record is required")
    path = Path(path).resolve(strict=True)
    if path.is_relative_to(run_dir.parent) or path.is_relative_to(ROOT.parent):
        raise ValueError("Controller state cannot reside in the runner project or output volume")
    tick = time.time() if now is None else now
    binding = watchdog.require_armed(path,tick,run_id=run_id,run_kind=run_kind,scenario_id=scenario_id,
                                     campaign_id=campaign_id,profile_sha256=profile_sha256)
    if binding.resource_id != resource_id or binding.bucket != "tcc":
        raise ValueError("Controller state is stale, closed or bound to another resource")
    return binding.deadline


def live(profile, scenario, seed, snapshot, out=None, rounds=None, *, durable_root=None, run_id=None,
         controller_state=None, resource_id=None, recovery_permit=None, resident_pool=None, warm_case=None):
    if campaign_profiles.scope(profile):
        raise RuntimeError("Incremental campaign is not qualified; plan and preflight only.")
    if os.getenv("TCC_LIVE_N20_APPROVED") != "true":
        raise RuntimeError("Set explicit live execution approval before running.")
    if sys.platform != "linux":
        raise RuntimeError("Live launch requires a dedicated Linux CUDA runner.")
    config, entry = scenario_args(profile, scenario, seed, rounds)
    if entry["run_kind"] == "official" and os.getenv("TCC_N20_OFFICIAL_QUALIFIED") != "true":
        raise ValueError("Official case disabled until the independent provider lifecycle is qualified")
    if recovery_permit is not None and os.getenv("TCC_N20_RECOVERY_QUALIFIED") != "true":
        raise ValueError("Real restart disabled until independent controller fencing is qualified")
    if (resident_pool is None)!=(warm_case is None):
        raise ValueError("Resident pool and independent batch grant must be supplied together")
    if resident_pool is not None and os.getenv("TCC_N20_RESIDENT_QUALIFIED")!="true":
        raise ValueError("Resident GPU execution is disabled until the independent batch is qualified")
    if resident_pool is not None:
        from sistema.scripts.resident_pool import ResidentPool
        if not isinstance(resident_pool,ResidentPool) or resident_pool.test_transport:
            raise ValueError("A test or unknown resident launcher cannot produce real evidence")
    run_dir = artifact_store.durable_run(durable_root, run_id, repo=ROOT.parent)
    if resident_pool is None:
        provider_deadline = verify_controller_arm(controller_state, run_dir, resource_id, run_id,
                                                  run_kind=entry["run_kind"], scenario_id=scenario["id"])
    else:
        from .warm_batch import WarmCase
        if not isinstance(warm_case,WarmCase) or controller_state is not None:
            raise ValueError("Use the independently owned batch, not the per-case stop controller")
        provider_deadline=warm_case.verify(resource_id=resource_id,run_id=run_id,entry=entry,scenario=scenario["id"])
    if out is not None and out.resolve() != run_dir:
        raise ValueError("Output must match durable-root/run-id")
    git_sha = subprocess.check_output(["git", "-C", str(ROOT.parent), "rev-parse", "HEAD"], text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", git_sha):
        raise ValueError("An identified Git checkout is required")
    if subprocess.run(["git", "-C", str(ROOT.parent), "diff", "--quiet", "HEAD", "--", "n20-runtime"]).returncode:
        raise ValueError("Live inference requires a clean tracked runtime at the recorded commit")
    if warm_case is not None:
        warm_case.verify_revision(git_sha,artifact_store.sha((Path(__file__).with_name("profile.json")).read_bytes().replace(b"\r\n",b"\n")))
    snapshot = snapshot.resolve(strict=True)
    if snapshot.name != profile["model_revision"] or not (snapshot / "config.json").is_file() or not list(snapshot.glob("*.safetensors")):
        raise ValueError("Select the preinstalled snapshot pinned by profile.json.")
    config_json = json.loads((snapshot / "config.json").read_text(encoding="utf-8"))
    if config_json.get("model_type") != profile["model_type"] or not (snapshot / "chat_template.jinja").is_file():
        raise ValueError("Invalid SmolLM3 snapshot architecture or missing official template.")
    measured = os.getenv("TCC_LIVE_N20_PEAK_VRAM_PER_NODE_GIB", "")
    try:
        per_node_gib = float(measured)
    except ValueError as exc:
        raise ValueError("Record the measured site-specific peak VRAM per Smol node first.") from exc
    weights_gib = 6_150_197_248 / 1024 ** 3  # BF16 tensor bytes in the pinned snapshot.
    if not math.isfinite(per_node_gib) or per_node_gib < weights_gib:
        raise ValueError("Peak VRAM must be measured and cannot be below the BF16 weights.")
    required_gib = per_node_gib * profile["models_per_gpu"] * profile["vram_headroom"]
    import torch
    n = profile["gpu_count"]
    if not torch.cuda.is_available() or torch.cuda.device_count() != n:
        raise RuntimeError("Select exactly two dedicated CUDA devices.")
    devices = os.getenv("CUDA_VISIBLE_DEVICES", "0,1").split(",")
    if len(devices) != n or len(set(devices)) != n or not all(devices):
        raise RuntimeError("Invalid CUDA_VISIBLE_DEVICES mapping.")
    free_vram_gib = [torch.cuda.mem_get_info(i)[0] / 1024 ** 3 for i in range(n)]
    already_loaded=resident_pool is not None and bool(resident_pool.children)
    if already_loaded and (resident_pool.closed or len(resident_pool.children)!=profile["nodes"]):
        raise ValueError("Warmed GPU set is incomplete; cold fallback is forbidden")
    # On subsequent reserved cases the verified residents already own weights.
    # Subtract only pinned tensor bytes, never a measured peak or safety margin.
    free_floor=required_gib if not already_loaded else required_gib - weights_gib*profile["models_per_gpu"]
    for i, free_gib in enumerate(free_vram_gib):
        with torch.cuda.device(i):
            if not torch.cuda.is_bf16_supported(including_emulation=False):
                raise RuntimeError(f"CUDA device {i} does not support native BF16.")
        if free_gib < free_floor:
            raise RuntimeError(f"CUDA device {i}: {free_gib:.2f} GiB free, {free_floor:.2f} GiB required.")
    from . import local_recovery
    out = run_dir
    entry["checkpoint_capture"]={"run_id":run_id,"git_sha":git_sha,"tasks_sha256":profile["task_sha256"],
                                 "scenario_id":scenario["id"],**campaign_profiles.scope(profile)}
    restart_digest=None
    if recovery_permit is None:
        artifact_store.create_run_directory(out)
    else:
        if out.is_symlink() or not out.is_dir():
            raise ValueError("Recovery requires the original durable run directory")
        restart_digest=local_recovery.external_permit(recovery_permit,out,now=time.time(),provider_deadline=provider_deadline,
            expected={"run_id":run_id,"scenario_id":scenario["id"],"resource_id":resource_id,
                      "git_sha":git_sha,"snapshot_revision":profile["model_revision"]})
    with local_recovery.acquire_executor(out):
        if restart_digest is not None:
            local_recovery.reject_unfenced_ports(worker.URLS.values())
            old_raw=artifact_store.read_file(out,"live-run.json")
            old=json.loads(old_raw)
            expected={"run_id":run_id,"scenario_id":scenario["id"],"git_sha":git_sha,
                      "model_revision":profile["model_revision"],"experiment_id":entry["id"],"seed":seed,
                      "run_kind":entry["run_kind"],"model_is_stand_in":False,"completed":False}
            if any(old.get(k)!=v for k,v in expected.items()) or old.get("status") not in ("running","failed","cancelled"):
                raise ValueError("Run lifecycle is complete or differs from the protected recovery identity")
            artifact_store.write_atomic(out/f"live-before-recovery-{restart_digest[:16]}.json",old_raw)
        _execute_live(out,entry,config,profile,scenario,seed,snapshot,rounds,git_sha,run_id,provider_deadline,
                      per_node_gib,required_gib,free_vram_gib,devices,torch,restart_digest,
                      resident_pool=resident_pool,warm_case=warm_case)


def _execute_live(out,entry,config,profile,scenario,seed,snapshot,rounds,git_sha,run_id,provider_deadline,
                  per_node_gib,required_gib,free_vram_gib,devices,torch,restart_digest, *, resident_pool=None,warm_case=None):
    n=len(devices)
    check_mapping(profile, scenario, seed, out, snapshot, rounds)
    metadata = {"profile": profile, "scenario": entry, "started": datetime.now(timezone.utc).isoformat(),
                "run_id": run_id, "experiment_id": entry["id"], "scenario_id": scenario["id"], "seed": seed,
                "nodes": profile["nodes"], "model": profile["model"], "model_revision": profile["model_revision"],
                "model_is_stand_in": False, "status": "running", "controller_deadline_epoch": provider_deadline,
                "devices": [torch.cuda.get_device_name(i) for i in range(n)],
                "vram_per_node_peak_gib": per_node_gib, "vram_required_per_gpu_gib": required_gib,
                "vram_available_gib": free_vram_gib,
                "run_kind": entry["run_kind"], "rounds": entry["rounds"],
                "expected_own_generations": entry["expected_own_generations"],
                "quantization": profile["quantization"], "dtype": profile["dtype"],
                "completed": False, "git_sha": git_sha,**campaign_profiles.scope(profile)}
    if resident_pool is not None:
        metadata["layout"]="resident_model_per_node"
    record = out / "live-run.json"
    write_json_atomically(record, metadata)
    deadline = time.monotonic() + min(60 * profile["timeout_minutes"], provider_deadline - time.time())
    interrupted = False
    last_heartbeat = -1e12

    def heartbeat(force=False):
        nonlocal last_heartbeat
        tick = time.monotonic()
        if force or tick - last_heartbeat >= 15:
            artifact_store.write_atomic(out / "heartbeat.json", artifact_store.json_bytes(
                {"run_id": run_id, "heartbeat_at_epoch": time.time(),**campaign_profiles.scope(profile)}), replace=True)
            last_heartbeat = tick

    heartbeat(force=True)

    def stop(_signum, _frame):
        nonlocal interrupted
        interrupted = True

    def check():
        if interrupted or time.monotonic() >= deadline:
            raise InterruptedError("Live run cancelled or deadline reached.")
        heartbeat()
        if warm_case is not None:
            warm_case.check()

    last = None

    def progress(state, **fields):
        nonlocal last
        item = (state, tuple(fields.items())) if state != "running" else (state, fields["rounds_completed"])
        if item != last:
            print(state, fields, flush=True)
            last = item

    previous = {s: signal.signal(s, stop) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        worker.execute_scenario(out, entry, config, snapshot, devices, check, progress,
                                restart_digest=restart_digest,resident_pool=resident_pool,
                                case_deadline=provider_deadline)
        if warm_case is not None:
            check()
        finalized = {**metadata, "status": "verified_local", "completed": True,
                     "verified_own_generations": entry["expected_own_generations"],
                     "finished": datetime.now(timezone.utc).isoformat()}
        finalized = artifact_store.finalize_run(out, finalized)
        artifact_store.write_atomic(record, artifact_store.json_bytes(finalized), replace=True)
    except BaseException as exc:
        metadata.update(status="cancelled" if isinstance(exc, InterruptedError) else "failed",
                        failure_kind=type(exc).__name__, finished=datetime.now(timezone.utc).isoformat())
        artifact_store.write_atomic(record, artifact_store.json_bytes(metadata), replace=True)
        raise
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main():
    bootstrap=argparse.ArgumentParser(add_help=False)
    bootstrap.add_argument("--campaign",choices=campaign_profiles.SELECTORS,default="legacy")
    selected,_=bootstrap.parse_known_args()
    profile, scenarios = load_profile(selected.campaign)
    parser = argparse.ArgumentParser(description=__doc__,parents=[bootstrap])
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("preflight")
    plan = sub.add_parser("plan", help="Print the schedule without starting any process.")
    plan.add_argument("--scenario", choices=scenarios)
    run = sub.add_parser("run")
    run.add_argument("--scenario", choices=scenarios, required=True)
    run.add_argument("--seed", choices=profile["seeds"], type=int, required=True)
    run.add_argument("--snapshot", type=Path, required=True)
    run.add_argument("--durable-root", type=Path, required=True)
    run.add_argument("--run-id", required=True)
    run.add_argument("--controller-state", type=Path, required=True)
    run.add_argument("--recovery-permit", type=Path, help="Controller-owned fence attestation for a qualified same-run restart.")
    run.add_argument("--resource-id", required=True)
    run.add_argument("--output", type=Path, help="Optional check: must equal durable-root/run-id.")
    run.add_argument("--rounds", type=int, choices=(*profile.get("pilot_rounds",()), profile["rounds"]),
                     default=None, help="Optional check: 5 for pilot, 50 for official scenarios.")
    args = parser.parse_args()
    if args.operation == "preflight":
        preflight(profile, scenarios)
    elif args.operation == "plan":
        chosen = (scenarios[args.scenario],) if args.scenario else tuple(scenarios.values())
        print(json.dumps([scenario_args(profile, x, 0)[1] for x in chosen], indent=2))
    else:
        live(profile, scenarios[args.scenario], args.seed, args.snapshot, args.output, args.rounds,
             durable_root=args.durable_root, run_id=args.run_id,
             controller_state=args.controller_state, resource_id=args.resource_id,
             recovery_permit=args.recovery_permit)


if __name__ == "__main__":
    main()
