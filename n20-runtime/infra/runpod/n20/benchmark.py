"""Run one live N20 lab scenario on an already provisioned CUDA runner."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import sys
import tempfile
import time

from sistema.scripts import runpod_worker as worker
from sistema.scripts.runner_containers import _write as write_json_atomically
from . import campaign

ROOT = Path(__file__).resolve().parents[3]
PROFILE = Path(__file__).with_name("profile.json")


def load_profile():
    p = json.loads(PROFILE.read_text(encoding="utf-8"))
    if (p["schema"], p["nodes"], p["rounds"], p["gpu_count"], p["models_per_gpu"],
        p["inference_layout"], p["quantization"], p["dtype"]) != (
        "tcc-live-n20/v2", 20, 50, 2, 10, "per_node", "none", "bfloat16"
    ):
        raise ValueError("Invalid fixed N20 CUDA profile")
    if (p["model"], p["model_type"], p["thinking"]) != ("HuggingFaceTB/SmolLM3-3B", "smollm3", False):
        raise ValueError("This scenario is pinned to SmolLM3-3B with thinking disabled.")
    if p["pilot_rounds"] != [5]:
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
    campaign.validate(p)
    scenarios = {s["id"]: s for s in (*p["scenarios"], p["pilot"])}
    return p, scenarios


def scenario_args(profile, scenario, seed, rounds=None):
    pilot = scenario["id"] == "pilot"
    expected_rounds = profile["pilot_rounds"][0] if pilot else profile["rounds"]
    rounds = expected_rounds if rounds is None else rounds
    if rounds != expected_rounds:
        raise ValueError("Only the separate pilot supports 5 rounds; official scenarios require 50.")
    if seed not in profile["seeds"]:
        raise ValueError("Seed outside audited grid")
    protocol = {**profile["protocol"], **scenario}
    schedule = campaign.plan(profile, scenario, seed, rounds)
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
                                   "mechanism", "defense", "audit_mode", "malicious_strategy", "collusion_value")},
    }
    entry = {
        "id": f"{'pilot' if pilot else 'live'}-n20-r{rounds}-{scenario['id']}-s{seed}",
        "rounds": rounds, "semente": seed, "run_kind": "pilot" if pilot else "official",
        "expected_own_generations": profile["nodes"] * rounds,
        "fracao_maliciosos": scenario["malicious_nodes"] / profile["nodes"],
        "nota": protocol["score"], "honest_rounds": protocol["honest_rounds"], "audit_p": protocol["audit_p"],
        "audit_plan": schedule,
    }
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
    print("Offline: 17 official scenarios and one separate baseline pilot; 20 BF16 processes, 10 per GPU.")


def live(profile, scenario, seed, snapshot, out, rounds=None):
    if os.getenv("TCC_LIVE_N20_APPROVED") != "true":
        raise RuntimeError("Set explicit live execution approval before running.")
    if sys.platform != "linux":
        raise RuntimeError("Live launch requires a dedicated Linux CUDA runner.")
    config, entry = scenario_args(profile, scenario, seed, rounds)
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
    for i, free_gib in enumerate(free_vram_gib):
        with torch.cuda.device(i):
            if not torch.cuda.is_bf16_supported(including_emulation=False):
                raise RuntimeError(f"CUDA device {i} does not support native BF16.")
        if free_gib < required_gib:
            raise RuntimeError(f"CUDA device {i}: {free_gib:.2f} GiB free, {required_gib:.2f} GiB required.")
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    check_mapping(profile, scenario, seed, out, snapshot, rounds)
    metadata = {"profile": profile, "scenario": entry, "started": datetime.now(timezone.utc).isoformat(),
                "devices": [torch.cuda.get_device_name(i) for i in range(n)],
                "vram_per_node_peak_gib": per_node_gib, "vram_required_per_gpu_gib": required_gib,
                "vram_available_gib": free_vram_gib,
                "run_kind": entry["run_kind"], "rounds": entry["rounds"],
                "expected_own_generations": entry["expected_own_generations"],
                "quantization": profile["quantization"], "dtype": profile["dtype"],
                "completed": False, "git_sha": os.getenv("GITHUB_SHA", "")}
    record = out / "live-run.json"
    write_json_atomically(record, metadata)
    deadline = time.monotonic() + 60 * profile["timeout_minutes"]
    interrupted = False

    def stop(_signum, _frame):
        nonlocal interrupted
        interrupted = True

    def check():
        if interrupted or time.monotonic() >= deadline:
            raise InterruptedError("Live run cancelled or deadline reached.")

    last = None

    def progress(state, **fields):
        nonlocal last
        item = (state, tuple(fields.items())) if state != "running" else (state, fields["rounds_completed"])
        if item != last:
            print(state, fields, flush=True)
            last = item

    previous = {s: signal.signal(s, stop) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        worker.execute_scenario(out, entry, config, snapshot, devices, check, progress)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    metadata.update(completed=True, verified_own_generations=entry["expected_own_generations"],
                    finished=datetime.now(timezone.utc).isoformat())
    write_json_atomically(record, metadata)


def main():
    profile, scenarios = load_profile()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("preflight")
    plan = sub.add_parser("plan", help="Print the schedule without starting any process.")
    plan.add_argument("--scenario", choices=scenarios)
    run = sub.add_parser("run")
    run.add_argument("--scenario", choices=scenarios, required=True)
    run.add_argument("--seed", choices=profile["seeds"], type=int, required=True)
    run.add_argument("--snapshot", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--rounds", type=int, choices=(*profile["pilot_rounds"], profile["rounds"]),
                     default=None, help="Optional check: 5 for pilot, 50 for official scenarios.")
    args = parser.parse_args()
    if args.operation == "preflight":
        preflight(profile, scenarios)
    elif args.operation == "plan":
        chosen = (scenarios[args.scenario],) if args.scenario else tuple(scenarios.values())
        print(json.dumps([scenario_args(profile, x, 0)[1] for x in chosen], indent=2))
    else:
        live(profile, scenarios[args.scenario], args.seed, args.snapshot, args.output, args.rounds)


if __name__ == "__main__":
    main()
