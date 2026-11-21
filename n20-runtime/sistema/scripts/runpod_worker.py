"""Runs the actual N20 distributed protocol with one resident model per node."""
from __future__ import annotations

import csv
from contextlib import ExitStack, nullcontext
from hashlib import sha256
import json
import os
import secrets
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen

import yaml

from .gen_compose import build_configuration, parse_args
from .runner_containers import _verify_per_node

ROOT = Path(__file__).resolve().parents[2]
URLS = {f"node-{index}": f"http://127.0.0.1:{18100 + index}" for index in range(20)}




def scenario_configuration(c, entry, work, snapshot):
    plan = entry.get("audit_plan")
    policy = c.get("noise_policy", "legacy")
    if policy not in ("legacy", "incremental_upward"):
        raise ValueError("Unknown BF16 campaign noise policy")
    incremental = policy == "incremental_upward"
    if incremental:
        if (c["model"], c["quantization"], c["dtype"], c["nodes"], c["mechanism"],
                c["malicious_strategy"], entry["honest_rounds"]) != (
                "HuggingFaceTB/SmolLM3-3B", "none", "bfloat16", 20, "ema", "knows_schedule", 5):
            raise ValueError("Incremental path requires the pinned dedicated BF16 protocol")
        if (type(entry.get("collusion")) is not bool or not isinstance(plan, dict) or
                c.get("audit_mode") not in ("fixed", "random") or c["audit_mode"] != plan.get("mode") or
                plan.get("genesis_rounds") != [] or c.get("test_every", 10) != 10 or
                (c.get("consensus_alpha"), c.get("oracle_alpha")) != (.05, .95)):
            raise ValueError("Incomplete incremental topology, audit, collusion or EMA configuration")
        rounds = plan.get("planned_rounds")
        if (not isinstance(rounds, list) or any(type(r) is not int or not 1 <= r <= entry["rounds"] for r in rounds)
                or rounds != sorted(set(rounds))):
            raise ValueError("Invalid explicit incremental audit dates")
        absences = plan.get("simulated_absences")
        if not isinstance(absences, dict) or any(
            not isinstance(r, int) or isinstance(r, bool) or not 1 <= r <= entry["rounds"]
            or not isinstance(ids, list) or any(node not in URLS for node in ids)
            or len(ids) != len(set(ids)) for r, ids in absences.items()
        ):
            raise ValueError("Invalid planned incremental absences")
    values = {
        "nodes": c["nodes"], "rounds": entry["rounds"], "num-tasks": entry["rounds"],
        "seed": entry["semente"], "malicious": entry["fracao_maliciosos"], "degree": c["degree"],
        "dataset": "task_bank", "task-bank": ROOT / c["task_bank"], "mode": "real",
        "inference-mode": "model", "model": c["model"], "model-run-id": entry["id"],
        "model-snapshot": snapshot, "model-revision": c["model_revision"],
        "model-quantization": c["quantization"], "model-dtype": c["dtype"],
        "gpu-count": c["gpu_count"], "models-per-gpu": c["models_per_gpu"],
        "topology": c["topology"], "signal": c["signal"], "consensus-mode": c["consensus_mode"],
        "consensus-center": c["consensus_center"], "mechanism": c["mechanism"], "defense": c["defense"],
        "validation-score": entry["nota"], "malicious-strategy": c["malicious_strategy"],
        "honest-rounds": entry["honest_rounds"], "audit-mode": c["audit_mode"],
        "audit-p": entry["audit_p"],
        "noise-mode": c.get("noise_mode", "relative"), "noise-distance": c.get("noise_distance", .2),
        "timeout-s": 600, "output-dir": work, "experiment-id": entry["id"],
    }
    if incremental:
        values.update({"test-every": c.get("test_every", 10),
                       "consensus-alpha": c["consensus_alpha"], "oracle-alpha": c["oracle_alpha"]})
    else:
        values["collusion-value"] = c["collusion_value"]
    services, config = build_configuration(parse_args([
        part for key, value in values.items() for part in (f"--{key}", str(value))
    ]))
    if incremental:
        config.update(noise_policy=policy, collusion=entry["collusion"], explicit_audit_schedule=True)
        if not config["defense"] == "all":
            raise ValueError("Incremental mode requires split-alpha and oracle quorum bypass")
    if plan is not None:
        config["campaign_plan"] = plan
        config["audit_rounds_override"] = [r - 1 for r in plan["planned_rounds"]]
        config["leaderless_calibration"] = bool(plan["genesis_rounds"])
        config["calibration_rounds"] = len(plan["genesis_rounds"])
    if incremental:
        # Replicas know only the assigned question digests, never pass answer keys by IPC.
        tasks = json.loads((ROOT / c["task_bank"]).read_text(encoding="utf-8"))["tarefas"][:entry["rounds"]]
        if len(tasks) != entry["rounds"]:
            raise ValueError("Incremental dataset does not match the number of rounds")
        task_pins = json.dumps([[t["id"], sha256(t["question"].encode("utf-8")).hexdigest()] for t in tasks],
                               separators=(",", ":"))
    processes = {}
    for node in config["nodes"]:
        node_id = node["id"]
        node["url"] = URLS[node_id]
        service = services[node_id]
        env = dict(service["environment"], NODE_URLS=json.dumps(URLS),
                   MODEL_NAME=str(snapshot), MODEL_CACHE_DIR=str(work / "node-models" / node_id),
                   MODEL_MAX_NEW_TOKENS=str(c["max_new_tokens"]),
                   MODEL_TEMPERATURE=str(c["temperature"]), MODEL_TOP_P=str(c["top_p"]))
        if incremental:
            env.update(N20_NOISE_POLICY=policy, N20_COLLUSION="1" if entry["collusion"] else "0",
                       N20_EXPLICIT_AUDIT_SCHEDULE="1", N20_INCREMENTAL_TASK_PINS=task_pins)
            if "MALICIOUS_VALUE" in env:
                raise ValueError("Incremental mode must not supply a fixed malicious answer")
        if plan is not None:
            env.update(AUDIT_ROUNDS_OVERRIDE=json.dumps(config["audit_rounds_override"]),
                       LEADERLESS_CALIBRATION="1" if config["leaderless_calibration"] else "0",
                       CALIBRATION_ROUNDS=str(config["calibration_rounds"]),
                       N20_SIMULATED_ABSENCES=json.dumps(sorted(
                           int(r)-1 for r, absent in plan["simulated_absences"].items() if node_id in absent)))
        gpu = int(service["deploy"]["resources"]["reservations"]["devices"][0]["device_ids"][0])
        processes[node_id] = (gpu, env)
    return processes, config






def stop_processes(processes):
    for process in processes:
        if process.poll() is None:
            process.terminate()
    until = time.monotonic() + 8
    for process in processes:
        try:
            process.wait(timeout=max(0, until - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def _completed_campaign_rounds(work):
    path = work / "audit-events.jsonl"
    complete = []
    if path.exists():
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.endswith("\n"):
                    break  # a concurrent reader caught the writer on its last line
                row = json.loads(line)
                if not row["complete"]:
                    break
                if row["round"] != len(complete)+1:
                    raise RuntimeError("Non-contiguous verified round telemetry")
                complete.append(row)
    return complete


def _verify_campaign(work, config, entry):
    from collections import Counter
    planned = entry["audit_plan"]
    nodes = {node["id"] for node in config["nodes"]}
    completed = _completed_campaign_rounds(work)
    if len(completed) != entry["rounds"]:
        raise RuntimeError("Campaign evidence does not cover every round")
    for row in completed:
        r = row["round"]
        if (
            row["genesis"] != (r in planned["genesis_rounds"])
            or row["planned"] != (r in planned["planned_rounds"])
            or row["preempted"] != (r in planned["preempted_rounds"])
            or set(row["simulated_absences"]) != set(planned["simulated_absences"].get(r, ()))
            or set(row["oracle_by_node"]) != (nodes if row["planned"] or row["genesis"] else set())
            or any(status != "applied" for status in row["oracle_by_node"].values())
        ):
            raise RuntimeError(f"Campaign evidence deviates from round {r} plan")
    with (work / "leadership.csv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    reference = [int(row["round_index"])+1 for row in rows if row["is_reference"] == "1"]
    if reference != list(range(1, entry["rounds"]+1)):
        raise RuntimeError("Unexpected reference leadership coverage")
    for row in rows:
        if int(row["round_index"])+1 in planned["genesis_rounds"] and (
            row["outcome"] != "calibration" or row["leader"] or row["auditor"]
        ):
            raise RuntimeError("Genesis has unexpected election or quorum")
    with (work / "reputation_history.csv").open(encoding="utf-8", newline="") as stream:
        history = Counter((int(row["checkpoint"]),row["node_id"]) for row in csv.DictReader(stream))
    if history != Counter((r,n) for r in range(entry["rounds"]+1) for n in nodes):
        raise RuntimeError("Unexpected reputation checkpoint coverage")
    for node in nodes:
        snap = json.loads((work / "ledgers" / f"{node}.json").read_text(encoding="utf-8"))
        if not snap["valid"] or [r["round_index"]+1 for r in snap["records"] if r["kind"]=="calibration"] != planned["genesis_rounds"]:
            raise RuntimeError(f"Missing genesis records in {node} ledger")


# Only explicit runtime variables enter inference and coordinator processes.
_CHILD_KEYS = frozenset({
    "PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONUTF8", "PYTHONDONTWRITEBYTECODE",
    "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "TEMP", "TMP", "TMPDIR",
    "APPDATA", "LOCALAPPDATA", "LD_LIBRARY_PATH", "CUDA_HOME", "LANG", "LC_ALL",
    "OMP_NUM_THREADS", "MKL_NUM_THREADS",
})


def child_environment(parent):
    return {key: value for key, value in parent.items() if key.upper() in _CHILD_KEYS}


def execute_scenario(work, entry, configuration, snapshot, devices, check, progress, *, restart_digest=None,
                     resident_pool=None, case_deadline=None):
    specifications, config = scenario_configuration(configuration, entry, work, snapshot)
    config_path = work / "config.yaml"
    env = child_environment(os.environ)
    checkpoints = entry.get("checkpoint_capture")
    if (restart_digest is not None or resident_pool is not None or config.get("noise_policy") == "incremental_upward") and not checkpoints:
        raise ValueError("Restart, resident and incremental execution require a checkpoint-bound scenario")
    if checkpoints:
        from infra.runpod.n20.artifact_store import json_bytes, sha
        from infra.runpod.n20.checkpoint import Identity
        if work.name != checkpoints["run_id"]:
            raise ValueError("Checkpoint path does not match run ID")
        scenario_id=checkpoints.get("scenario_id", "pilot")
        if (scenario_id == "pilot") != (entry["run_kind"] == "pilot"):
            raise ValueError("Checkpoint phase and scenario do not match")
        identity = Identity(
            run_id=checkpoints["run_id"], experiment_id=entry["id"], scenario_id=scenario_id,
            seed=entry["semente"], rounds=entry["rounds"], git_sha=checkpoints["git_sha"],
            model_revision=configuration["model_revision"], config_sha256=sha(json_bytes(config)),
            tasks_sha256=checkpoints["tasks_sha256"], audit_sha256=sha(json_bytes(entry["audit_plan"])),
            **{k: checkpoints[k] for k in ("campaign_id", "profile_sha256") if k in checkpoints},
        )
        config["checkpoint_identity"]=identity.serialized()
        env.update(N20_CHECKPOINT_TOKEN=secrets.token_hex(32),N20_CHECKPOINT_RUN_ID=identity.run_id,
                   MODEL_RUN_ID=identity.run_id)
    if resident_pool is not None:
        resident_pool.precheck(identity,resume=restart_digest is not None)
    if restart_digest is None:
        if config_path.exists():
            raise ValueError("Cannot overwrite an existing scenario without a validated restart")
        config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    else:
        from infra.runpod.n20 import local_recovery
        from sistema.orchestrator.run import load_tasks
        if config_path.is_symlink() or yaml.safe_load(config_path.read_text("utf-8")) != config:
            raise ValueError("Sealed configuration differs from current worker")
        if (work/"verified-generations.csv").exists():
            raise ValueError("Scenario already contains finalized generation evidence")
        scope={"model":str(snapshot),"revision":configuration["model_revision"],"quantization":configuration["quantization"],
               "device":"cuda","dtype":configuration["dtype"],"max_new_tokens":configuration["max_new_tokens"],
               "temperature":configuration["temperature"],"top_p":configuration["top_p"]}
        frontier,marker=local_recovery.prepare(work,identity,load_tasks(config),scope,accepted_digest=restart_digest)
        local_recovery.quarantine(work,marker,restart_digest)
        env["N20_RESTORE_FRONTIER"]=json.dumps(frontier)
    lease=nullcontext({})
    if resident_pool is not None:
        from sistema.orchestrator.run import load_tasks
        lease=resident_pool.scenario(work,identity,load_tasks(config),configuration,snapshot,
            specifications,devices,ROOT,env,check,resume=restart_digest is not None,case_deadline=case_deadline)
        outer_check=check
        check=lambda:resident_pool._healthy(outer_check)
    with lease as resident_env:
        children = []
        ready = {}
        with ExitStack() as stack:
            try:
                ordered = list(specifications)
                for start in range(0, len(ordered), len(devices)):
                    batch = ordered[start:start + len(devices)]
                    for node_id in batch:
                        gpu, node_env = specifications[node_id]
                        log = stack.enter_context((work / f"{node_id}.log").open("wb"))
                        process = subprocess.Popen(
                            [sys.executable, "-m", "uvicorn", "sistema.node.app:app",
                             "--host", "127.0.0.1", "--port", URLS[node_id].rsplit(":", 1)[1],
                             "--workers", "1", "--no-access-log"],
                            cwd=ROOT, env={**env, **node_env, **resident_env.get(node_id,{}),
                                 "CUDA_VISIBLE_DEVICES":devices[gpu] if resident_pool is None else "",
                                 "MODEL_RUN_ID":identity.run_id if checkpoints else node_env["MODEL_RUN_ID"]},
                            stdout=log, stderr=subprocess.STDOUT)
                        children.append(process)
                        ready[node_id] = process
                    for node_id in batch:
                        until = time.monotonic() + 300
                        while time.monotonic() < until:
                            check()
                            if any(process.poll() is not None for process in children):
                                raise RuntimeError("Um nó encerrou durante a carga; consulte os logs do cenário.")
                            try:
                                with urlopen(URLS[node_id] + "/health", timeout=2) as response:
                                    health = json.load(response)
                                if (health.get("node_id"), health.get("model_loaded"), health.get("model_instances"),
                                        health.get("quantization"), health.get("dtype")) == (
                                            node_id, True, 1, configuration["quantization"], configuration["dtype"]
                                        ):
                                    if resident_pool is None or (health.get("resident_pid"),health.get("model_run_id"))==(
                                        int(resident_env[node_id]["N20_RESIDENT_PID"]),identity.run_id):
                                        break
                            except (OSError, ValueError):
                                pass
                            time.sleep(0.5)
                        else:
                            raise TimeoutError(f"{node_id} não carregou o modelo na precisão exigida em cinco minutos.")
                    progress("loading", nodes_ready=len(ready))
                log = stack.enter_context((work / "orchestrator.log").open("wb"))
                coordinator = subprocess.Popen(
                    [sys.executable, "-m", "sistema.orchestrator.run", "--config", str(config_path)],
                    cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
                children.append(coordinator)
                round_started = time.monotonic()
                start_count=frontier["index"]+1 if restart_digest is not None else 0
                while coordinator.poll() is None:
                    check()
                    if any(process.poll() is not None for process in ready.values()):
                        raise RuntimeError("Um nó encerrou antes da conclusão do cenário.")
                    rounds = work / "rounds.csv"
                    count = 0
                    if checkpoints:
                        count = len(list(work.glob("checkpoint-[0-9][0-9].json")))
                    elif "audit_plan" in entry:
                        count = len(_completed_campaign_rounds(work))
                    elif rounds.exists():
                        with rounds.open(encoding="utf-8", newline="") as stream:
                            count = sum(row.get("round_index", "").isdigit() for row in csv.DictReader(stream))
                    fields = {"rounds_completed": count}
                    if count>start_count:
                        fields["seconds_per_round_observed"] = round((time.monotonic() - round_started) / (count-start_count), 2)
                    progress("running", **fields)
                    time.sleep(2)
                if coordinator.returncode:
                    raise RuntimeError("O orquestrador encerrou com erro; consulte orchestrator.log.")
            finally:
                stop_processes(children)
        _verify_per_node(work, work / "node-models", configuration["nodes"], entry["rounds"], identity.run_id if checkpoints else entry["id"],
                         configuration["model_revision"], model_path=str(snapshot),
                         quantization=configuration["quantization"], dtype=configuration["dtype"])
        if "audit_plan" in entry:
            _verify_campaign(work, config, entry)
        if checkpoints:
            from infra.runpod.n20.checkpoint import CheckpointStore, verify_log_prefixes
            frontier,_ = CheckpointStore(work,identity).recover()
            if frontier is None or frontier["round_index"] != entry["rounds"]-1:
                raise RuntimeError("Scenario completed without a verified final checkpoint")
            verify_log_prefixes(work,frontier)
