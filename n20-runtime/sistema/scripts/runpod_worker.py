"""Runs the actual N20 distributed protocol with one resident model per node."""
from __future__ import annotations

import csv
from contextlib import ExitStack
import json
import os
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
    values = {
        "nodes": c["nodes"], "rounds": entry["rounds"], "num-tasks": entry["rounds"],
        "seed": entry["semente"], "malicious": entry["fracao_maliciosos"], "degree": c["degree"],
        "dataset": "task_bank", "task-bank": ROOT / c["task_bank"], "mode": "real",
        "inference-mode": "model", "model": c["model"], "model-run-id": entry["id"],
        "model-snapshot": snapshot, "model-revision": c["model_revision"],
        "gpu-count": c["gpu_count"], "models-per-gpu": c["models_per_gpu"],
        "topology": c["topology"], "signal": c["signal"], "consensus-mode": c["consensus_mode"],
        "consensus-center": c["consensus_center"], "mechanism": c["mechanism"], "defense": c["defense"],
        "validation-score": entry["nota"], "malicious-strategy": c["malicious_strategy"],
        "honest-rounds": entry["honest_rounds"], "audit-mode": c["audit_mode"],
        "audit-p": entry["audit_p"], "collusion-value": c["collusion_value"],
        "noise-mode": c["noise_mode"], "noise-distance": c["noise_distance"],
        "timeout-s": 600, "output-dir": work, "experiment-id": entry["id"],
    }
    services, config = build_configuration(parse_args([
        part for key, value in values.items() for part in (f"--{key}", str(value))
    ]))
    processes = {}
    for node in config["nodes"]:
        node_id = node["id"]
        node["url"] = URLS[node_id]
        service = services[node_id]
        env = dict(service["environment"], NODE_URLS=json.dumps(URLS),
                   MODEL_NAME=str(snapshot), MODEL_CACHE_DIR=str(work / "node-models" / node_id),
                   MODEL_MAX_NEW_TOKENS=str(c["max_new_tokens"]),
                   MODEL_TEMPERATURE=str(c["temperature"]), MODEL_TOP_P=str(c["top_p"]))
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


def execute_scenario(work, entry, configuration, snapshot, devices, check, progress):
    specifications, config = scenario_configuration(configuration, entry, work, snapshot)
    config_path = work / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    # The bucket credential is only for the supervisor.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("TCC_S3_") and key != "RUNPOD_API_KEY"}
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
                        cwd=ROOT, env=dict(env, **node_env, CUDA_VISIBLE_DEVICES=devices[gpu]),
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
                            if (health.get("node_id"), health.get("model_instances"),
                                    health.get("quantization")) == (node_id, 1, "nf4"):
                                break
                        except (OSError, ValueError):
                            pass
                        time.sleep(0.5)
                    else:
                        raise TimeoutError(f"{node_id} não carregou o modelo NF4 em cinco minutos.")
                progress("loading", nodes_ready=len(ready))
            log = stack.enter_context((work / "orchestrator.log").open("wb"))
            coordinator = subprocess.Popen(
                [sys.executable, "-m", "sistema.orchestrator.run", "--config", str(config_path)],
                cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            children.append(coordinator)
            round_started = time.monotonic()
            while coordinator.poll() is None:
                check()
                if any(process.poll() is not None for process in ready.values()):
                    raise RuntimeError("Um nó encerrou antes da conclusão do cenário.")
                rounds = work / "rounds.csv"
                count = 0
                if rounds.exists():
                    with rounds.open(encoding="utf-8", newline="") as stream:
                        count = sum(row.get("round_index", "").isdigit() for row in csv.DictReader(stream))
                fields = {"rounds_completed": count}
                if count:
                    fields["seconds_per_round_observed"] = round((time.monotonic() - round_started) / count, 2)
                progress("running", **fields)
                time.sleep(2)
            if coordinator.returncode:
                raise RuntimeError("O orquestrador encerrou com erro; consulte orchestrator.log.")
        finally:
            stop_processes(children)
    _verify_per_node(work, work / "node-models", configuration["nodes"], entry["rounds"], entry["id"],
                     configuration["model_revision"], model_path=str(snapshot))
