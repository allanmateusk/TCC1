"""One Docker CPU flow pilot with real simulator genesis, audit and EMA."""
from __future__ import annotations
from dataclasses import replace
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import statistics

from sistema.core import behavior
from sistema.core.metrics import MetricsLogger
from sistema.core.network import SimulatedNetwork
from sistema.core.protocol import ProtocolConfig
from sistema.core.topology import build_graph
from sistema.simulate import _dynamic_round, build_profiles, defense_from_args, parse_args, run_simulation

ROOT = Path(__file__).resolve().parent
OUT = Path("/tmp/tcc-output")
SEED = 0
GENESIS = {1, 2, 3}
TESTS = set(range(10, 51, 10))
AUDIT_P = 0.2
DROPOUT_P = 0.3
MALICIOUS = tuple(f"node-{i}" for i in range(16))
HONEST = tuple(f"node-{i}" for i in range(16, 20))


def read_rows(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_rows(path, rows):
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_json(path, data):
    with path.open("x", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=True, indent=2)
        handle.write("\n")


def cohort(vals, ids):
    return round(statistics.mean(vals[n] for n in ids), 8)


def main():
    tasks_file = ROOT / "pilot-tasks.json"
    tasks = json.loads(tasks_file.read_text(encoding="utf-8"))
    if len(tasks) != 50 or len({t["id"] for t in tasks}) != 50:
        raise RuntimeError("Expected 50 distinct tasks.")
    args = parse_args([
        "--nodes", "20", "--rounds", "50", "--seed", str(SEED), "--malicious", "0.8",
        "--unstable", "0.8", "--unstable-mode", "attribute", "--unstable-p-drop", str(DROPOUT_P),
        "--orchestration", "dynamic", "--topology", "kregular", "--degree", "4",
        "--signal", "hybrid", "--consensus-mode", "distance", "--consensus-center", "medoid",
        "--defense", "all", "--mechanism", "ema_slow_up", "--calibration-rounds", "3", "--leaderless-calibration",
        "--alpha", "0.3", "--alpha-up", "0.1", "--alpha-down", "0.8",
        "--consensus-alpha", "0.05", "--oracle-alpha", "0.8",
        "--audit-mode", "random", "--audit-p", str(AUDIT_P), "--validation-score", "exact",
        "--malicious-answer", "noise", "--noise-mode", "multiplicative", "--collusion-value", "999",
        "--malicious-strategy", "knows_schedule", "--honest-rounds", "5",
        "--output", str(OUT), "--experiment-id", "pilot", "--quiet", "--no-row-sync",
    ])
    rng = random.Random(f"{SEED}:audit")
    draws = {r: rng.random() for r in range(1, 51) if r not in GENESIS | TESTS}
    audit_rounds = {r for r, u in draws.items() if u < AUDIT_P}
    args.audited_rounds_override = {r - 1 for r in audit_rounds}
    args.unstable_node_ids_override = MALICIOUS
    args.tasks = tasks
    events_raw = []
    summary = run_simulation(args, round_observer=lambda **entry: events_raw.append(entry))
    if len(events_raw) != 50:
        raise RuntimeError("Incomplete observed evidence.")
    profiles = build_profiles(20, .8)
    nodes = list(profiles)
    state = SimulatedNetwork(nodes, profiles, build_graph(nodes, "kregular", degree=4, seed=SEED),
        ProtocolConfig(signal="hybrid", alpha=.3, initial=.5, mechanism="ema",
            defense=defense_from_args(args), consensus_mode="distance",
            malicious_strategy="knows_schedule", honest_rounds=5,
            audit_mode="random", audited_rounds=frozenset(args.audited_rounds_override),
            validation_score="exact", consensus_center="medoid"))
    shadow = MetricsLogger(str(OUT / "ema-shadow"), experiment_id="ema-shadow", row_sync=False)
    curves = [dict(round=0, phase="initial", slow_honest=.5, slow_malicious=.5,
                   symmetric_honest=.5, symmetric_malicious=.5)]
    try:
        for evidence in events_raw:
            index = evidence["round_index"]
            _dynamic_round(state, shadow, index, tasks[index]["id"], evidence["expected"],
                           evidence["responses"], profiles, "ema", .5, evidence["is_test"])
            alt = {n: state.group_of(n).state.consensus.get(n) for n in nodes}
            after = evidence["after"]
            r = index + 1
            phase = ("genesis" if r in GENESIS else "audit" if r in audit_rounds
                     else "test" if r in TESTS else "normal")
            curves.append(dict(round=r, phase=phase, slow_honest=cohort(after, HONEST),
                               slow_malicious=cohort(after, MALICIOUS), symmetric_honest=cohort(alt, HONEST),
                               symmetric_malicious=cohort(alt, MALICIOUS)))
    finally:
        shadow.close()

    base = OUT / "pilot"
    rounds = read_rows(base / "rounds.csv")
    per_node = read_rows(base / "per_node.csv")
    leadership = {int(row["round_index"])+1: row for row in read_rows(base / "leadership.csv")
                  if row["is_reference"] == "1"}
    assert len(rounds) == len(leadership) == 50 and len(per_node) == 1000
    assert {(int(row["round_index"]), row["node_id"]) for row in per_node} == {
        (i, n) for i in range(50) for n in nodes}
    assert {int(row["round_index"])+1 for row in rounds if row["calibration"] == "1"} == GENESIS
    assert {int(row["round_index"])+1 for row in rounds if row["audited"] == "1"} == audit_rounds
    assert {int(row["round_index"])+1 for row in rounds if row["is_test"] == "1"} == TESTS
    series = []
    absolute_missing = 0
    collusion_sent = 0
    for r, evidence in enumerate(events_raw, 1):
        l = leadership[r]
        responses = {x.node_id: x.answer for x in evidence["responses"]}
        missing = sum(responses[n] is None for n in MALICIOUS)
        absolute_missing += missing
        assert all(responses[n] is not None for n in HONEST)
        supplied = [responses[n] for n in MALICIOUS if responses[n] is not None]
        if r > 5:
            assert supplied and len(set(supplied)) == 1 and abs(supplied[0]) >= 1_000
            collusion_sent += len(supplied)
        if r in GENESIS:
            assert l["outcome"] == "calibration" and not l["leader"] and not l["auditor"]
            assert float(l["confirmed_mass"] or 0) == float(l["total_mass"] or 0) == 0
        if r in audit_rounds:
            assert l["oracle"] == "applied"
        series.append(dict(round=r, phase=curves[r]["phase"], audit_eligible=int(r in draws),
                           audit_draw=f"{draws[r]:.12f}" if r in draws else "",
                           colluding_response_phase=int(r > 5), absent_malicious=missing, absent_honest=0,
                           leader=l["leader"], auditor=l["auditor"], quorum_outcome=l["outcome"],
                           quorum_confirmed_mass=l["confirmed_mass"], quorum_total_mass=l["total_mass"],
                           oracle=l["oracle"], chain_length=l["chain_length"]))
    assert curves[1]["slow_honest"] != .5 or curves[1]["slow_malicious"] != .5
    assert absolute_missing > 0
    write_rows(OUT / "events.csv", series)
    write_rows(OUT / "ema_by_round.csv", curves)
    config = {"scope": "synthetic CPU simulation", "seed": SEED, "nodes": 20, "rounds": 50,
              "malicious": list(MALICIOUS), "unstable": list(MALICIOUS), "unstable_p_drop": DROPOUT_P,
              "dropout_rng": "Python Random('0:unstable'); native per-answer drop and latency draws",
              "dropout_scope": "answer only; simulated nodes can still cast protocol votes",
              "honest_mock_accuracy": .9, "collusion_from_round": 6,
              "strong_noise_formula": "sign * (abs(base)+1) * 10**Uniform(3,6); base is a synthetic mock draw",
              "audit_p": AUDIT_P, "audit_rng": "Python Random('0:audit'); one draw per eligible round",
              "audit_eligibility": "outside genesis and fixed tests", "audit_rounds": sorted(audit_rounds),
              "genesis_rounds": sorted(GENESIS), "test_rounds": sorted(TESTS),
              "genesis": "native leaderless calibration; ground truth without election/proposal/vote/quorum",
              "ema": {"method": "ema_slow_up", "ordinary": .05, "truth_up": .1, "truth_down": .8,
                      "symmetric_shadow": "identical captured answers and audits; alpha .05 ordinary/.8 on truth"},
              "dataset_sha256": hashlib.sha256(tasks_file.read_bytes()).hexdigest()}
    write_json(OUT / "scenario-config.json", config)
    eligible_accuracy = [i for i in range(50) if i+1 not in GENESIS | audit_rounds]
    slow_correct = sum(int(rounds[i]["consensus_correct"]) for i in eligible_accuracy)
    shadow_correct = sum(int(shadow.round_rows[i]["consensus_correct"]) for i in eligible_accuracy)
    receipt = {"status": "verified", "kind": "local-cpu-simulation-m80-unstable-genesis",
               "nodes": 20, "rounds": 50, "verified_node_rounds": 1000,
               "malicious_unstable": 16, "missing_malicious": absolute_missing,
               "missing_honest": 0, "strong_colluding_responses": collusion_sent,
               "audit_rounds": sorted(audit_rounds), "genesis_rounds": sorted(GENESIS),
               "tested_rounds": sorted(TESTS), "reference_quorum_rounds": 47,
               "reference_quorum_accepted": sum(r["quorum_outcome"] == "accepted" for r in series),
               "accuracy_denominator": len(eligible_accuracy), "ema_slow_up_correct": slow_correct,
               "ema_symmetric_shadow_correct": shadow_correct, "live_llm": False, "gpu": False,
               "verified_at_utc": datetime.now(timezone.utc).isoformat()}
    write_json(OUT / "receipt.json", receipt)
    print(json.dumps(receipt), flush=True)


if __name__ == "__main__":
    main()
