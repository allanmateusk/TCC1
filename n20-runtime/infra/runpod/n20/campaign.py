"""Pinned, paired scenario planning (round numbers in the plan are 1-based)."""
from __future__ import annotations

from random import Random

IDS = tuple("C01 C16 C17 C10 C14 C11 C02 C03 C08 C04 C05 C09 C06 C07 C12 C15 C13".split())
EXPECTED = (
    (0,"none",0), (4,"none",0), (8,"none",0), (12,"none",0), (16,"none",0),
    (12,"fixed",.2), (8,"random",.1), (8,"random",.2), (12,"random",.2),
    (16,"random",.1), (16,"random",.2), (12,"random",.2), (16,"random",.2),
    (16,"random",.2), (12,"random",.2), (16,"random",.2), (16,"random",.2),
)


def validate(profile):
    scenarios = profile["scenarios"]
    if tuple(row["id"] for row in scenarios) != IDS or profile["seeds"] != [0]:
        raise ValueError("Expected the pinned order of 17 scenarios with one shared seed")
    for row, (n, mode, prob) in zip(scenarios, EXPECTED, strict=True):
        tag = row["id"]
        exact = {"id": tag, "malicious_nodes": n, "audit": mode, "audit_p": prob}
        if tag == "C11":
            exact["match_audit_count"] = "C08"
        if tag in ("C09", "C06", "C13"):
            exact["genesis_rounds"] = 3
        if tag == "C07":
            exact["score"] = "graded"
        if tag in ("C12", "C15"):
            exact["mechanism"] = "ema"
        if tag == "C13":
            exact["dropout_colluder_p"] = .3
        if row != exact:
            raise ValueError(f"Unexpected scenario specification: {tag}")
    if profile["pilot"] != {"id":"pilot", "malicious_nodes":0, "audit":"random", "audit_p":.2}:
        raise ValueError("Unexpected baseline pilot")
    protocol = profile["protocol"]
    if (protocol["test_every"], protocol["honest_rounds"], protocol["signal"], protocol["mechanism"],
        protocol["score"], protocol["malicious_strategy"], protocol["consensus_center"], protocol["defense"]) != (
        10, 5, "consensus", "ema_slow_up", "exact", "on_off", "medoid", "all"
    ):
        raise ValueError("Unexpected official protocol defaults")


def plan(profile, row, seed, rounds):
    # Draw for every physical round before masking. Genesis therefore cannot
    # shift the common per-round variates; .1 is always a subset of .2.
    rng = Random(f"n20-v2:{seed}:audit")
    draws = {r: rng.random() for r in range(1, rounds+1)}
    period = profile["protocol"]["test_every"]
    tests = set(range(period, rounds+1, period))
    genesis = set(range(1, row.get("genesis_rounds", 0)+1))
    eligible = sorted(set(draws) - tests - genesis)
    mode = row["audit"]
    planned = []
    preempted = []
    if mode == "random":
        planned = [r for r in eligible if draws[r] < row["audit_p"]]
        preempted = sorted(r for r in genesis - tests if draws[r] < row["audit_p"])
    elif mode == "fixed":
        target = next(s for s in profile["scenarios"] if s["id"] == row["match_audit_count"])
        n = sum(draws[r] < target["audit_p"] for r in eligible)
        # Stratified deterministic spacing: match the planned count, not which rounds won.
        planned = [eligible[(2*i+1)*len(eligible)//(2*n)] for i in range(n)]
    masked = {}
    if row.get("dropout_colluder_p"):
        for r in draws:
            absent = [f"node-{i}" for i in range(row["malicious_nodes"])
                      if Random(f"n20-v2:{seed}:dropout:{r}:{i}").random() < row["dropout_colluder_p"]]
            if absent:
                masked[r] = absent
    return {"mode": mode, "probability": row["audit_p"], "fixed_test_rounds": sorted(tests),
            "genesis_rounds": sorted(genesis), "planned_rounds": planned,
            "preempted_rounds": preempted, "uniform_by_round": draws, "simulated_absences": masked}
