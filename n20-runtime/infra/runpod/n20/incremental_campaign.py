"""Versioned, sealed experimental plan for the incremental live BF16 suite.

No command here starts a Pod or publishes an object. All round IDs are 1-based.
"""
from copy import deepcopy
from random import Random

SCHEMA = "tcc-live-n20/incremental-v1"
PAIRS = ((0, False), (4, False), (4, True), (8, False), (8, True),
         (16, False), (16, True))
FIXED = (10, 20, 30, 40, 50)
DROPOUT_PROBABILITY = .30


def _row(stage, n, collusion, score="exact", unstable_nodes=0):
    prob = .1 if stage == 4 else .2
    key = (f"e{stage}-c{int(collusion)}-m{n * 5:02}-p{round(prob * 100):02}"
           f"-{score}-u{unstable_nodes * 5:02}-s0")
    return dict(id=key, malicious_nodes=n, collusion=collusion, audit="fixed" if stage == 4 else "random",
                audit_p=prob, score=score, unstable_nodes=unstable_nodes)


def scenarios():
    return ([_row(stage, n, c) for stage in (4, 5) for n, c in PAIRS] +
            [_row(6, n, True, "graded") for n in (4, 8, 16)] +
            [_row(7, n, True, unstable_nodes=4) for n in (4, 8, 16)])


IDS = tuple(row["id"] for row in scenarios())

PROTOCOL = {
    "degree": 4, "topology": "kregular", "signal": "consensus",
    "consensus_mode": "distance", "consensus_center": "medoid",
    "mechanism": "ema", "consensus_alpha": .05, "oracle_alpha": .95,
    "defense": "all", "audit_mode": "random", "score": "exact",
    "honest_rounds": 5, "malicious_strategy": "knows_schedule",
    "noise_policy": "incremental_upward", "relative_noise_distance": .2,
    "test_every": 10,
}


def configure(base_profile):
    profile = deepcopy(base_profile)
    profile.update(schema=SCHEMA, seeds=[0], scenarios=scenarios(),
                   protocol=deepcopy(PROTOCOL))
    # The recorded 20x5 pilot belongs solely to the original campaign.
    profile.pop("pilot", None)
    profile.pop("pilot_rounds", None)
    validate(profile)
    return profile


def validate(profile):
    if (profile.get("schema"), profile.get("nodes"), profile.get("rounds"),
        profile.get("gpu_count"), profile.get("models_per_gpu"), profile.get("model"),
        profile.get("dtype"), profile.get("quantization"),
        profile.get("inference_layout"), profile.get("seeds")) != (
        SCHEMA, 20, 50, 2, 10, "HuggingFaceTB/SmolLM3-3B", "bfloat16", "none", "per_node", [0]
    ):
        raise ValueError("Expected the sealed 20-case Smol BF16 incremental profile")
    if (profile.get("scenarios") != scenarios() or profile.get("protocol") != PROTOCOL or
            "pilot" in profile or "pilot_rounds" in profile):
        raise ValueError("Incremental protocol or scenario list differs from its specification")


def plan(profile, row, seed, rounds):
    validate(profile)
    if row not in profile["scenarios"] or type(seed) is not int or seed != 0 or rounds != 50:
        raise ValueError("The incremental sweep requires a declared scenario, seed 0 and 50 rounds")
    rng = Random(f"n20-incremental-v1:{seed}:audit")
    draws = {r: rng.random() for r in range(1, rounds + 1)}
    is_fixed = row["audit"] == "fixed"
    planned = list(FIXED) if is_fixed else [r for r, p in draws.items() if p < row["audit_p"]]
    # For fair comparisons, the same 4 node IDs can be marked across scenarios.
    # Instability is orthogonal to profile and never suppresses generation.
    unstable = sorted(Random(f"n20-incremental-v1:{seed}:unstable").sample(range(20), row["unstable_nodes"]))
    mask = {}
    for r in draws:
        absent = [f"node-{i}" for i in unstable
                  if Random(f"n20-incremental-v1:{seed}:drop:{r}:{i}").random() < DROPOUT_PROBABILITY]
        if absent:
            mask[r] = absent
    return {"mode": row["audit"], "probability": row["audit_p"],
            "fixed_test_rounds": list(FIXED), "genesis_rounds": [],
            "planned_rounds": planned, "preempted_rounds": [],
            "uniform_by_round": draws, "simulated_absences": mask}
