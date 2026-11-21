"""Descriptive fair comparisons for the N20 incremental protocol.

Use the output of artifact integrity checks as the input here. Do not call
unsigned local logs official results; this module does not establish provenance.
"""
from collections.abc import Iterable, Mapping


def _flag(row, key):
    value = row[key]
    if type(value) not in (str, int) or value not in ("0", "1", 0, 1):
        raise ValueError(f"{key} must be a bit")
    return int(value)


def _rounds(rows, expected_tasks):
    rows = tuple(rows)
    tasks = tuple(expected_tasks)
    if not tasks or len(set(tasks)) != len(tasks) or len(rows) != len(tasks):
        raise ValueError("Round count and ordered unique dataset questions must match")
    if [int(r["round_index"]) for r in rows] != list(range(len(tasks))):
        raise ValueError("Rounds must appear once in their original zero-based order")
    if tuple(r["task_id"] for r in rows) != tasks:
        raise ValueError("Round question IDs/order differ from the shared sequence")
    for row in rows:
        for key in ("audited", "calibration", "consensus_correct", "majority_correct"):
            _flag(row, key)
    return rows


def _score(rows):
    n = len(rows)
    weighted = sum(_flag(row, "consensus_correct") for row in rows)
    unweighted = sum(_flag(row, "majority_correct") for row in rows)
    return {"n": n, "weighted_correct": weighted, "unweighted_correct": unweighted,
            "weighted_accuracy": weighted / n if n else None,
            "unweighted_accuracy": unweighted / n if n else None}


def summarize(rows: Iterable[Mapping], expected_tasks):
    rows = _rounds(rows, expected_tasks)
    return {"all": _score(rows),
            "non_audited": _score([r for r in rows if not _flag(r, "audited") and not _flag(r, "calibration")]),
            "audited": _score([r for r in rows if _flag(r, "audited")]),
            "variance_between_seeds": None}


def compare_paired(left, right, expected_tasks):
    """Report all-round comparisons and a matched un-audited sensitivity check."""
    tasks = tuple(expected_tasks)
    left, right = _rounds(left, tasks), _rounds(right, tasks)
    common = [(l, r) for l, r in zip(left, right, strict=True)
              if all(not _flag(row, k) for row in (l, r) for k in ("audited", "calibration"))]
    matched_left = [l for l, _ in common]
    matched_right = [r for _, r in common]
    return {"all": {"left": _score(left), "right": _score(right)},
            "common_non_audited": {"left": _score(matched_left), "right": _score(matched_right),
                                   "task_ids": [l["task_id"] for l in matched_left]},
            "unweighted_is_readout_not_independent": True,
            "variance_between_seeds": None}
