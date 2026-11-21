"""Closed local profile registry; never load a path selected by an artifact."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from . import campaign

LEGACY_SCHEMA = "tcc-live-n20/v2"
INCREMENTAL_SCHEMA = "tcc-live-n20/incremental-v1"
SELECTORS = ("legacy", "incremental-v1")
FIELDS = ("campaign_id", "profile_sha256")
PROFILE = Path(__file__).with_name("profile.json")
HEX = re.compile(r"[a-f0-9]{64}\Z")


def canonical_bytes(profile):
    return (json.dumps(profile,indent=2,sort_keys=True,allow_nan=False)+"\n").encode("utf-8")


def digest(profile):
    return hashlib.sha256(canonical_bytes(profile)).hexdigest()


def _incremental():
    from . import incremental_campaign
    if incremental_campaign.SCHEMA!=INCREMENTAL_SCHEMA:
        raise ValueError("Unexpected incremental module identity")
    return incremental_campaign


def resolve(selector="legacy"):
    if selector not in SELECTORS:
        raise ValueError("Unknown campaign selector")
    old = json.loads(PROFILE.read_text(encoding="utf-8"))
    campaign.validate(old)
    if selector=="legacy":
        return old
    module=_incremental()
    new=module.configure(old)
    if new.get("schema")!=INCREMENTAL_SCHEMA:
        raise ValueError("Configured incremental profile lacks exact schema")
    module.validate(new)
    return new


def scope(profile):
    schema=profile.get("schema")
    if schema==LEGACY_SCHEMA:
        return {}
    if schema==INCREMENTAL_SCHEMA:
        return {"campaign_id":schema,"profile_sha256":digest(profile)}
    raise ValueError("Unknown campaign schema")


def select_for_record(record):
    present=set(FIELDS).intersection(record)
    if not present:
        return resolve()
    if present!=set(FIELDS):
        raise ValueError("Incomplete campaign scope")
    profile=resolve("incremental-v1")
    if any(record[k]!=v for k,v in scope(profile).items()):
        raise ValueError("Unknown campaign or profile digest mismatch")
    return profile


def matches_record(record,expected):
    return isinstance(record,dict) and {k:record[k] for k in FIELDS if k in record}==expected


def fields(campaign_id,profile_sha256):
    if campaign_id is None and profile_sha256 is None:
        return {}
    if campaign_id!=INCREMENTAL_SCHEMA or not isinstance(profile_sha256,str) or not HEX.fullmatch(profile_sha256):
        raise ValueError("Incomplete or unknown campaign identity")
    return dict(campaign_id=campaign_id,profile_sha256=profile_sha256)


def verify_identity(scenario,rounds,campaign_id=None,profile_sha256=None):
    metadata=fields(campaign_id,profile_sha256)
    if not metadata:
        return (scenario=="pilot" and rounds==5) or (scenario in campaign.IDS and rounds==50)
    profile=select_for_record(metadata)
    return (scenario in _incremental().IDS and rounds==profile["rounds"])


def plan(profile,row,seed,rounds):
    return (_incremental() if scope(profile) else campaign).plan(profile,row,seed,rounds)


def experiment_id(profile,scenario,seed,rounds):
    prefix="pilot" if scenario=="pilot" else ("incremental-v1" if scope(profile) else "live")
    return f"{prefix}-n20-r{rounds}-{scenario}-s{seed}"


def candidate_key(run_id):
    if not isinstance(run_id,str) or not re.fullmatch(r"[a-f0-9]{32}",run_id):
        raise ValueError("Invalid candidate UUID")
    # Deliberately not a current R2 grant prefix.
    return f"tcc/candidato/incremental-v1/n20-{run_id}.zip"
