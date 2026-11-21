"""Pack only verified M80 local simulation outputs and optionally verify an R2 upload."""
from __future__ import annotations
import argparse
import csv
from datetime import datetime, timezone
import getpass
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import sys
import warnings
from xml.etree import ElementTree
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from . import r2_pilot, r2_pilot_prompt
from .r2_docker_pilot import ROOT, RUN_PATTERN, _save_local

KEYS = re.compile(r"tcc/piloto/m80-[0-9a-f]{12}-[0-9a-f]{32}\.zip\Z")
FILES = ("receipt.json", "scenario-config.json", "events.csv", "ema_by_round.csv",
         "pilot/rounds.csv", "pilot/per_node.csv", "pilot/leadership.csv", "ema-eventos-final.svg")
SENSITIVE = re.compile(
    r"-----BEGIN .*PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{24,}|"
    r"\bgithub_pat_[A-Za-z0-9_]{30,}|X-Amz-(?:Credential|Signature)|https://[a-f0-9]{32}\.r2\.cloudflarestorage",
    re.I,
)


def check_svg(raw):
    tree = ElementTree.fromstring(raw)
    if tree.tag.split("}")[-1] != "svg":
        raise ValueError("Expected generated SVG.")
    for elem in tree.iter():
        if elem.tag.split("}")[-1] in {"script", "foreignObject", "iframe", "image"}:
            raise ValueError("Unexpected active or embedded artifact content.")
        for key, value in elem.attrib.items():
            if (key.split("}")[-1].lower().startswith("on")
                    or (key.split("}")[-1] == "href" and not value.startswith("#"))):
                raise ValueError("External SVG content is not allowed.")


def build_archive(root):
    artifacts = {}
    for filename in FILES:
        path = root / filename
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("Expected synthetic pilot artifact not found.")
        if path.stat().st_size > 500 * 1024:
            raise ValueError("Unanticipated file size.")
        raw = path.read_bytes()
        if SENSITIVE.search(raw.decode("utf-8")):
            raise ValueError("Unexpected credential-like content.")
        artifacts[filename] = raw
    receipt = json.loads(artifacts["receipt.json"])
    config = json.loads(artifacts["scenario-config.json"])
    if (receipt.get("status"), receipt.get("kind"), receipt.get("nodes"), receipt.get("rounds"),
        receipt.get("verified_node_rounds"), receipt.get("malicious_unstable"), receipt.get("live_llm"),
        receipt.get("gpu")) != ("verified", "local-cpu-simulation-m80-unstable-genesis", 20, 50, 1000, 16, False, False):
        raise ValueError("Not the authorized 20 x 50 synthetic pilot.")
    if config.get("seed") != 0 or config.get("audit_p") != .2 or config.get("genesis_rounds") != [1, 2, 3]:
        raise ValueError("Scenario metadata does not match.")
    for name,count in (("events.csv",50),("ema_by_round.csv",51),("pilot/rounds.csv",50),("pilot/per_node.csv",1000)):
        if len(list(csv.DictReader(io.StringIO(artifacts[name].decode("utf-8"))))) != count:
            raise ValueError("Incomplete run artifacts.")
    check_svg(artifacts["ema-eventos-final.svg"])
    target = io.BytesIO()
    with ZipFile(target, "w") as z:
        for name, raw in artifacts.items():
            z.writestr(ZipInfo(name), raw, compress_type=ZIP_DEFLATED)
    data = target.getvalue()
    if len(data) > 128 * 1024:
        raise ValueError("Only the small reviewed pilot package is allowed.")
    return data


def consume_download(root, data):
    with ZipFile(io.BytesIO(data)) as z:
        if sorted(z.namelist()) != sorted(FILES) or z.testzip() is not None:
            raise ValueError("Downloaded archive is not the expected ZIP.")
        def rows(name):
            with z.open(name) as member:
                return list(csv.DictReader(io.TextIOWrapper(member, encoding="utf-8", newline="")))
        rounds = rows("pilot/rounds.csv")
        nodes = rows("pilot/per_node.csv")
        ema = rows("ema_by_round.csv")
        if (len(rounds), len(nodes), len(ema)) != (50, 1000, 51):
            raise ValueError("Downloaded rounds/nodes/EMA counts differ.")
        if {int(r["round_index"]) for r in rounds} != set(range(50)):
            raise ValueError("Unexpected downloaded rounds.")
        if {(int(r["round_index"]),r["node_id"]) for r in nodes} != {
                (i,f"node-{j}") for i in range(50) for j in range(20)}:
            raise ValueError("Unexpected downloaded node-round evidence.")
        if [int(r["round"]) for r in ema] != list(range(51)):
            raise ValueError("Unexpected downloaded EMA checkpoints.")
        for row in ema:
            if not all(0 <= float(row[k]) <= 1 for k in
                       ("slow_honest","slow_malicious","symmetric_honest","symmetric_malicious")):
                raise ValueError("Unexpected downloaded EMA value.")
    path = root / "r2-downloaded.zip"
    try:
        with path.open("xb") as f:
            f.write(data)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != data:
            raise ValueError("Refusing to overwrite a different downloaded archive.") from None
    return {
        "downloaded_rounds": len(rounds), "downloaded_node_rounds": len(nodes),
        "downloaded_ema_checkpoints": len(ema), "downloaded_zip": path.name,
        "download_verified_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def upload(config, key, put, get, data, *, output_dir, opener=None, now=None):
    return r2_pilot._send_payload(config, key, put, get, data=data, key_pattern=KEYS,
                                  content_type="application/zip", opener=opener, now=now,
                                  download_consumer=lambda observed: consume_download(output_dir, observed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    if not RUN_PATTERN.fullmatch(args.run_id):
        parser.error("Expected local Docker run ID.")
    if not args.prepare_only and (not sys.stdin.isatty() or not sys.stderr.isatty()):
        print("No upload. Use a normal interactive terminal or --prepare-only.", file=sys.stderr)
        return 2
    try:
        root = ROOT / "resultados" / "docker-local" / args.run_id
        if not root.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError("Unexpected local output location.")
        data = build_archive(root)
        local = _save_local(root, data)
        print(json.dumps(dict(status="prepared_locally", path=str(local), bytes=len(data),
                              sha256=hashlib.sha256(data).hexdigest())))
        if args.prepare_only:
            return 0
        config = r2_pilot.load_config()
        key = f"tcc/piloto/m80-{args.run_id}-{secrets.token_hex(16)}.zip"
        print(f"Scope: 1 synthetic mock-result package to {config['bucket']}/{key}.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            access = getpass.getpass("R2 S3 Access Key ID (hidden): ")
            secret = getpass.getpass("R2 S3 Secret Access Key (hidden): ")
        try:
            put,get = r2_pilot_prompt._create_urls(config,key,access.strip(),secret.strip(),
                                                  datetime.now(timezone.utc),key_pattern=KEYS)
        finally:
            del access,secret
        try:
            result = upload(config,key,put,get,data,output_dir=root)
        finally:
            del put,get
        print(json.dumps(result))
        return 0
    except (KeyboardInterrupt, EOFError):
        print("Stopped; no verified upload reported.", file=sys.stderr)
        return 130
    except Exception:
        print("Not verified; check local artifacts or scoped R2 access. No secrets displayed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
