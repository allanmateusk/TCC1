"""Pack only the simulator and pinned questions for the selected CPU test."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

HERE = Path(__file__).resolve().parent
RUNTIME = HERE.parents[3]


def prepare(output, scenario="base"):
    if scenario not in {'base','m80'}:
        raise ValueError('Unknown synthetic pilot')
    count = 50 if scenario == "m80" else 5
    tasks = json.loads((RUNTIME / "sistema/dados/gsm8k_test_n20.json").read_text(encoding="utf-8"))["tarefas"][:count]
    if len(tasks) != count or any(set(row) != {"id", "question", "answer"} for row in tasks):
        raise ValueError("Expected only the required questions, IDs and answer keys.")
    paths = [RUNTIME / "sistema/__init__.py", RUNTIME / "sistema/simulate.py",
             *sorted((RUNTIME / "sistema/core").glob("*.py"))]
    with ZipFile(output, "x", compression=ZIP_DEFLATED) as z:
        for path in paths:
            z.write(path, path.relative_to(RUNTIME).as_posix())
        z.write(HERE / ("pilot_m80.py" if scenario == "m80" else "pilot.py"), "pilot.py")
        z.writestr("pilot-tasks.json", json.dumps(tasks, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--scenario", choices=("base","m80"), default="base")
    args = parser.parse_args()
    prepare(args.archive, args.scenario)
