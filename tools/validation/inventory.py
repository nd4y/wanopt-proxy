#!/usr/bin/env python3
"""Keep the complete named Go test inventory and CI mapping in version control."""
import argparse
import ast
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
NAME = re.compile(r"^func ((?:Test|Fuzz)[A-Z0-9_]\w*)\(", re.MULTILINE)


def inventory():
    rows = []
    for path in sorted(ROOT.rglob("*_test.go")):
        for name in NAME.findall(path.read_text()):
            rows.append({"file": path.relative_to(ROOT).as_posix(), "name": name,
                         "workflow": "CI/test (Linux and Windows); Linux race",
                         "additional_gate": "CI/build Docker runtime" if name.startswith("TestDockerImage") else None})
    for filename in ["wanopt.patch", "quic-go.patch"]:
        current = ""
        for line in (ROOT / "experiments/bbr" / filename).read_text().splitlines():
            if line.startswith("+++ b/"):
                current = line[6:]
            if line.startswith("+func "):
                for name in NAME.findall(line[1:]):
                    rows.append({"file": f"experiments/bbr/{filename}:{current}", "name": name,
                                 "workflow": "CI/experimental-bbr pinned recipe"})
    for path in sorted((ROOT / "tools/validation").glob("test_*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                rows.append({"file": path.relative_to(ROOT).as_posix(), "name": node.name,
                             "workflow": "CI/test Python observation/asset checks (Linux and Windows)"})
    path = ROOT / "experiments/bbr/coherence_test.go.txt"
    for name in NAME.findall(path.read_text()):
        rows.append({"file": path.relative_to(ROOT).as_posix(), "name": name,
                     "workflow": "CI/experimental-bbr pinned recipe"})
    return {"schema": 1, "note": "Includes named root tests; complete executed subtest paths are retained in Actions JSON event artifacts.",
            "cases": sorted(rows, key=lambda row: (row["file"], row["name"]))}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    target = ROOT / "docs/test-cases.json"
    data = json.dumps(inventory(), indent=2) + "\n"
    if args.check:
        if not target.is_file() or target.read_text() != data:
            raise SystemExit("Test inventory changed: run python3 tools/validation/inventory.py")
    else:
        target.write_text(data)
    print(f"{len(inventory()['cases'])} named root tests mapped to Actions")


if __name__ == "__main__":
    main()
