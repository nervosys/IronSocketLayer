"""Export source branch gaps from LLVM JSON, merging repeated locations.

This is branch coverage, not MC/DC. A gap needs source review; it is not
automatically a defect, deactivated code, or justified defensive code.
"""
import argparse
import csv
import json
import re
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("report", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
report = json.loads(args.report.read_text(encoding="utf-8-sig"))
branches = {}
summaries = []
for unit in report["data"]:
    for file in unit["files"]:
        name = file["filename"].replace("\\", "/")
        if "/crates/ironsocketlayer/src/" not in name:
            continue
        short = name.split("/crates/ironsocketlayer/", 1)[1]
        summaries.append((short, file["summary"]))
        # Unit-test modules are appended after production code in these files.
        # Exclude their branches rather than crediting test assertions as
        # covered decisions in the shipped library.
        source = Path(file["filename"]).read_text(encoding="utf-8-sig")
        limits = [i for i, line in enumerate(source.splitlines(), 1)
                  if re.match(r"^#\[cfg\((test|all\(test,)", line)]
        test_start = min(limits, default=2**32)
        for branch in file["branches"]:
            if branch[0] >= test_start:
                continue
            location = (short, *branch[:4])
            counts = branches.setdefault(location, [0, 0])
            counts[0] = max(counts[0], branch[4])
            counts[1] = max(counts[1], branch[5])

args.output.parent.mkdir(parents=True, exist_ok=True)
with args.output.open("w", newline="", encoding="utf-8") as out:
    writer = csv.writer(out)
    writer.writerow(["file", "line", "column", "end_line", "end_column", "true_count", "false_count"])
    for location, counts in sorted(branches.items()):
        if 0 in counts:
            writer.writerow([*location, *counts])

for kind in ("lines", "regions", "branches"):
    total = sum(summary[kind]["count"] for _, summary in summaries)
    covered = sum(summary[kind]["covered"] for _, summary in summaries)
    print(f"LLVM {kind}: {covered}/{total} ({100 * covered / total:.2f}%)")
covered = sum(sum(count > 0 for count in counts) for counts in branches.values())
total = 2 * len(branches)
print(f"Merged production branch outcomes: {covered}/{total} ({100 * covered / total:.2f}%)")
print(f"Uncovered source locations: {sum(0 in counts for counts in branches.values())}")
print(f"Gap inventory: {args.output}")
