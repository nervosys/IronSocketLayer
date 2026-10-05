"""Check a branch-gap inventory against the reviewed dispositions.

Every uncovered branch outcome in a gap inventory (from coverage_gaps.py)
must have a row in the review file, and every review row must still match a
gap. A row is keyed by file, the source line's text (whitespace-trimmed) and
the column, so it survives edits elsewhere in the file. When several gaps
share a key, the key holds for all of them.

Dispositions:
  tested       a requirements-based test now covers it; the row names the test
  defensive    reachable only through a fault the type system or an earlier
               check already prevents; kept to fail closed, not panic
  unreachable  cannot be taken with any input, by construction; explained
  environment  depends on the host (OS entropy, clock, I/O errors) and is
               exercised only by fault injection outside this suite

A disposition is the author's review, not an independent one.

  python scripts/coverage_review.py GAPS.csv docs/evidence/coverage-review.csv
  python scripts/coverage_review.py GAPS.csv REVIEW.csv --template NEW.csv
"""
import argparse
import csv
import sys
from pathlib import Path

DISPOSITIONS = {"tested", "defensive", "unreachable", "environment"}
SRC = Path(__file__).resolve().parent.parent / "crates" / "iron-socket-layer"

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("gaps", type=Path)
parser.add_argument("review", type=Path)
parser.add_argument("--template", type=Path, help="write unreviewed gaps here as review rows to fill in")
args = parser.parse_args()

lines = {}


def text(file, line):
    if file not in lines:
        lines[file] = (SRC / file).read_text(encoding="utf-8").splitlines()
    return lines[file][int(line) - 1].strip()


gaps = {}
with args.gaps.open(encoding="utf-8") as f:
    for row in csv.DictReader(f):
        missed = "true" if row["true_count"] == "0" else "false"
        if row["true_count"] == "0" and row["false_count"] == "0":
            missed = "both"
        key = (row["file"], text(row["file"], row["line"]), row["column"])
        gaps.setdefault(key, []).append((row["line"], missed))

reviewed = {}
problems = []
if args.review.exists():
    with args.review.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["file"], row["source"], row["column"])
            if row["disposition"] not in DISPOSITIONS:
                problems.append(f"{key}: unknown disposition {row['disposition']!r}")
            if not row["rationale"].strip():
                problems.append(f"{key}: no rationale")
            reviewed[key] = row

missing = [k for k in gaps if k not in reviewed]
for key in gaps:
    if key in reviewed and reviewed[key]["disposition"] == "tested":
        problems.append(f"marked tested but still uncovered: {key[0]}: {key[1]}")
stale = [k for k, row in reviewed.items() if k not in gaps and row["disposition"] != "tested"]
for key in missing:
    lines_missed = ", ".join(f"line {l} ({m})" for l, m in gaps[key])
    problems.append(f"unreviewed: {key[0]} {lines_missed}: {key[1]}")
for key in stale:
    problems.append(f"stale (no longer a gap; mark tested or remove): {key[0]}: {key[1]}")

if args.template:
    with args.template.open("w", newline="", encoding="utf-8") as out:
        w = csv.writer(out)
        w.writerow(["file", "source", "column", "missed", "disposition", "rationale"])
        for key in missing:
            w.writerow([key[0], key[1], key[2], gaps[key][0][1], "", ""])

counts = {}
for key in gaps:
    if key in reviewed:
        d = reviewed[key]["disposition"]
        counts[d] = counts.get(d, 0) + 1
print(f"gap keys: {len(gaps)}; reviewed: {len(gaps) - len(missing)}; unreviewed: {len(missing)}; stale: {len(stale)}")
for d, n in sorted(counts.items()):
    print(f"  {d}: {n}")
for p in problems:
    print(p)
sys.exit(1 if problems else 0)
