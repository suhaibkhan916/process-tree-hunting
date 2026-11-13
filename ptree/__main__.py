"""Command line.

  python -m ptree hunt INCIDENT [--baseline BASELINE] [--out DIR]
  python -m ptree tree FILE (--pid N | --match TEXT)
  python -m ptree score [--out DIR]

hunt exits 1 when a high or critical alert fires, 0 when none does, 2 on bad input.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ptree.hunts import run_rules, stack
from ptree.parser import parse_file
from ptree.report import alerts_md, score_md, stack_md
from ptree.score import score_rules, score_stack, truth_keys
from ptree.tree import Forest

ROOT = Path(__file__).resolve().parent.parent
DATASETS = [
    ("Linux, real Sysmon for Linux capture", "data/baseline.log", "data/incident.log", None),
    (
        "Windows, synthetic Sysmon events",
        "data/windows_baseline.xml",
        "data/windows_incident.xml",
        "data/windows_truth.txt",
    ),
]


def _write(out: Path, name: str, lines: list[str]) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    path = out / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return path


def cmd_hunt(a: argparse.Namespace) -> int:
    cap = parse_file(a.incident)
    forest = Forest(cap.procs)
    alerts = run_rules(forest, cap.nets)
    lines = [
        f"# Process tree hunt: {a.incident.name}",
        "",
        f"{len(cap.procs)} process events, {len(cap.nets)} network events, "
        f"{cap.unreadable} unreadable lines.",
        "",
    ]
    lines += alerts_md(forest, alerts)
    rare = []
    if a.baseline:
        base = Forest(parse_file(a.baseline).procs)
        rare = stack(base, forest)
        lines += stack_md(rare)
    path = _write(a.out, f"hunt_{a.incident.stem}.md", lines)
    print(f"{len(alerts)} alerts, {len(rare)} rare chains -> {path}")
    for al in alerts:
        print(f"  [{al.severity:8}] {al.rule}: {al.summary[:100]}")
    return 1 if any(al.severity in ("high", "critical") for al in alerts) else 0


def cmd_tree(a: argparse.Namespace) -> int:
    forest = Forest(parse_file(a.file).procs)
    hits = forest.by_pid(a.pid) if a.pid is not None else [n for n in forest.real() if a.match in n.proc.cmd]
    if not hits:
        print("no matching process", file=sys.stderr)
        return 2
    for n in hits[: a.limit]:
        chain = " > ".join(x.name for x in reversed([n, *forest.ancestors(n.key)]))
        print(f"# {chain}")
        print(forest.render(n.key))
        print()
    return 0


def cmd_score(a: argparse.Namespace) -> int:
    lines = [
        "# Scorecard: lineage rules against stacking",
        "",
        "Ground truth is read only here, never by a hunt.",
        "",
    ]
    for title, base, inc, truth in DATASETS:
        cb, ci = parse_file(ROOT / base), parse_file(ROOT / inc)
        fb, fi = Forest(cb.procs), Forest(ci.procs)
        t = truth_keys(fi, ROOT / truth if truth else None)
        base_alerts = run_rules(fb, cb.nets)
        lines += score_md(
            title, [score_rules(fi, t, run_rules(fi, ci.nets)), score_stack(fi, t, stack(fb, fi))]
        )
        lines += [f"Lineage rule alerts on the baseline alone: {len(base_alerts)}.", ""]
    path = _write(a.out, "scorecard.md", lines)
    print(path.read_text(encoding="utf-8"))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ptree", description="Hunt in Sysmon process trees.")
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hunt", help="run lineage rules, and stacking if a baseline is given")
    h.add_argument("incident", type=Path)
    h.add_argument("--baseline", type=Path)
    h.add_argument("--out", type=Path, default=Path("reports"))
    t = sub.add_parser("tree", help="print the tree under matching processes")
    t.add_argument("file", type=Path)
    g = t.add_mutually_exclusive_group(required=True)
    g.add_argument("--pid", type=int)
    g.add_argument("--match")
    t.add_argument("--limit", type=int, default=3)
    s = sub.add_parser("score", help="score both methods on the lab data")
    s.add_argument("--out", type=Path, default=Path("reports"))
    a = p.parse_args(argv)
    for f in (getattr(a, "incident", None), getattr(a, "baseline", None), getattr(a, "file", None)):
        if f is not None and not f.exists():
            print(f"error: {f} not found", file=sys.stderr)
            return 2
    return {"hunt": cmd_hunt, "tree": cmd_tree, "score": cmd_score}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
