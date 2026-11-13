"""Score hunts against ground truth. Only this module reads the truth markers.

Linux: every payload sent by scenario/attack.sh ends with the shell comment '#lab-attack',
so the injected shell's command line carries it. That shell and everything under it is
attack activity. Windows: data/windows_truth.txt lists the attack ProcessGuids.

A step is one connected piece of attack activity: a truth node whose parent is not truth,
plus its truth descendants. A method finds a step if any alert or rare chain points at
a node in it. A finding that points at no truth node is a false finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ptree.hunts import Alert, Rare
from ptree.tree import Forest

LINUX_MARKER = "#lab-attack"


def truth_keys(forest: Forest, truth_file: Path | None = None) -> set[str]:
    if truth_file is not None:
        wanted = set(truth_file.read_text(encoding="utf-8").split())
        return {k for k in forest.nodes if k in wanted}
    keys: set[str] = set()
    for n in forest.real():
        if LINUX_MARKER in n.proc.cmd and n.name != "curl":  # curl is the attacker's client side
            keys.add(n.key)
            keys.update(d.key for d in forest.descendants(n.key))
    return keys


def steps(forest: Forest, truth: set[str]) -> list[set[str]]:
    tops = [k for k in truth if forest.nodes[k].parent not in truth]
    tops.sort(key=lambda k: forest.nodes[k].proc.time)
    return [{t, *(d.key for d in forest.descendants(t))} & truth for t in tops]


@dataclass
class Score:
    method: str
    steps_found: int
    steps_total: int
    findings: int
    false_findings: int
    missed: list[str]


def score(forest: Forest, truth: set[str], method: str, groups: list[list[str]]) -> Score:
    all_steps = steps(forest, truth)
    hit = set().union(*groups) if groups else set()
    missed = [forest.nodes[min(s, key=lambda k: forest.nodes[k].proc.time)].proc.cmd[:90]
              for s in all_steps if not s & hit]
    false = sum(1 for g in groups if not set(g) & truth)
    return Score(method, len(all_steps) - len(missed), len(all_steps), len(groups), false, missed)


def score_rules(forest: Forest, truth: set[str], alerts: list[Alert]) -> Score:
    return score(forest, truth, "lineage rules", [a.evidence for a in alerts])


def score_stack(forest: Forest, truth: set[str], rare: list[Rare]) -> Score:
    return score(forest, truth, "stacking", [r.keys for r in rare])
