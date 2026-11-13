"""Markdown output: alerts with their process trees, the stacking table, the scorecard."""

from __future__ import annotations

from ptree.hunts import SEVERITY, Alert, Rare
from ptree.score import Score
from ptree.tree import Forest


def _start(forest: Forest, alert: Alert) -> str:
    """Draw from the lowest common ancestor of the evidence; a lone leaf is drawn from its parent."""
    start = forest.common_ancestor(alert.evidence)
    if not forest.nodes[start].children and forest.nodes[start].parent:
        start = forest.nodes[start].parent
    return start


def alerts_md(forest: Forest, alerts: list[Alert]) -> list[str]:
    lines = ["## Lineage rule alerts", ""]
    if not alerts:
        return lines + ["No alerts.", ""]
    lines += ["| Time (UTC) | Severity | Rule | ATT&CK | Summary |", "|---|---|---|---|---|"]
    for a in sorted(alerts, key=lambda a: (SEVERITY[a.severity], forest.nodes[a.anchor].proc.time)):
        summary = a.summary.replace("|", "\\|")
        lines.append(
            f"| {forest.nodes[a.anchor].proc.time} | {a.severity} | {a.rule} | {a.attack} | {summary} |"
        )
    lines += ["", "### Trees", "", "Lines marked `<<` are the evidence for the alert.", ""]
    for a in alerts:
        start = _start(forest, a)
        parent = forest.nodes[start].parent
        head = f"under {forest.nodes[parent].name} [{forest.nodes[parent].proc.pid}]" if parent else "root"
        tree = forest.render(start, set(a.evidence), pruned=True)
        lines += [f"**{a.rule}** ({head})", "", "```", tree, "```", ""]
    return lines


def stack_md(rare: list[Rare]) -> list[str]:
    lines = ["## Stacking: chains not seen in the baseline", ""]
    if not rare:
        return lines + ["None.", ""]
    lines += ["| Count | Chain (grandparent > parent > process) |", "|---|---|"]
    lines += [f"| {r.count} | `{r.chain}` |" for r in rare]
    return lines + [""]


def score_md(title: str, scores: list[Score]) -> list[str]:
    lines = [
        f"### {title}",
        "",
        "| Method | Attack steps found | Findings | False findings | Missed |",
        "|---|---|---|---|---|",
    ]
    for s in scores:
        missed = "; ".join(f"`{m}`" for m in s.missed) or "-"
        found = f"{s.steps_found} of {s.steps_total}"
        lines.append(f"| {s.method} | {found} | {s.findings} | {s.false_findings} | {missed} |")
    return lines + [""]
