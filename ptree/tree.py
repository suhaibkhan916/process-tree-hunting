"""Build process trees from ProcessCreate events.

Nodes are keyed by ProcessGuid, not PID. PIDs are reused, and on Linux the same PID
can belong to a shell and then to the program it execs. The GUID is unique per process.

A parent the capture never saw (it started before Sysmon, or its event was filtered)
becomes a placeholder node built from the child's Parent* fields. When the parent GUID
is all zeros, as Sysmon for Linux reports for processes started before it, the
placeholder is keyed by host, parent PID and parent image instead.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field

from ptree.parser import ZERO_GUID, Proc


@dataclass
class Node:
    key: str
    proc: Proc
    placeholder: bool = False
    parent: str | None = None
    children: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.proc.name


class Forest:
    def __init__(self, procs: list[Proc]) -> None:
        self.nodes: dict[str, Node] = {}
        for p in procs:
            self.nodes[p.guid] = Node(p.guid, p)
        for p in procs:
            parent_key = self._parent_key(p)
            self.nodes[p.guid].parent = parent_key
            self.nodes[parent_key].children.append(p.guid)
        for node in self.nodes.values():
            node.children.sort(key=lambda k: self.nodes[k].proc.time)

    def _parent_key(self, p: Proc) -> str:
        if p.parent_guid != ZERO_GUID and p.parent_guid in self.nodes:
            return p.parent_guid
        key = (p.parent_guid if p.parent_guid != ZERO_GUID
               else f"orphan:{p.host}:{p.parent_pid}:{p.parent_image}")
        if key not in self.nodes:
            ghost = Proc(key, p.parent_pid, p.parent_image, p.parent_cmd, ZERO_GUID, -1, "-", "",
                         "", "", p.host)
            self.nodes[key] = Node(key, ghost, placeholder=True)
        return key

    @property
    def roots(self) -> list[Node]:
        return sorted((n for n in self.nodes.values() if n.parent is None), key=lambda n: n.proc.time)

    def real(self) -> Iterator[Node]:
        """Nodes that came from an event (not placeholders), in time order."""
        yield from sorted((n for n in self.nodes.values() if not n.placeholder), key=lambda n: n.proc.time)

    def ancestors(self, key: str) -> list[Node]:
        """Parent first, then grandparent, up to the root."""
        out = []
        cur = self.nodes[key].parent
        while cur is not None:
            out.append(self.nodes[cur])
            cur = self.nodes[cur].parent
        return out

    def descendants(self, key: str) -> list[Node]:
        out, stack = [], list(reversed(self.nodes[key].children))
        while stack:
            node = self.nodes[stack.pop()]
            out.append(node)
            stack.extend(reversed(node.children))
        return out

    def chain(self, key: str, depth: int = 3) -> str:
        """'grandparent > parent > self' by image name: the key used for stacking."""
        names = [self.nodes[key].name] + [a.name for a in self.ancestors(key)]
        return " > ".join(reversed(names[:depth]))

    def by_pid(self, pid: int) -> list[Node]:
        return [n for n in self.real() if n.proc.pid == pid]

    def render(self, key: str, mark: set[str] | None = None, width: int = 90) -> str:
        """ASCII tree under key. Nodes in `mark` get a '<<' marker."""
        mark = mark or set()
        lines: list[str] = []

        def walk(k: str, prefix: str, last: bool, top: bool) -> None:
            n = self.nodes[k]
            cmd = n.proc.cmd if not n.placeholder else f"(not in capture) {n.proc.image}"
            label = f"{n.name} [{n.proc.pid}] {cmd}"
            if len(label) > width:
                label = label[: width - 3] + "..."
            flag = "  <<" if k in mark else ""
            lines.append(label + flag if top else f"{prefix}{'`-- ' if last else '|-- '}{label}{flag}")
            child_prefix = "" if top else prefix + ("    " if last else "|   ")
            for i, c in enumerate(n.children):
                walk(c, child_prefix, i == len(n.children) - 1, False)

        walk(key, "", True, True)
        return "\n".join(lines)


def children_by_parent(forest: Forest) -> dict[str, list[Node]]:
    out: dict[str, list[Node]] = defaultdict(list)
    for n in forest.real():
        if n.parent:
            out[n.parent].append(n)
    return out
