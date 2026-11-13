"""Two ways to hunt in process trees.

1. Lineage rules: written by hand from what attackers do (web server -> shell,
   Office -> shell). They need no baseline but only find what someone thought of.
2. Stacking: count every 'grandparent > parent > child' chain in a baseline and list
   the chains in the incident data that the baseline never had. It needs no idea of
   the attack, but it flags anything new, attack or not.
"""

from __future__ import annotations

import base64
import binascii
import re
import shlex
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from ptree.parser import Net, basename
from ptree.tree import Forest, Node

WEB_SERVERS = {
    "w3wp.exe",
    "httpd",
    "apache2",
    "nginx",
    "php-fpm",
    "java",
    "node",
    "gunicorn",
    "uwsgi",
    "python3",
    "python3.10",
    "python3.11",
    "python3.12",
}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
SHELLS = {"sh", "dash", "bash", "zsh", "cmd.exe", "powershell.exe", "pwsh.exe"}
LOLBINS = {"mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "certutil.exe"}
DISCOVERY = {
    "id",
    "whoami",
    "uname",
    "hostname",
    "ifconfig",
    "ip",
    "whoami.exe",
    "hostname.exe",
    "systeminfo.exe",
    "ipconfig.exe",
    "nltest.exe",
    "net.exe",
    "net1.exe",
    "quser.exe",
}
SENSITIVE_FILES = ("/etc/passwd", "/etc/shadow")
DOWNLOADERS = {"curl", "wget", "certutil.exe", "bitsadmin.exe"}
# Shell syntax that chains a second command. In a web server's shell this is the
# fingerprint of command injection: the app meant to run one program.
CHAINING = re.compile(r";|&&|\|\||\||`|\$\(")
ENCODED = re.compile(r"\s-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{8,})", re.I)

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Alert:
    rule: str
    attack: str
    severity: str
    anchor: str  # node key the analyst should start from
    summary: str
    evidence: list[str] = field(default_factory=list)  # node keys


def _has_ancestor(forest: Forest, key: str, names: set[str]) -> Node | None:
    for a in forest.ancestors(key):
        if a.name in names:
            return a
    return None


def _is_discovery(n: Node) -> bool:
    if n.name in DISCOVERY:
        return True
    return n.name == "cat" and any(f in n.proc.cmd for f in SENSITIVE_FILES)


def web_shell_injection(forest: Forest) -> list[Alert]:
    out = []
    for n in forest.real():
        if n.name in SHELLS and forest.nodes[n.parent].name in WEB_SERVERS and CHAINING.search(n.proc.cmd):
            out.append(
                Alert(
                    "web_shell_injection",
                    "T1190",
                    "high",
                    n.key,
                    f"{forest.nodes[n.parent].name} ran a shell with chained commands: {n.proc.cmd[:120]}",
                    [n.key],
                )
            )
    return out


def discovery_from_unusual_parent(forest: Forest) -> list[Alert]:
    """Discovery commands run by a shell that sits under a web server or an Office
    program. Grouped by that web server or Office process, so a web shell that runs
    one command per request still gives one alert, not one per request."""
    groups: dict[str, list[Node]] = defaultdict(list)
    for n in forest.real():
        if not _is_discovery(n) or forest.nodes[n.parent].name not in SHELLS:
            continue
        root = _has_ancestor(forest, n.key, WEB_SERVERS | OFFICE)
        if root is not None:
            groups[root.key].append(n)
    out = []
    for root_key, found in groups.items():
        root = forest.nodes[root_key]
        names = ", ".join(n.proc.cmd for n in found)
        sev = "high" if len(found) >= 3 else "medium"
        shells = list(dict.fromkeys(n.parent for n in found))
        out.append(
            Alert(
                "discovery_from_unusual_parent",
                "T1033,T1082,T1087",
                sev,
                found[0].parent,
                f"{len(found)} discovery command(s) under {root.name}: {names[:140]}",
                [*shells, *(n.key for n in found)],
            )
        )
    return out


def office_spawns_shell(forest: Forest) -> list[Alert]:
    out = []
    for n in forest.real():
        parent = forest.nodes[n.parent]
        if parent.name in OFFICE and (n.name in SHELLS or n.name in LOLBINS):
            out.append(
                Alert(
                    "office_spawns_shell",
                    "T1204.002,T1059",
                    "critical",
                    n.key,
                    f"{parent.name} started {n.name}: {n.proc.cmd[:120]}",
                    [parent.key, n.key],
                )
            )
    return out


def decode_powershell(cmd: str) -> str | None:
    m = ENCODED.search(cmd)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError):
        return None


def encoded_powershell(forest: Forest) -> list[Alert]:
    out = []
    for n in forest.real():
        if n.name in ("powershell.exe", "pwsh.exe") and ENCODED.search(n.proc.cmd):
            decoded = decode_powershell(n.proc.cmd)
            shown = f"decodes to: {decoded}" if decoded is not None else "could not decode"
            out.append(
                Alert(
                    "encoded_powershell",
                    "T1059.001,T1027",
                    "high",
                    n.key,
                    f"PowerShell with an encoded command, {shown}",
                    [n.key],
                )
            )
    return out


def _download_targets(cmd: str) -> list[str]:
    try:
        args = shlex.split(cmd, posix=True)
    except ValueError:
        return []
    targets = []
    for i, a in enumerate(args[:-1]):
        if a in ("-o", "-O", "--output"):
            targets.append(args[i + 1])
    return targets


def download_then_execute(forest: Forest) -> list[Alert]:
    """A downloader writes a file and a later process in the same tree runs it."""
    out = []
    for n in forest.real():
        if n.name not in DOWNLOADERS:
            continue
        parent = forest.nodes[n.parent]
        for target in _download_targets(n.proc.cmd):
            if target in ("/dev/null", "-"):
                continue
            later = [
                d
                for d in forest.descendants(parent.key)
                if d.key != n.key and d.proc.time >= n.proc.time and target in d.proc.cmd
            ]
            if later:
                out.append(
                    Alert(
                        "download_then_execute",
                        "T1105,T1059.004",
                        "high",
                        parent.key,
                        f"{n.name} saved {target}, then {later[0].proc.cmd[:80]!r} ran it",
                        [n.key, *(d.key for d in later)],
                    )
                )
    return out


def shell_network(forest: Forest, nets: list[Net]) -> list[Alert]:
    out = []
    by_guid = set(forest.nodes)
    for n in forest.real():
        # Skip a shell whose child shell carries the same /dev/tcp text: the injected
        # `sh -c "...; bash -c '...dev/tcp...'"` and the bash it starts are one event.
        if any(d.name in SHELLS and "/dev/tcp/" in d.proc.cmd for d in forest.descendants(n.key)):
            continue
        if n.name in SHELLS and "/dev/tcp/" in n.proc.cmd:
            out.append(
                Alert(
                    "shell_network",
                    "T1059.004",
                    "high",
                    n.key,
                    f"shell opens a TCP socket: {n.proc.cmd[:100]}",
                    [n.key],
                )
            )
    seen = {a.anchor for a in out}
    for c in nets:
        if basename(c.image) in SHELLS and c.guid in by_guid and c.guid not in seen:
            seen.add(c.guid)
            out.append(
                Alert(
                    "shell_network",
                    "T1059.004",
                    "high",
                    c.guid,
                    f"{basename(c.image)} connected to {c.dest_ip}:{c.dest_port}",
                    [c.guid],
                )
            )
    return out


def run_rules(forest: Forest, nets: list[Net] | None = None) -> list[Alert]:
    alerts = (
        web_shell_injection(forest)
        + discovery_from_unusual_parent(forest)
        + office_spawns_shell(forest)
        + encoded_powershell(forest)
        + download_then_execute(forest)
        + shell_network(forest, nets or [])
    )
    return sorted(alerts, key=lambda a: (forest.nodes[a.anchor].proc.time, SEVERITY[a.severity]))


@dataclass
class Rare:
    chain: str
    count: int
    keys: list[str]


def stack(baseline: Forest, incident: Forest, depth: int = 3) -> list[Rare]:
    """Chains in the incident that never occur in the baseline, rarest first."""
    seen = Counter(baseline.chain(n.key, depth) for n in baseline.real())
    found: dict[str, list[str]] = defaultdict(list)
    for n in incident.real():
        c = incident.chain(n.key, depth)
        if seen[c] == 0:
            found[c].append(n.key)
    return sorted((Rare(c, len(k), k) for c, k in found.items()), key=lambda r: (r.count, r.chain))
