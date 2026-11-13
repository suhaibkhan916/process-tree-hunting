from pathlib import Path

import pytest

from ptree.parser import ZERO_GUID, Proc, basename, parse_file
from ptree.tree import Forest

DATA = Path(__file__).resolve().parent.parent / "data"


def proc(guid, image, parent_guid=ZERO_GUID, pid=1, parent_pid=0, parent_image="-", t="2026-01-01 00:00:00.000"):
    return Proc(guid, pid, image, image, parent_guid, parent_pid, parent_image, "", "", t, "h")


@pytest.mark.parametrize("path, name", [
    ("/usr/bin/dash", "dash"),
    (r"C:\Windows\System32\cmd.exe", "cmd.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "winword.exe"),
    ("", "-"),
])
def test_basename(path, name):
    assert basename(path) == name


def test_linux_capture_parses():
    cap = parse_file(DATA / "incident.log")
    assert len(cap.procs) == 95 and len(cap.nets) == 33 and cap.unreadable == 0


def test_windows_capture_parses_namespaced_xml():
    cap = parse_file(DATA / "windows_incident.xml")
    assert len(cap.procs) == 42
    assert {p.host for p in cap.procs} == {"WKS-021.labcorp.local", "WEB-01.labcorp.local"}


def test_truncated_syslog_line_is_counted(tmp_path):
    good = (DATA / "baseline.log").read_text(encoding="utf-8").splitlines()[5]
    f = tmp_path / "cut.log"
    f.write_text(good + "\n" + good[:200] + "\n", encoding="utf-8")
    cap = parse_file(f)
    assert cap.unreadable == 1


def test_guid_beats_reused_pid():
    # Same PID twice: the tree must still link each child to the right parent.
    procs = [proc("{a}", "/bin/bash", pid=10, t="1"), proc("{b}", "/bin/ls", "{a}", pid=11, parent_pid=10, t="2"),
             proc("{c}", "/bin/sh", pid=10, t="3"), proc("{d}", "/bin/id", "{c}", pid=12, parent_pid=10, t="4")]
    f = Forest(procs)
    assert [n.name for n in f.descendants("{c}")] == ["id"]


def test_zero_guid_parents_share_one_placeholder():
    procs = [proc("{a}", "/bin/bash", parent_pid=99, parent_image="-"),
             proc("{b}", "/bin/grep", parent_pid=99, parent_image="-")]
    f = Forest(procs)
    roots = f.roots
    assert len(roots) == 1 and roots[0].placeholder and len(roots[0].children) == 2


def test_web_app_tree_from_real_capture():
    f = Forest(parse_file(DATA / "incident.log").procs)
    web = next(n for n in f.real() if "webapp.py" in n.proc.cmd)
    names = {n.name for n in f.descendants(web.key)}
    assert {"dash", "ping", "id", "whoami", "curl", "bash"} <= names
    shell = next(n for n in f.descendants(web.key) if n.name == "id")
    assert f.chain(shell.key) == "python3.10 > dash > id"


def test_render_marks_nodes():
    procs = [proc("{a}", "/bin/bash"), proc("{b}", "/bin/id", "{a}")]
    out = Forest(procs).render("{a}", mark={"{b}"})
    assert out.splitlines()[1].startswith("`-- id") and out.endswith("<<")
