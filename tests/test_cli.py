from pathlib import Path

from ptree.__main__ import main

DATA = Path(__file__).resolve().parent.parent / "data"


def test_hunt_incident_exits_one_and_writes_report(tmp_path, capsys):
    rc = main(
        ["hunt", str(DATA / "incident.log"), "--baseline", str(DATA / "baseline.log"), "--out", str(tmp_path)]
    )
    assert rc == 1
    report = (tmp_path / "hunt_incident.md").read_text(encoding="utf-8")
    assert "web_shell_injection" in report and "- > fstrim" in report
    assert "8 alerts, 10 rare chains" in capsys.readouterr().out


def test_hunt_baseline_exits_zero(tmp_path):
    assert main(["hunt", str(DATA / "windows_baseline.xml"), "--out", str(tmp_path)]) == 0


def test_tree_by_pid_and_match(capsys):
    # pid 4828 is `sh /tmp/.x`, the second stage run by the injected shell.
    assert main(["tree", str(DATA / "incident.log"), "--pid", "4828"]) == 0
    assert capsys.readouterr().out.startswith("# - > python3.10 > dash > dash")
    # --match also finds the attacker's own curl: its command line carries the payload.
    assert main(["tree", str(DATA / "incident.log"), "--match", "/tmp/.x", "--limit", "1"]) == 0
    assert capsys.readouterr().out.startswith("# - > bash > curl")
    assert main(["tree", str(DATA / "incident.log"), "--pid", "999999"]) == 2


def test_missing_file_exits_two(tmp_path):
    assert main(["hunt", str(tmp_path / "nope.log")]) == 2


def test_score_writes_scorecard(tmp_path):
    assert main(["score", "--out", str(tmp_path)]) == 0
    text = (tmp_path / "scorecard.md").read_text(encoding="utf-8")
    assert "| lineage rules | 5 of 5 | 8 | 0 | - |" in text
