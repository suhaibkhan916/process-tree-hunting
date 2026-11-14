# process-tree-hunting

[![ci](https://github.com/suhaibkhan916/process-tree-hunting/actions/workflows/ci.yml/badge.svg)](https://github.com/suhaibkhan916/process-tree-hunting/actions/workflows/ci.yml)

Build process trees from Sysmon ProcessCreate events and hunt in them two ways: with lineage rules written from attacker behaviour (web server to shell, Office to shell), and with stacking (chains that never appear in a baseline). Both are scored against ground truth on a real Sysmon for Linux capture and on synthetic Windows Sysmon data.

**Data:**
- `data/baseline.log` and `data/incident.log` are **real Sysmon for Linux 1.6.0 output**, captured in a disposable container on Docker Desktop. The activity in them is **synthetic**: a scripted user of a deliberately vulnerable lab web app, plus a scripted attack through its command injection. The attack only talks to a second lab container on an internal Docker network, and its payloads only print text.
- `data/windows_*.xml` are **synthetic** Windows Sysmon events made by `make_windows_sample.py`. Hosts, users and GUIDs are made up. The encoded PowerShell decodes to a harmless `Write-Output`.

## The problem

A single process event rarely tells you much. `whoami` is normal. `whoami` whose parent is `cmd.exe` whose parent is `w3wp.exe` is a web shell. `python3` running `sh -c ping ...` is normal for this lab app, and the same chain with `; id` on the end is command injection. You only see this with the tree.

Two questions:
1. Hand-written lineage rules need someone to think of the attack first. How much do they catch, and how noisy are they?
2. Stacking needs no idea of the attack, only a baseline. What does it catch, and what does it get wrong?

## What gets built

| Part | What it does |
|---|---|
| `ptree/parser.py` | reads Sysmon for Linux syslog lines and Windows event XML into the same records; counts lines cut off at the syslog size limit |
| `ptree/tree.py` | process forest keyed by **ProcessGuid**, placeholders for parents the capture never saw, ancestors, descendants, chains, ASCII trees pruned to the evidence |
| `ptree/hunts.py` | six lineage rules and baseline stacking |
| `ptree/score.py` | ground truth and scoring (the only code that reads the truth markers) |
| `python -m ptree` | `hunt`, `tree` and `score` commands |

Lineage rules:

| Rule | ATT&CK | Logic |
|---|---|---|
| web_shell_injection | T1190 | shell whose parent is a web server, with `;`, `&&`, `\|`, backticks or `$(` in its command line |
| discovery_from_unusual_parent | T1033, T1082, T1087 | `id`, `whoami`, `uname`, `systeminfo`, `nltest`, `net`, `cat /etc/passwd` and similar, run by a shell that sits under a web server or Office program. One alert per web server or Office process; high at 3 or more commands |
| office_spawns_shell | T1204.002, T1059 | Word, Excel, PowerPoint, Outlook or OneNote starting a shell or a LOLBin (mshta, rundll32, regsvr32, wscript, cscript, certutil) |
| encoded_powershell | T1059.001, T1027 | PowerShell with `-enc` and its abbreviations; the payload is decoded into the alert |
| download_then_execute | T1105, T1059.004 | curl or wget writes a file with `-o`, then a later process in the same tree has that path on its command line |
| shell_network | T1059.004 | a shell with `/dev/tcp/` in its command line, or a NetworkConnect event from a shell |

Stacking counts every `grandparent > parent > process` chain in the baseline and lists the incident chains that never appeared there.

## How to run

Analysis only (Python 3.10 or later, no third-party packages at run time):

```bash
python -m ptree score                                                   # scorecard for both datasets
python -m ptree hunt data/incident.log --baseline data/baseline.log     # report in reports/
python -m ptree hunt data/windows_incident.xml --baseline data/windows_baseline.xml
python -m ptree tree data/incident.log --pid 4828                       # the tree around one process
pip install -r requirements-dev.txt && python -m pytest -q
```

`hunt` exits `1` when a high or critical alert fires, `0` when none does, and `2` when an input file is missing.

New Linux captures (Docker needed; about two minutes after the image build). From the repo root, in Git Bash or a Linux shell:

```bash
bash scripts/capture.sh baseline incident
```

The sensor runs `--privileged --pid=host` because Sysmon for Linux uses eBPF and reports host PIDs. Run it only on a machine you own. A new capture has different PIDs, GUIDs and times, so a few tests that name a PID would need updating.

## Results

Scorecard (`python -m ptree score`):

| Data | Method | Attack steps found | Findings | False findings | Missed |
|---|---|---|---|---|---|
| Linux, real capture | lineage rules | 5 of 5 | 8 | 0 | none |
| Linux, real capture | stacking | 4 of 5 | 10 | 1 | the cron persistence step |
| Windows, synthetic | lineage rules | 4 of 4 | 4 | 0 | none |
| Windows, synthetic | stacking | 4 of 4 | 10 | 0 | none |

The lineage rules raise **no alerts on either baseline**. The Linux baseline has 68 process events from 12 rounds of normal app use, including 12 `python3.10 > dash > ping` chains that look like the attack's parent chain. The Windows baseline has Word printing through `splwow64.exe` and IIS compiling pages with `csc.exe`, both normal children that a careless rule would flag.

What the capture showed:

- **The cron persistence step left no process.** The payload was `echo '...' > /etc/cron.d/lab-job`. `echo` and the redirect are shell built-ins, so the only ProcessCreate is the injected shell itself. Stacking missed it, because `python3.10 > dash` is in the baseline and the shell had no new child. The lineage rule caught it only because the shell's command line contains `;`. A FileCreate event on `/etc/cron.d/` would show it directly; this lab's config has file events off to keep the focus on processes.
- **Stacking's one false finding is the host.** `fstrim` is a Docker Desktop VM maintenance job. It appears because the sensor runs with `--pid=host`, and it ran during the incident capture but not the baseline. That is how stacking behaves in real estates too: anything new is flagged, attack or not, so a short baseline gives noise.
- **Stacking is noisier.** It gives one finding per new chain (10 on each dataset), where the rules group them into 8 and 4 alerts.
- **Processes started before Sysmon have an all-zero parent GUID** and `ParentImage` of `-`. The forest turns these into one placeholder node per parent PID, so `benign.sh` and `attack.sh` still have tree roots.
- **The injected shell forks every command.** `dash` ran `ping`, `id`, `whoami` and the rest as separate children, so each one is its own ProcessCreate event with the shell as parent.

Checks in this build: 37 pytest tests pass on Python 3.14 locally and on Python 3.10 in a `python:3.10-slim` container. `ruff check` and `ruff format --check` are clean. The same checks, the scorecard and both hunt reports pass on GitHub Actions on Python 3.10, 3.12 and 3.13, with the same scorecard numbers.

## What broke and how it was fixed

- **One reverse shell, two alerts.** The injected `sh -c "...; bash -c 'exec 3<>/dev/tcp/...'"` and the `bash` it started both had `/dev/tcp/` on their command line. `shell_network` now skips a shell when a descendant shell carries the same text, and a test checks one alert per socket.
- **A web shell gave three medium alerts instead of one high.** Discovery commands were grouped by the shell that ran them, and the IIS web shell starts a new `cmd.exe` per request. They are now grouped by the web server or Office process above them.
- **A report drew the whole web server.** The `download_then_execute` tree started at `python3.10` and printed every benign ping round. Trees now start at the lowest common ancestor of the alert's evidence and keep only the paths to the evidence.
- **A test searched the wrong side.** `ptree tree --match /tmp/.x` was expected to find the victim's shell, but the first match was the attacker's own `curl`, because its command line carries the payload. The test now uses `--pid` and checks both results. Text search on command lines finds the client as well as the victim.

## Limitations

- One app, one attack, a two-minute capture. The baseline is far too short for stacking to be trusted outside a lab.
- `python3.10` counts as a web server image here. In a real estate Python runs many scripts that shell out, so this rule would need scoping to known services.
- The Windows data is synthetic and follows the Sysmon event 1 schema. It has not been checked against a real Windows Sysmon capture.
- Grandparent chains of image names only. Two different scripts run by the same interpreter look the same to stacking.
- Ground truth for Linux comes from a `#lab-attack` comment at the end of each payload. No hunt reads it, but it does appear in the captured command lines and reports.
- Command-line rules can be evaded (for example with `${IFS}` instead of spaces, or `$'\x3b'`). Lineage alone (`python3.10 > dash > id`) is harder to hide.
- Placeholder parents are keyed by PID. A reused PID inside one capture would merge two unrelated parents.

## Layout

```
data/                     real Linux captures, synthetic Windows samples, Windows truth list
configs/sysmon-process.xml  Sysmon config: ProcessCreate and NetworkConnect only
docker/Dockerfile         Ubuntu 22.04 with Sysmon for Linux from Microsoft's repo
scenario/                 vulnerable web app, benign workload, attack, capture script
scripts/capture.sh        builds the image and records both captures
make_windows_sample.py    synthetic Windows generator (seeded)
ptree/                    parser, tree, hunts, score, report, CLI
tests/                    pytest
docs/DESIGN_NOTES.md      design decisions
```

MIT licence.
