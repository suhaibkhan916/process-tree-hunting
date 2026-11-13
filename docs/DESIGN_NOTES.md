# Design notes

## Why trees and not single events

A detection on one event asks "is this process bad?". Most discovery and admin tools are not bad on their own. The parent and grandparent answer "who asked for this?", and that is usually the question that separates an admin from an intruder. Process trees are also how an analyst explains an incident: the tree under the first bad process is the scope.

## ProcessGuid over PID

Sysmon gives every process a GUID that is unique on the host. PIDs are reused, and the same PID can show up in one capture as two different processes. The forest keys nodes by GUID and links a child to `ParentProcessGuid`.

Two cases need a fallback:

- **The parent was never captured** (started before Sysmon, or filtered out). A placeholder node is made from the child's `ParentImage`, `ParentProcessId` and `ParentCommandLine`, keyed by the parent GUID.
- **The parent GUID is all zeros.** Sysmon for Linux reports this for processes started before it. The placeholder is then keyed by host, parent PID and parent image, so siblings with the same unknown parent share one node.

## Parsing two formats into one record

Sysmon for Linux writes one XML event per syslog line with no namespace. Windows tools write namespaced XML, sometimes with no root element. The parser strips namespaces and produces the same `Proc` and `Net` records from both, so trees, rules and reports have one code path. A syslog line cut off at the size limit is counted as unreadable rather than skipped silently.

## Lineage rules

- **Chaining in a web server's shell.** A web app that shells out means to run one program. `;`, `&&`, `|`, backticks and `$(` in that shell's command line mean someone added a second one. This caught all five Linux steps, including the cron step that left no child process.
- **Discovery grouped by the web server or Office process.** A web shell starts a new shell per request, so grouping by shell gives one weak alert per command. Grouping by the process the attacker came in through gives one alert with the whole list, and the severity rises with the count.
- **Office children by name, with a print helper left out.** `splwow64.exe` is a normal Word child when printing; it is not in the shell or LOLBin list.
- **Encoded PowerShell is decoded in the alert.** An analyst should not need a second tool to read it.
- **Download then execute needs the same path.** curl writing to `/dev/null` (health checks) is ignored, and the run must come after the download.

## Stacking

Count `grandparent > parent > process` chains in a baseline and list incident chains with a count of zero. Depth 3 is a trade-off: depth 2 (`dash > id`) loses the web server, so it cannot tell the backup job's shell from the injected one; depth 4 starts to include the launcher scripts, which differ between runs.

Stacking needs no idea of the attack, so it would catch an attack nobody wrote a rule for. Its costs showed up in the data: everything new is flagged (the host's `fstrim`), one attack gives many findings, and anything that does not create a process is invisible.

## Ground truth and scoring

Ground truth is kept away from the hunts. On Linux each payload ends with `#lab-attack`; on Windows the generator writes the attack GUIDs to a file. Only `score.py` reads either. A step is a connected piece of attack activity (a truth node whose parent is not truth, plus its truth descendants). A finding that touches no truth node is false. Scoring by step, not by process, matches how an analyst counts: catching any process of a step leads you to the rest of it through the tree.

## Reports

Each alert shows a tree pruned to its evidence: from the lowest common ancestor of the evidence, only the paths down to evidence and everything under it. Without pruning, an alert inside a busy web server prints every benign request.

## Possible next steps

- Turn on FileCreate for `/etc/cron*` and `~/.ssh/` and add file events to the tree, so built-in shell writes become visible.
- Longer baselines, and stacking across many hosts instead of one capture (the method behind most enterprise hunting).
- Express the lineage rules as Sigma rules on `ParentImage` and compare what Sigma can and cannot say about grandparents.
