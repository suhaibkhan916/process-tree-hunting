"""Write SYNTHETIC Windows Sysmon event 1 (ProcessCreate) data in the XML that
`Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | % { $_.ToXml() }` gives.

data/windows_baseline.xml  normal workstation and web server activity
data/windows_incident.xml  the same plus a malicious Word document and a web shell
data/windows_truth.txt     ProcessGuids of the attack processes, used only to score hunts

Hosts, users and hashes are made up. The PowerShell payload decodes to a harmless
Write-Output. It is never run; it is only text in an event.
"""

from __future__ import annotations

import argparse
import base64
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
START = datetime(2026, 11, 12, 8, 0, tzinfo=timezone.utc)
EXE = {
    "explorer": r"C:\Windows\explorer.exe",
    "winword": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "splwow64": r"C:\Windows\splwow64.exe",
    "chrome": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "services": r"C:\Windows\System32\services.exe",
    "svchost": r"C:\Windows\System32\svchost.exe",
    "taskhostw": r"C:\Windows\System32\taskhostw.exe",
    "w3wp": r"C:\Windows\System32\inetsrv\w3wp.exe",
    "csc": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "cmd": r"C:\Windows\System32\cmd.exe",
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "whoami": r"C:\Windows\System32\whoami.exe",
    "net": r"C:\Windows\System32\net.exe",
    "nltest": r"C:\Windows\System32\nltest.exe",
    "ipconfig": r"C:\Windows\System32\ipconfig.exe",
    "systeminfo": r"C:\Windows\System32\systeminfo.exe",
}


class Writer:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.rows: list[tuple[datetime, str]] = []
        self.next_pid = 4000
        self.attack_guids: list[str] = []
        self.recording = False

    def guid(self) -> str:
        return "{" + str(uuid.UUID(int=self.rng.getrandbits(128))) + "}"

    def proc(
        self, when: datetime, host: str, user: str, image: str, cmd: str, parent: dict[str, str] | None
    ) -> dict[str, str]:
        self.next_pid += self.rng.randint(4, 40)
        me = {"guid": self.guid(), "pid": str(self.next_pid), "image": image, "cmd": cmd}
        p = parent or {"guid": "{00000000-0000-0000-0000-000000000000}", "pid": "0", "image": "-", "cmd": "-"}
        data = {
            "RuleName": "-",
            "UtcTime": when.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "ProcessGuid": me["guid"],
            "ProcessId": me["pid"],
            "Image": image,
            "CommandLine": cmd,
            "CurrentDirectory": "C:\\Windows\\system32\\",
            "User": user,
            "IntegrityLevel": "Medium" if "\\" in user and "SYSTEM" not in user else "System",
            "ParentProcessGuid": p["guid"],
            "ParentProcessId": p["pid"],
            "ParentImage": p["image"],
            "ParentCommandLine": p["cmd"],
        }
        fields = "".join(f"<Data Name={quoteattr(k)}>{escape(v)}</Data>" for k, v in data.items())
        xml = (
            f"<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-Sysmon' "
            "Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID>"
            f"<TimeCreated SystemTime='{when.strftime('%Y-%m-%dT%H:%M:%S.%f')}0Z'/>"
            "<EventRecordID>{rec}</EventRecordID>"
            f"<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>{host}</Computer>"
            f"</System><EventData>{fields}</EventData></Event>"
        )
        self.rows.append((when, xml))
        if self.recording:
            self.attack_guids.append(me["guid"])
        return me

    def render(self) -> str:
        self.rows.sort(key=lambda r: r[0])
        body = "\n".join(x.replace("{rec}", str(1000 + i)) for i, (_, x) in enumerate(self.rows))
        return f"<Events>\n<!-- SYNTHETIC lab data. Not from a real system. -->\n{body}\n</Events>\n"


def baseline(w: Writer) -> tuple[dict, dict]:
    ws, user = "WKS-021.labcorp.local", "LABCORP\\p.ellis"
    explorer = w.proc(START, ws, user, EXE["explorer"], "C:\\Windows\\Explorer.EXE", None)
    for i in range(6):  # documents opened during the day; some are printed
        t = START + timedelta(minutes=20 + i * 55)
        word = w.proc(
            t,
            ws,
            user,
            EXE["winword"],
            f'"{EXE["winword"]}" /n "C:\\Users\\p.ellis\\Documents\\report-{i}.docx"',
            explorer,
        )
        if i % 2 == 0:
            w.proc(
                t + timedelta(minutes=5), ws, user, EXE["splwow64"], "C:\\Windows\\splwow64.exe 8192", word
            )
    for i in range(4):
        w.proc(
            START + timedelta(minutes=10 + i * 90), ws, user, EXE["chrome"], f'"{EXE["chrome"]}"', explorer
        )
    services = w.proc(
        START, ws, "NT AUTHORITY\\SYSTEM", EXE["services"], "C:\\Windows\\system32\\services.exe", None
    )
    for i in range(5):
        svc = w.proc(
            START + timedelta(minutes=i * 70),
            ws,
            "NT AUTHORITY\\SYSTEM",
            EXE["svchost"],
            "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
            services,
        )
        w.proc(START + timedelta(minutes=i * 70 + 1), ws, user, EXE["taskhostw"], "taskhostw.exe", svc)

    web, pool = "WEB-01.labcorp.local", "IIS APPPOOL\\Intranet"
    w3wp = w.proc(
        START, web, pool, EXE["w3wp"], '"C:\\Windows\\System32\\inetsrv\\w3wp.exe" -ap "Intranet"', None
    )
    for i in range(3):  # ASP.NET compiles pages on first request: a normal child of w3wp
        w.proc(
            START + timedelta(minutes=3 + i * 120),
            web,
            pool,
            EXE["csc"],
            f'"{EXE["csc"]}" /noconfig /fullpaths @"C:\\Windows\\Temp\\asp{i}.cmdline"',
            w3wp,
        )
    return explorer, w3wp


def attack(w: Writer, explorer: dict, w3wp: dict) -> None:
    ws, user = "WKS-021.labcorp.local", "LABCORP\\p.ellis"
    t = START + timedelta(hours=6, minutes=12)
    word = w.proc(
        t,
        ws,
        user,
        EXE["winword"],
        f'"{EXE["winword"]}" /n "C:\\Users\\p.ellis\\Downloads\\Invoice-4471.doc"',
        explorer,
    )
    enc = base64.b64encode("Write-Output 'lab payload'".encode("utf-16-le")).decode()
    cmd = w.proc(
        t + timedelta(seconds=9),
        ws,
        user,
        EXE["cmd"],
        f"cmd.exe /c powershell -nop -w hidden -enc {enc}",
        word,
    )
    ps = w.proc(
        t + timedelta(seconds=10), ws, user, EXE["powershell"], f"powershell -nop -w hidden -enc {enc}", cmd
    )
    for i, (name, args) in enumerate(
        [
            ("whoami", "whoami /all"),
            ("net", "net user /domain"),
            ("nltest", "nltest /dclist:labcorp"),
            ("ipconfig", "ipconfig /all"),
        ]
    ):
        w.proc(t + timedelta(seconds=30 + i * 4), ws, user, EXE[name], args, ps)

    web, pool = "WEB-01.labcorp.local", "IIS APPPOOL\\Intranet"
    t = START + timedelta(hours=7, minutes=3)
    for i, (name, args) in enumerate(
        [("whoami", "whoami"), ("systeminfo", "systeminfo"), ("net", "net localgroup administrators")]
    ):
        shell = w.proc(t + timedelta(minutes=i), web, pool, EXE["cmd"], f'cmd.exe /c "{args}"', w3wp)
        w.proc(t + timedelta(minutes=i, seconds=1), web, pool, EXE[name], args, shell)


def build(seed: int, with_attack: bool) -> tuple[str, list[str]]:
    w = Writer(random.Random(seed))
    explorer, w3wp = baseline(w)
    if with_attack:
        w.recording = True  # ground truth for scoring only; detections never read it
        attack(w, explorer, w3wp)
    return w.render(), w.attack_guids


def main() -> None:
    p = argparse.ArgumentParser(description="Write synthetic Windows Sysmon event 1 samples.")
    p.add_argument("--seed", type=int, default=4)
    p.add_argument("--out", type=Path, default=Path("data"))
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    base, _ = build(a.seed, False)
    incident, truth = build(a.seed, True)
    (a.out / "windows_baseline.xml").write_text(base, encoding="utf-8", newline="\n")
    (a.out / "windows_incident.xml").write_text(incident, encoding="utf-8", newline="\n")
    (a.out / "windows_truth.txt").write_text("\n".join(truth) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {a.out / 'windows_baseline.xml'} and {a.out / 'windows_incident.xml'}")


if __name__ == "__main__":
    main()
