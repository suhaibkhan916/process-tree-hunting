"""Read Sysmon ProcessCreate (1) and NetworkConnect (3) events from two formats:

- Sysmon for Linux lines in syslog: `... sysmon: <Event>...</Event>` (no XML namespace)
- Windows XML from Get-WinEvent ToXml() or wevtutil, with or without a root element

Both become the same Proc and Net records, so the tree code does not care which OS
the data came from.
"""

from __future__ import annotations

import codecs
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

ZERO_GUID = "{00000000-0000-0000-0000-000000000000}"
_NS = re.compile(r"^\{[^}]*\}")


@dataclass(frozen=True)
class Proc:
    guid: str
    pid: int
    image: str
    cmd: str
    parent_guid: str
    parent_pid: int
    parent_image: str
    parent_cmd: str
    user: str
    time: str
    host: str

    @property
    def name(self) -> str:
        return basename(self.image)


@dataclass(frozen=True)
class Net:
    guid: str
    pid: int
    image: str
    dest_ip: str
    dest_port: str
    time: str


@dataclass
class Capture:
    procs: list[Proc]
    nets: list[Net]
    unreadable: int = 0


def basename(path: str) -> str:
    """Last part of a Linux or Windows path, lower case. '-' stays '-'."""
    return re.split(r"[\\/]", path)[-1].lower() if path else "-"


def _int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return -1


def _event(elem: ET.Element) -> tuple[int, str, dict[str, str]]:
    event_id, host, data = 0, "", {}
    for part in elem:
        tag = _NS.sub("", part.tag)
        if tag == "System":
            for field in part:
                ftag = _NS.sub("", field.tag)
                if ftag == "EventID":
                    event_id = _int(field.text or "")
                elif ftag == "Computer":
                    host = field.text or ""
        elif tag == "EventData":
            for d in part:
                data[d.get("Name", "")] = (d.text or "").strip()
    return event_id, host, data


def _add(cap: Capture, event_id: int, host: str, d: dict[str, str]) -> None:
    g = d.get
    if event_id == 1:
        cap.procs.append(
            Proc(
                guid=g("ProcessGuid", ZERO_GUID),
                pid=_int(g("ProcessId", "")),
                image=g("Image", ""),
                cmd=g("CommandLine", ""),
                parent_guid=g("ParentProcessGuid", ZERO_GUID),
                parent_pid=_int(g("ParentProcessId", "")),
                parent_image=g("ParentImage", "-") or "-",
                parent_cmd=g("ParentCommandLine", ""),
                user=g("User", ""),
                time=g("UtcTime", ""),
                host=host,
            )
        )
    elif event_id == 3:
        cap.nets.append(
            Net(
                guid=g("ProcessGuid", ZERO_GUID),
                pid=_int(g("ProcessId", "")),
                image=g("Image", ""),
                dest_ip=g("DestinationIp", ""),
                dest_port=g("DestinationPort", ""),
                time=g("UtcTime", ""),
            )
        )


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def parse_file(path: Path | str) -> Capture:
    path = Path(path)
    text = _read_text(path)
    cap = Capture([], [])
    if "sysmon: <Event>" in text:  # Sysmon for Linux via syslog, one event per line
        for line in text.splitlines():
            if "sysmon: <Event>" not in line:
                continue
            try:
                elem = ET.fromstring(line.split("sysmon: ", 1)[1])
            except ET.ParseError:
                cap.unreadable += 1  # e.g. a record cut at the syslog size limit
                continue
            _add(cap, *_event(elem))
    else:  # Windows XML, events back to back or inside a root element
        if text.lstrip().startswith("<?xml"):
            text = text.split("?>", 1)[1]
        root = ET.fromstring(f"<Root>{text}</Root>")
        for elem in root.iter():
            if _NS.sub("", elem.tag) == "Event":
                _add(cap, *_event(elem))
    cap.procs.sort(key=lambda p: p.time)
    return cap
