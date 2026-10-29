import re

S = r"(?:^|[;&|(])\s*"   # start of a command, also inside "a; b" / "a && b" / "a | b"

def _cmd(pattern):
    rx = re.compile(pattern, re.I)
    return lambda e: e.get("eventid") == "cowrie.command.input" and bool(rx.search(e.get("command") or ""))

def _ev(eid):
    return lambda e: e.get("eventid") == eid

# (technique id, name, tactic, test)
RULES = [
    ("T1110.001", "Brute Force: Password Guessing", "Credential Access", _ev("cowrie.login.failed")),
    ("T1078", "Valid Accounts", "Initial Access", _ev("cowrie.login.success")),
    ("T1021.004", "Remote Services: SSH", "Lateral Movement", _ev("cowrie.login.success")),
    ("T1059.004", "Unix Shell", "Execution", _ev("cowrie.command.input")),
    ("T1105", "Ingress Tool Transfer", "Command and Control",
        lambda e: e.get("eventid") == "cowrie.session.file_download" or _cmd(
            r"\b(wget|curl|tftp|ftpget|scp|sftp)\b|\bpython[0-9.]*\b.*\b(urllib|urlretrieve|urlopen|requests)\b")(e)),
    ("T1082", "System Information Discovery", "Discovery", _cmd(r"\buname\b|lscpu|cpuinfo|meminfo|lsb_release")),
    ("T1033", "System Owner/User Discovery", "Discovery", _cmd(S + r"(whoami|id|w|who|last)\b")),
    ("T1087.001", "Account Discovery: Local Account", "Discovery", _cmd(r"/etc/passwd")),
    ("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access", _cmd(r"/etc/shadow")),
    ("T1083", "File and Directory Discovery", "Discovery", _cmd(S + r"(ls|find|pwd)\b")),
    ("T1057", "Process Discovery", "Discovery", _cmd(S + r"(ps|top|htop)\b")),
    ("T1016", "System Network Configuration Discovery", "Discovery", _cmd(r"ifconfig|\bip\s+a\b|netstat|\bss\s+-")),
    ("T1046", "Network Service Discovery", "Discovery", _cmd(r"\b(nmap|masscan|zmap)\b")),
    ("T1053.003", "Scheduled Task/Job: Cron", "Persistence", _cmd(r"crontab")),
    ("T1098.004", "SSH Authorized Keys", "Persistence", _cmd(r"authorized_keys")),
    ("T1070.003", "Clear Command History", "Defense Evasion",
        _cmd(r"history\s+-c|unset\s+HISTFILE|HISTSIZE=0|bash_history")),
    ("T1027", "Obfuscated Files or Information", "Defense Evasion",
        _cmd(r"base64\s+(-d|--decode)|\\x[0-9a-f]{2}|\becho\b.*\|\s*(ba|z)?sh\b")),
    ("T1222.002", "File Permissions Modification: Linux", "Defense Evasion", _cmd(r"\bchmod\b")),
    ("T1496", "Resource Hijacking", "Impact", _cmd(r"xmrig|minerd|cpuminer|stratum\+tcp")),
]

TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access",
                "Discovery", "Lateral Movement", "Command and Control", "Impact"]

def split_cmd(cmd):
    """'a; b && c' -> ['a', 'b', 'c'] (a single pipe stays inside one part)."""
    return [x.strip() for x in re.split(r"\s*(?:;|&&|\|\|)\s*", cmd or "") if x.strip()]

def map_events(events):
    """{technique id: (name, count)}  (used by report.py)"""
    out = {}
    for e in events:
        for tid, name, _tactic, test in RULES:
            if test(e):
                n = out.get(tid, (name, 0))[1]
                out[tid] = (name, n + 1)
    return out

def map_events_detailed(events):
    """List of {id, name, tactic, count, evidence} sorted along the kill chain."""
    out = {}
    for e in events:
        for tid, name, tactic, test in RULES:
            if not test(e):
                continue
            t = out.setdefault(tid, {"id": tid, "name": name, "tactic": tactic, "count": 0, "evidence": ""})
            t["count"] += 1
            if not t["evidence"]:
                if e.get("eventid") == "cowrie.login.failed":
                    t["evidence"] = f"{e.get('username') or ''}:{e.get('password') or ''}"
                elif e.get("eventid") == "cowrie.login.success":
                    t["evidence"] = f"login as {e.get('username') or '?'}"
                elif e.get("eventid") == "cowrie.command.input":
                    cmd = e.get("command") or ""
                    part = next((x for x in split_cmd(cmd) if test(dict(e, command=x))), cmd)
                    t["evidence"] = part[:90]
                else:
                    t["evidence"] = (e.get("url") or "")[:90]
    return sorted(out.values(), key=lambda t: (TACTIC_ORDER.index(t["tactic"]), t["id"]))
