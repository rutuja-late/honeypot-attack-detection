import re

def _cmd(pattern):
    rx = re.compile(pattern)
    return lambda e: e["eventid"] == "cowrie.command.input" and rx.search(e["command"] or "")

RULES = [
    ("T1110.001", "Brute Force: Password Guessing", lambda e: e["eventid"] == "cowrie.login.failed"),
    ("T1078", "Valid Accounts", lambda e: e["eventid"] == "cowrie.login.success"),
    ("T1021.004", "Remote Services: SSH", lambda e: e["eventid"] == "cowrie.login.success"),
    ("T1059.004", "Unix Shell", lambda e: e["eventid"] == "cowrie.command.input"),
    ("T1105", "Ingress Tool Transfer", lambda e: e["eventid"] == "cowrie.session.file_download"
        or _cmd(r"\b(wget|curl|tftp)\b")(e)),
    ("T1082", "System Information Discovery", _cmd(r"\buname\b|lscpu|cpuinfo")),
    ("T1033", "System Owner/User Discovery", _cmd(r"\b(whoami|id|w|who)\b")),
    ("T1087.001", "Account Discovery: Local Account", _cmd(r"/etc/passwd")),
    ("T1083", "File and Directory Discovery", _cmd(r"^\s*(ls|find)\b")),
    ("T1057", "Process Discovery", _cmd(r"\b(ps|top)\b")),
    ("T1016", "System Network Configuration Discovery", _cmd(r"ifconfig|ip a|netstat")),
    ("T1053.003", "Scheduled Task/Job: Cron", _cmd(r"crontab")),
    ("T1098.004", "SSH Authorized Keys", _cmd(r"authorized_keys")),
    ("T1070.003", "Clear Command History", _cmd(r"history\s+-c")),
    ("T1496", "Resource Hijacking", _cmd(r"xmrig|minerd")),
]

def map_events(events):
    out = {}
    for e in events:
        for tid, name, test in RULES:
            if test(e):
                n = out.get(tid, (name, 0))[1]
                out[tid] = (name, n + 1)
    return out
