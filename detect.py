"""Feature 1: real-time attack alerts.

evaluate() looks at one Cowrie event and returns the alert rules it triggers.
run() stores new alerts in the `alerts` table (one alert per rule, per session
or per IP, so a noisy attacker does not flood the feed).
"""
import re
import mitre

BRUTE_MEDIUM = 5     # failed logins from one IP -> Medium alert
BRUTE_HIGH = 20      # failed logins from one IP -> High alert

# (rule, severity, regex). A single command can trigger several rules.
CMD_RULES = [(r, s, re.compile(p, re.I)) for r, s, p in [
    ("Malware / tool download", "Critical", r"\b(wget|curl|tftp|ftpget)\b"),
    ("Scripted download (python)", "Critical",
        r"\bpython[0-9.]*\b.*\b(urllib|urlretrieve|urlopen|requests|wget)\b"),
    ("Cryptominer", "Critical", r"xmrig|minerd|cpuminer|stratum\+tcp"),
    ("Reverse shell / netcat", "High", r"\b(nc|ncat|netcat)\b|/dev/tcp/|\bbash\s+-i\b"),
    ("Pipe to shell", "High", r"\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
    ("Encoded payload", "High", r"base64\s+(?:-d|--decode)|\\x[0-9a-f]{2}"),
    ("Password file (/etc/shadow)", "High", r"/etc/shadow"),
    ("Account file (/etc/passwd)", "Medium", r"/etc/passwd"),
    ("Persistence", "High", r"crontab|authorized_keys|/etc/rc\.local|systemctl\s+enable"),
    ("Log / history tampering", "High",
        r"history\s+-c|unset\s+HISTFILE|HISTSIZE=0|rm\s+.*(?:/var/log|bash_history)|\bshred\b"),
    ("Destructive command", "High", r"\brm\s+-rf\s+/(?!tmp)"),
    ("File transfer (scp/sftp)", "Medium", r"\b(scp|sftp|rsync)\b"),
    ("Network scanning", "Medium", r"\b(nmap|masscan|zmap)\b"),
    ("Permission change", "Medium", r"\bchmod\b"),
    ("Reconnaissance", "Low",
        r"(?:^|[;&|(])\s*(?:uname|whoami|id|hostname|lscpu|uptime|ps|ifconfig|netstat|ss|w|who|ls|pwd|env|df|free|lsb_release)\b"
        r"|/proc/(?:cpuinfo|meminfo)|\bip\s+a\b"),
]]


def evaluate(c, e):
    """Return [(rule, severity, detail, scope)] for one event. scope is 'ip' or 'session'."""
    eid, ip = e.get("eventid"), e.get("src_ip")
    out = []
    if eid == "cowrie.login.failed":
        n = c.execute("SELECT COUNT(*) FROM events WHERE src_ip=? AND eventid='cowrie.login.failed'",
                      (ip,)).fetchone()[0]
        if n == BRUTE_MEDIUM:
            out.append(("SSH brute force", "Medium", f"{n} failed logins", "ip"))
        elif n == BRUTE_HIGH:
            out.append(("SSH brute force", "High", f"{n}+ failed logins, still going", "ip"))
    elif eid == "cowrie.login.success":
        user = e.get("username") or "?"
        n = c.execute("SELECT COUNT(*) FROM events WHERE src_ip=? AND eventid='cowrie.login.failed'",
                      (ip,)).fetchone()[0]
        if n >= BRUTE_MEDIUM:
            out.append(("Credential guessing succeeded", "Critical",
                        f"login as '{user}' after {n} failed attempts", "ip"))
        else:
            out.append(("Successful login", "High", f"login accepted for '{user}'", "ip"))
    elif eid == "cowrie.session.file_download":
        out.append(("File download captured", "Critical", e.get("url") or e.get("outfile") or "file", "session"))
    elif eid == "cowrie.command.input":
        cmd = (e.get("input") or "").strip()
        for rule, sev, rx in CMD_RULES:
            if rx.search(cmd):
                part = next((x for x in mitre.split_cmd(cmd) if rx.search(x)), cmd)
                out.append((rule, sev, part[:140], "session"))
    return out


def run(c, e):
    """Evaluate one event and store alerts that are new. Returns the stored alerts."""
    ip, session, ts = e.get("src_ip"), e.get("session") or "", e.get("timestamp")
    stored = []
    for rule, sev, detail, scope in evaluate(c, e):
        q, args = "SELECT 1 FROM alerts WHERE ip=? AND rule=? AND severity=?", [ip, rule, sev]
        if scope == "session":
            q += " AND session=?"
            args.append(session)
        if c.execute(q, args).fetchone():
            continue
        c.execute("INSERT INTO alerts(ts,ip,session,rule,severity,detail) VALUES(?,?,?,?,?,?)",
                  (ts, ip, session, rule, sev, detail))
        stored.append({"ts": ts, "ip": ip, "rule": rule, "severity": sev, "detail": detail})
    return stored
