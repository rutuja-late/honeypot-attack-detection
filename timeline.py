"""Feature 4: attacker activity timeline.

build(c, ip) returns everything the dashboard shows for one attacker:
counts (logins, sessions, commands, downloads), risk score, MITRE ATT&CK
techniques with evidence, and the ordered activity list.
Cowrie handshake noise (client.version, client.kex, client.var, ...) is stored
in the DB but filtered out here.
"""
import mitre

LABELS = {
    "cowrie.session.connect": ("connect", "session opened"),
    "cowrie.login.failed": ("failed", None),
    "cowrie.login.success": ("success", None),
    "cowrie.command.input": ("command", None),
    "cowrie.session.file_download": ("download", None),
    "cowrie.session.closed": ("closed", "session closed"),
}

def _text(kind, default, e):
    if kind == "failed":
        return f"failed login {e['username'] or ''}:{e['password'] or ''}"
    if kind == "success":
        return f"login accepted for {e['username'] or '?'}"
    if kind == "command":
        return (e["command"] or "")[:140]
    if kind == "download":
        return e["url"] or "file downloaded"
    return default

def build(c, ip, limit=40):
    a = c.execute("SELECT * FROM attackers WHERE ip=?", (ip,)).fetchone()
    if a is None:
        return None
    ev = [dict(r) for r in c.execute(
        "SELECT ts, session, eventid, username, password, command, url FROM events "
        "WHERE src_ip=? ORDER BY id", (ip,))]
    count = lambda eid: sum(1 for e in ev if e["eventid"] == eid)
    steps = []
    for e in reversed(ev):                      # newest first
        if e["eventid"] not in LABELS:
            continue
        kind, default = LABELS[e["eventid"]]
        if kind == "command":                   # "a; b; c" -> three steps, in order
            for part in mitre.split_cmd(e["command"]) or [""]:
                steps.append({"ts": e["ts"], "type": kind, "text": part[:140]})
        else:
            steps.append({"ts": e["ts"], "type": kind, "text": _text(kind, default, e)})
    monitored = c.execute("SELECT 1 FROM responses WHERE ip=? AND action='MONITOR' LIMIT 1", (ip,)).fetchone()
    return {
        "ip": ip, "country": a["country"], "severity": a["severity"], "score": a["score"],
        "blocked": bool(a["blocked"]), "monitored": bool(monitored),
        "first_seen": a["first_seen"], "last_seen": a["last_seen"],
        "counts": {
            "failed": count("cowrie.login.failed"),
            "success": count("cowrie.login.success"),
            "sessions": len({e["session"] for e in ev if e["session"]}),
            "commands": count("cowrie.command.input"),
            "downloads": count("cowrie.session.file_download"),
        },
        "mitre": mitre.map_events_detailed(ev),
        "events": steps[:limit],
    }
