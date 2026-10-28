import re, datetime

RECON = re.compile(r"^\s*(whoami|id|uname|ifconfig|ip\s+a|netstat|ps|ls|w|who|hostname|lscpu|cat\s+/proc/(cpuinfo|meminfo))\b")
SUSP = re.compile(r"\b(wget|curl|tftp|chmod|crontab|base64|busybox|nc)\b|/etc/(passwd|shadow)|authorized_keys|rm\s+-rf|xmrig|minerd")
WINDOW_MIN, BRUTE_N = 5, 10

def _ago(ts, minutes):
    dt = datetime.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
    return (dt - datetime.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")

def classify(c, e):
    """Return (rule, severity, detail) or None. Call AFTER the event is inserted."""
    eid, ip, ts = e.get("eventid"), e.get("src_ip"), e.get("timestamp")
    cmd = (e.get("input") or "").strip()
    if eid == "cowrie.login.failed":
        n = c.execute("SELECT COUNT(*) FROM events WHERE src_ip=? AND eventid=? AND ts>=?",
                      (ip, eid, _ago(ts, WINDOW_MIN))).fetchone()[0]
        if n >= BRUTE_N:
            return "BRUTE_FORCE", "High", f"{BRUTE_N}+ failed logins in {WINDOW_MIN} min"
    elif eid == "cowrie.login.success":
        return "LOGIN_SUCCESS", "High", f"login ok as {e.get('username')}"
    elif eid == "cowrie.session.file_download":
        return "DOWNLOAD", "Critical", f"download {e.get('url') or e.get('outfile')}"
    elif eid == "cowrie.command.input":
        if SUSP.search(cmd): return "SUSPICIOUS_CMD", "High", cmd[:120]
        if RECON.search(cmd): return "RECON_CMD", "Medium", cmd[:120]
    return None

def record(c, ip, session, ts, rule, sev, detail):
    dup = c.execute("SELECT 1 FROM alerts WHERE ip=? AND rule=? AND detail=? AND ts>=?",
                    (ip, rule, detail, _ago(ts, 10))).fetchone()
    if dup:
        return False
    c.execute("INSERT INTO alerts(ts,ip,session,rule,severity,detail) VALUES(?,?,?,?,?,?)",
              (ts, ip, session, rule, sev, detail))
    return True