SUSPICIOUS = ["wget", "curl", "chmod", "/etc/passwd", "/etc/shadow", "uname",
              "crontab", "nc ", "base64", "rm -rf", "authorized_keys",
              "busybox", "tftp",
              # added after the detection-gap tests (docs/DETECTION_TESTS.md)
              "nmap", "masscan", "scp ", "sftp ", "xmrig", "minerd", "cpuminer",
              "history -c", "histfile", "| sh", "|sh", "| bash", "|bash",
              "urllib", "urlretrieve", "/dev/tcp", "ncat", "netcat", "shred"]

def severity(score):
    if score >= 100: return "Critical"
    if score >= 60: return "High"
    if score >= 25: return "Medium"
    return "Low"

def compute(c, ip):
    r = c.execute("""SELECT
        COALESCE(SUM(eventid='cowrie.login.failed'), 0) AS failed,
        COALESCE(SUM(eventid='cowrie.login.success'), 0) AS success,
        COALESCE(SUM(eventid='cowrie.session.file_download'), 0) AS downloads
        FROM events WHERE src_ip=?""", (ip,)).fetchone()
    cmds = [x["command"] or "" for x in c.execute(
        "SELECT command FROM events WHERE src_ip=? AND eventid='cowrie.command.input'",
        (ip,))]
    sus = sum(1 for cmd in cmds if any(k in cmd.lower() for k in SUSPICIOUS))
    score = min(r["failed"], 30)
    if r["failed"] >= 10: score += 25
    if r["success"] > 0: score += 20
    score += min(len(cmds), 10) * 3
    score += sus * 15
    score += r["downloads"] * 40
    return score
