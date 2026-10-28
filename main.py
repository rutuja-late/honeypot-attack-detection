import json, os, time
import db, scoring, blocker, notifier, geo, detect
from config import LOG_PATH, WHITELIST, BLOCK_THRESHOLD

def read_new(path, pos):
    lines = []
    if not os.path.exists(path):
        return lines, pos
    if os.path.getsize(path) < pos:
        pos = 0
    with open(path, "r") as f:
        f.seek(pos)
        while True:
            line = f.readline()
            if not line or not line.endswith("\n"):
                break
            lines.append(line)
            pos = f.tell()
    return lines, pos

def handle(c, e):
    ip, eid, ts = e.get("src_ip"), e.get("eventid"), e.get("timestamp")
    if not ip or not eid:
        return
    c.execute("INSERT INTO events(ts,session,src_ip,eventid,username,password,"
              "command,url,raw) VALUES(?,?,?,?,?,?,?,?,?)",
              (ts, e.get("session"), ip, eid, e.get("username"), e.get("password"),
               e.get("input"), e.get("url"), json.dumps(e)))
    if c.execute("SELECT 1 FROM attackers WHERE ip=?", (ip,)).fetchone() is None:
        c.execute("INSERT INTO attackers(ip,first_seen,last_seen,country) "
                  "VALUES(?,?,?,?)", (ip, ts, ts, geo.country(ip)))
    else:
        c.execute("UPDATE attackers SET last_seen=? WHERE ip=?", (ts, ip))
    score = scoring.compute(c, ip)
    sev = scoring.severity(score)
    row = c.execute("SELECT * FROM attackers WHERE ip=?", (ip,)).fetchone()
    c.execute("UPDATE attackers SET score=?, severity=? WHERE ip=?", (score, sev, ip))
    if sev in ("High", "Critical") and not row["alerted"]:
        notifier.send(f"[{sev}] attacker {ip} ({row['country']}) score={score}")
        c.execute("UPDATE attackers SET alerted=1 WHERE ip=?", (ip,))
    hit = detect.classify(c, e)
    if hit and detect.record(c, ip, e.get("session"), ts, *hit):
        rule, asev, detail = hit
        if asev == "Critical":
            notifier.send(f"[ALERT {asev}] {rule} from {ip}: {detail}")
    if score >= BLOCK_THRESHOLD and not row["blocked"] and ip not in WHITELIST:
        blocker.block(ip)
        c.execute("UPDATE attackers SET blocked=1 WHERE ip=?", (ip,))
        notifier.send(f"[BLOCKED] {ip} auto-blocked (score {score})")

def main():
    db.init()
    blocker.reapply()
    c = db.conn()
    row = c.execute("SELECT v FROM offsets WHERE k='pos'").fetchone()
    pos = row["v"] if row else 0
    while True:
        lines, pos = read_new(LOG_PATH, pos)
        for line in lines:
            try:
                handle(c, json.loads(line))
            except Exception as ex:
                print("skip line:", ex)
        c.execute("INSERT OR REPLACE INTO offsets(k,v) VALUES('pos',?)", (pos,))
        c.commit()
        time.sleep(1)

if __name__ == "__main__":
    main()