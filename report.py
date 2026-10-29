import os, sys
import db, mitre
from config import BASE

def build(ip):
    c = db.conn()
    a = c.execute("SELECT * FROM attackers WHERE ip=?", (ip,)).fetchone()
    if a is None:
        return "No data for " + ip
    ev = [dict(r) for r in c.execute("SELECT * FROM events WHERE src_ip=? ORDER BY id", (ip,))]
    techs = mitre.map_events(ev)
    cmds = [e["command"] for e in ev if e["eventid"] == "cowrie.command.input"]
    urls = {e["url"] for e in ev if e["url"]}
    pw = sorted({e["password"] for e in ev if e["eventid"] == "cowrie.login.failed" and e["password"]})[:15]
    out = [f"INCIDENT REPORT: {ip}",
           f"Country: {a['country']}  Severity: {a['severity']} (score {a['score']})",
           f"First seen: {a['first_seen']}  Last seen: {a['last_seen']}",
           f"Blocked: {'yes' if a['blocked'] else 'no'}",
           f"Total events: {len(ev)}  Commands: {len(cmds)}", "",
           "MITRE ATT&CK techniques:"]
    for tid, (name, n) in sorted(techs.items()):
        out.append(f"  {tid}  {name}  (x{n})")
    out += ["", "Commands run:"] + [f"  $ {x}" for x in cmds[:30]]
    out += ["", "Downloaded URLs: " + (", ".join(urls) or "none"),
            "Sample passwords tried: " + (", ".join(pw) or "none"), "",
            "Recommendations: disable password SSH, use keys, rate-limit/fail2ban, egress filtering."]
    return "\n".join(out)

if __name__ == "__main__":
    text = build(sys.argv[1])
    folder = os.path.join(BASE, "reports")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, f"{sys.argv[1]}.txt"), "w") as f:
        f.write(text)
    print(text)
