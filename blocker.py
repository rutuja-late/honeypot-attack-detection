import ipaddress, subprocess, datetime
import db

def _valid(ip):
    ipaddress.ip_address(ip)

def block(ip):
    _valid(ip)
    check = subprocess.run(["iptables", "-C", "DOCKER-USER", "-s", ip, "-j", "DROP"],
                           capture_output=True)
    if check.returncode != 0:
        subprocess.run(["iptables", "-I", "DOCKER-USER", "-s", ip, "-j", "DROP"],
                       check=True)

def unblock(ip):
    _valid(ip)
    subprocess.run(["iptables", "-D", "DOCKER-USER", "-s", ip, "-j", "DROP"])

def reapply():
    c = db.conn()
    for row in c.execute("SELECT ip FROM attackers WHERE blocked=1"):
        try:
            block(row["ip"])
        except Exception as e:
            print("reapply failed:", row["ip"], e)

ACTIONS = ("block_ip", "increase_monitoring")

def simulate(ip, action):
    """Log what WOULD happen. No subprocess, no iptables."""
    _valid(ip)
    if action not in ACTIONS:
        raise ValueError("unknown action")
    would = (f"iptables -I DOCKER-USER -s {ip} -j DROP" if action == "block_ip"
             else f"monitoring for {ip}: normal -> HIGH (alert on every command)")
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    c = db.conn()
    c.execute("INSERT INTO responses(ts,ip,action,mode,note) VALUES(?,?,?,?,?)",
              (ts, ip, action, "simulated", would))
    c.commit()
    return {"mode": "simulated", "action": action, "would_run": would, "ts": ts}