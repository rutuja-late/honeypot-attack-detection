"""Feature 3: response (simulate or enforce).

Actions: BLOCK_IP, UNBLOCK_IP, MONITOR (increased monitoring).
Every action is written to the `responses` table. In simulate mode (default)
that is ALL that happens: iptables is never called. In enforce mode BLOCK_IP /
UNBLOCK_IP also add/remove a DROP rule in the DOCKER-USER chain.
"""
import datetime
import ipaddress
import subprocess
from config import RESPONSE_MODE

ACTIONS = ("BLOCK_IP", "UNBLOCK_IP", "MONITOR")

def _valid(ip):
    ipaddress.ip_address(ip)

def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def block(ip):
    _valid(ip)
    if RESPONSE_MODE != "enforce":
        return
    check = subprocess.run(["iptables", "-C", "DOCKER-USER", "-s", ip, "-j", "DROP"],
                           capture_output=True)
    if check.returncode != 0:
        subprocess.run(["iptables", "-I", "DOCKER-USER", "-s", ip, "-j", "DROP"],
                       check=True)

def unblock(ip):
    _valid(ip)
    if RESPONSE_MODE != "enforce":
        return
    subprocess.run(["iptables", "-D", "DOCKER-USER", "-s", ip, "-j", "DROP"])

def is_monitored(c, ip):
    return c.execute("SELECT 1 FROM responses WHERE ip=? AND action='MONITOR' LIMIT 1", (ip,)).fetchone() is not None

def apply(c, ip, action, note=""):
    """Apply one response action and record it. The caller commits."""
    _valid(ip)
    if action not in ACTIONS:
        raise ValueError("unknown action " + action)
    if action == "BLOCK_IP":
        block(ip)
        c.execute("UPDATE attackers SET blocked=1 WHERE ip=?", (ip,))
    elif action == "UNBLOCK_IP":
        unblock(ip)
        c.execute("UPDATE attackers SET blocked=0 WHERE ip=?", (ip,))
    c.execute("INSERT INTO responses(ts,ip,action,mode,note) VALUES(?,?,?,?,?)",
              (_now(), ip, action, RESPONSE_MODE, note))

def reapply(c):
    """After a restart: put real iptables rules back (enforce mode only)."""
    if RESPONSE_MODE != "enforce":
        return
    for row in c.execute("SELECT ip FROM attackers WHERE blocked=1"):
        try:
            block(row["ip"])
        except Exception as e:
            print("reapply failed:", row["ip"], e)
