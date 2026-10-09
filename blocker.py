import ipaddress, subprocess
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
