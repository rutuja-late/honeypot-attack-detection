#!/usr/bin/env python3
"""Export a sanitized snapshot of the dashboard stats and publish it.

Runs on the honeypot server (cron, every few minutes):
  1. reads the local dashboard API (127.0.0.1:5000/api/stats)
  2. masks attacker IPs and hides the owner's own IPs
  3. force-pushes a single stats.json to the `data` branch of the GitHub repo

The GitHub Pages dashboard (docs/index.html) reads that file.

Settings come from the environment (see .env, never commit it):
  GH_TOKEN  fine-grained token limited to this one repo (Contents: read/write)
  GH_REPO   owner/name, e.g. rutuja-late/honeypot-attack-detection
  OWN_IPS   comma separated IPs of yours (laptop / Kali) that must never be shown
Use --dry-run to print the sanitized JSON instead of pushing.
"""
import datetime
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import urllib.request

API = os.getenv("STATS_URL", "http://127.0.0.1:5000/api/stats")
REPO = os.getenv("GH_REPO", "rutuja-late/honeypot-attack-detection")
TOKEN = os.getenv("GH_TOKEN", "")
OWN_IPS = {x.strip() for x in os.getenv("OWN_IPS", "").split(",") if x.strip()}
LAB_IP, LAB_COUNTRY = "203.0.113.9", "Lab (Kali VM)"


def mask(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "masked"
    if a.version == 4:
        p = str(a).split(".")
        return ".".join(p[:3] + ["xxx"])
    return ":".join(a.exploded.split(":")[:3]) + "::xxxx"


def show_ip(ip):
    return LAB_IP if ip in OWN_IPS else mask(ip)


def sanitize(d):
    out = dict(d)
    out["attackers"] = [
        dict(a, ip=show_ip(a["ip"]), country=LAB_COUNTRY if a["ip"] in OWN_IPS else a.get("country"))
        for a in d.get("attackers", [])
    ]
    out["recent"] = [dict(e, src_ip=show_ip(e["src_ip"])) for e in d.get("recent", [])]
    out["generated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return out


def fetch():
    with urllib.request.urlopen(API, timeout=10) as r:
        return json.load(r)


def git(args, cwd):
    r = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True,
                       env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).replace(TOKEN, "***") if TOKEN else (r.stderr or r.stdout)
        print("git failed:", msg.strip(), file=sys.stderr)
        sys.exit(1)


def push(payload):
    if not TOKEN:
        sys.exit("GH_TOKEN is not set")
    url = f"https://x-access-token:{TOKEN}@github.com/{REPO}.git"
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "stats.json"), "w") as f:
            json.dump(payload, f, separators=(",", ":"))
        git(["init", "-q", "-b", "data"], d)
        git(["add", "stats.json"], d)
        git(["-c", "user.name=honeypot-bot", "-c", "user.email=honeypot-bot@users.noreply.github.com",
             "commit", "-q", "-m", "snapshot " + payload["generated_at"]], d)
        git(["push", "-q", "-f", url, "data:data"], d)


if __name__ == "__main__":
    data = sanitize(fetch())
    if "--dry-run" in sys.argv:
        print(json.dumps(data, indent=1))
    else:
        push(data)
        print("pushed", data["generated_at"])
