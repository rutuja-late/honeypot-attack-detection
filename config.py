import os

BASE = os.path.dirname(os.path.abspath(__file__))

LOG_PATH = os.getenv("LOG_PATH", "/var/lib/docker/volumes/cowrie-logs/_data/cowrie.json")
# Defaults to the repo folder, so it works on EC2 (/home/ubuntu/honeypot) and on the Kali VM alike.
DB_PATH = os.getenv("DB_PATH", os.path.join(BASE, "honeypot.db"))

WHITELIST = {x.strip() for x in os.getenv("WHITELIST", "").split(",") if x.strip()}
BLOCK_THRESHOLD = int(os.getenv("BLOCK_THRESHOLD", "60"))      # score -> BLOCK_IP
MONITOR_THRESHOLD = int(os.getenv("MONITOR_THRESHOLD", "25"))  # score -> MONITOR (increased monitoring)

# "simulate" (default): responses are only recorded, the firewall is never touched.
# "enforce": BLOCK_IP really adds an iptables DROP rule in DOCKER-USER.
RESPONSE_MODE = os.getenv("RESPONSE_MODE", "simulate").lower()

TG_TOKEN = os.getenv("TG_TOKEN")
TG_CHAT = os.getenv("TG_CHAT")