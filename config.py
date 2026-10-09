import os
LOG_PATH = "/var/lib/docker/volumes/cowrie-logs/_data/cowrie.json"
DB_PATH = "/home/ubuntu/honeypot/honeypot.db"
WHITELIST = set()
BLOCK_THRESHOLD = 60
TG_TOKEN = os.getenv("TG_TOKEN")
TG_CHAT = os.getenv("TG_CHAT")
