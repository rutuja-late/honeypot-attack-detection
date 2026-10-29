import sqlite3
from config import DB_PATH

def conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=10000")  # engine and dashboard both write
    return c

def init():
    c = conn()
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript("""
    CREATE TABLE IF NOT EXISTS events(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT, session TEXT, src_ip TEXT, eventid TEXT,
      username TEXT, password TEXT, command TEXT, url TEXT, raw TEXT);
    CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
    CREATE TABLE IF NOT EXISTS attackers(
      ip TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
      score INTEGER DEFAULT 0, severity TEXT DEFAULT 'Low',
      country TEXT, blocked INTEGER DEFAULT 0, alerted INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS offsets(k TEXT PRIMARY KEY, v INTEGER);
    CREATE TABLE IF NOT EXISTS alerts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT, ip TEXT, session TEXT, rule TEXT, severity TEXT, detail TEXT);
    CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip);
    CREATE TABLE IF NOT EXISTS responses(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT, ip TEXT, action TEXT, mode TEXT, note TEXT);
    CREATE INDEX IF NOT EXISTS idx_responses_ip ON responses(ip);""")
    c.commit()
    c.close()