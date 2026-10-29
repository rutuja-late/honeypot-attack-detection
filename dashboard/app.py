import datetime
import ipaddress
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from flask import Flask, abort, jsonify, request, send_from_directory
import blocker, db, timeline
from config import RESPONSE_MODE, WHITELIST

DOCS = os.path.join(BASE, "docs")   # the same page is served here (live) and on GitHub Pages (snapshot)
app = Flask(__name__)
db.init()


@app.after_request
def no_cache(r):
    if r.mimetype == "text/html" or request.path.startswith("/api/"):
        r.headers["Cache-Control"] = "no-store"
    return r


@app.route("/")
def index():
    return send_from_directory(DOCS, "index.html")


@app.route("/demo.html")
def demo():
    return send_from_directory(DOCS, "demo.html")


@app.route("/api/stats")
def stats():
    c = db.conn()
    rows = lambda sql: [dict(r) for r in c.execute(sql)]
    t = c.execute("""SELECT COUNT(*) AS events, COUNT(DISTINCT src_ip) AS ips,
        (SELECT COUNT(*) FROM attackers WHERE blocked=1) AS blocked,
        (SELECT COUNT(*) FROM attackers
           WHERE severity IN ('High','Critical')) AS high FROM events""").fetchone()
    attackers = rows(
        "SELECT ip, country, score, severity, blocked, "
        "EXISTS(SELECT 1 FROM responses r WHERE r.ip=attackers.ip AND r.action='MONITOR') AS monitored "
        "FROM attackers ORDER BY score DESC LIMIT 10")
    return jsonify(
        generated_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        mode=RESPONSE_MODE,
        totals=dict(t),
        passwords=rows("SELECT password AS k, COUNT(*) AS n FROM events "
                       "WHERE eventid='cowrie.login.failed' AND password IS NOT NULL "
                       "GROUP BY password ORDER BY n DESC LIMIT 10"),
        usernames=rows("SELECT username AS k, COUNT(*) AS n FROM events "
                       "WHERE eventid='cowrie.login.failed' AND username IS NOT NULL "
                       "GROUP BY username ORDER BY n DESC LIMIT 10"),
        countries=rows("SELECT country AS k, COUNT(*) AS n FROM attackers "
                       "GROUP BY country ORDER BY n DESC LIMIT 10"),
        timeline=rows("SELECT substr(ts,1,13) AS k, COUNT(*) AS n FROM events "
                      "GROUP BY k ORDER BY k DESC LIMIT 48"),
        recent=rows("SELECT ts, src_ip, eventid, username, command FROM events "
                    "WHERE eventid IN ('cowrie.login.failed','cowrie.login.success',"
                    "'cowrie.command.input','cowrie.session.file_download') "
                    "ORDER BY id DESC LIMIT 15"),
        attackers=attackers,
        alerts=rows("SELECT ts, ip, session, rule, severity, detail FROM alerts "
                    "ORDER BY id DESC LIMIT 25"),
        alert_counts=rows("SELECT severity AS k, COUNT(*) AS n FROM alerts GROUP BY severity"),
        responses=rows("SELECT ts, ip, action, mode, note FROM responses ORDER BY id DESC LIMIT 15"),
        timelines=[timeline.build(c, a["ip"]) for a in attackers])


@app.route("/api/timeline/<ip>")
def timeline_for(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        abort(400)
    t = timeline.build(db.conn(), ip)
    if t is None:
        abort(404)
    return jsonify(t)


@app.route("/api/respond", methods=["POST"])
def respond():
    """Manual response from the dashboard buttons (local page only)."""
    if request.host.split(":")[0] not in ("127.0.0.1", "localhost"):
        abort(403)
    if not request.is_json:          # forces a CORS preflight, so other websites cannot call this
        abort(415)
    d = request.get_json(silent=True) or {}
    ip, action = d.get("ip"), d.get("action")
    if action not in blocker.ACTIONS:
        return jsonify(ok=False, error="unknown action"), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify(ok=False, error="invalid ip"), 400
    if ip in WHITELIST and action == "BLOCK_IP":
        return jsonify(ok=False, error="ip is whitelisted"), 403
    c = db.conn()
    if c.execute("SELECT 1 FROM attackers WHERE ip=?", (ip,)).fetchone() is None:
        return jsonify(ok=False, error="unknown attacker"), 404
    try:
        blocker.apply(c, ip, action, "manual (dashboard)")
        c.commit()
    except Exception as ex:
        return jsonify(ok=False, error=str(ex)), 500
    return jsonify(ok=True, ip=ip, action=action, mode=RESPONSE_MODE)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
