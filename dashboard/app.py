import sys, os, ipaddress
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from flask import Flask, jsonify, render_template, request, abort
import db, blocker, mitre

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    c = db.conn()
    rows = lambda sql: [dict(r) for r in c.execute(sql)]
    t = c.execute("""SELECT COUNT(*) AS events, COUNT(DISTINCT src_ip) AS ips,
        (SELECT COUNT(*) FROM attackers WHERE blocked=1) AS blocked,
        (SELECT COUNT(*) FROM attackers
           WHERE severity IN ('High','Critical')) AS high FROM events""").fetchone()
    return jsonify(
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
                    "ORDER BY id DESC LIMIT 15"),
        attackers=rows("SELECT ip, country, score, severity, blocked FROM attackers "
                       "ORDER BY score DESC LIMIT 10"))

@app.route("/api/alerts")
def alerts():
    c = db.conn()
    return jsonify([dict(r) for r in c.execute(
        "SELECT ts, ip, severity, rule, detail FROM alerts ORDER BY id DESC LIMIT 50")])

@app.route("/api/respond", methods=["POST"])
def respond():
    if request.headers.get("X-Requested-With") != "honeypot-ui":
        abort(403)
    d = request.get_json(silent=True) or {}
    try:
        return jsonify(blocker.simulate(d.get("ip", ""), d.get("action", "")))
    except ValueError as ex:
        return jsonify(error=str(ex)), 400

@app.route("/api/attacker/<ip>")
def attacker(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        abort(400)
    c = db.conn()
    a = c.execute("SELECT * FROM attackers WHERE ip=?", (ip,)).fetchone()
    if a is None:
        abort(404)
    ev = [dict(r) for r in c.execute(
        "SELECT ts, session, eventid, username, password, command, url "
        "FROM events WHERE src_ip=? ORDER BY id", (ip,))]
    count = lambda eid: sum(1 for e in ev if e["eventid"] == eid)
    return jsonify(
        ip=ip, country=a["country"], score=a["score"], severity=a["severity"],
        blocked=bool(a["blocked"]), first_seen=a["first_seen"], last_seen=a["last_seen"],
        summary=dict(failed_logins=count("cowrie.login.failed"),
                     successful_logins=count("cowrie.login.success"),
                     sessions=len({e["session"] for e in ev if e["session"]}),
                     commands=count("cowrie.command.input"),
                     downloads=count("cowrie.session.file_download")),
        techniques=mitre.map_with_evidence(ev),
        alerts=[dict(r) for r in c.execute(
            "SELECT ts, rule, severity, detail FROM alerts WHERE ip=? ORDER BY id", (ip,))],
        responses=[dict(r) for r in c.execute(
            "SELECT ts, action, mode, note FROM responses WHERE ip=? ORDER BY id", (ip,))],
        timeline=ev[-200:])

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)