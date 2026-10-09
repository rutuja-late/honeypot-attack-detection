import sys
sys.path.insert(0, "/home/ubuntu/honeypot")
from flask import Flask, jsonify, render_template
import db

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

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
