# Detection tests

Automated: `python3 -m unittest discover -s tests -v` (synthetic Cowrie events, temp DB, iptables is mocked to fail if called).

Live: on the attacker VM run `tests/attack_from_kali.sh <honeypot-ip>`.

| Gap found earlier | Command | Alert rule | MITRE |
|---|---|---|---|
| nmap not detected | `nmap -sV ...` | Network scanning | T1046 |
| scp not detected | `scp a b@h:/tmp` | File transfer (scp/sftp) | T1105 |
| xmrig not scored | `./xmrig -o stratum+tcp://...` | Cryptominer | T1496 |
| history -c | `history -c` | Log / history tampering | T1070.003 |
| python download | `python3 -c 'urllib...'` | Scripted download (python) | T1105 |
| echo piped to sh | `echo ... \| sh` | Pipe to shell | T1027 |
| /etc/shadow | `cat /etc/shadow` | Password file (/etc/shadow) | T1003.008 |
