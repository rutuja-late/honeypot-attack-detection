import ipaddress
import requests

def country(ip):
    try:
        a = ipaddress.ip_address(ip)
        if a.is_private or a.is_loopback:
            return "Private network"   # lab VMs: no point asking the geo service
    except ValueError:
        return "Unknown"
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country",
                         timeout=3).json()
        return r.get("country") if r.get("status") == "success" else "Unknown"
    except Exception:
        return "Unknown"
