import requests

def country(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country",
                         timeout=3).json()
        return r.get("country") if r.get("status") == "success" else "Unknown"
    except Exception:
        return "Unknown"
