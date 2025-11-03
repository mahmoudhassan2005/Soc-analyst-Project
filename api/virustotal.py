import os
import requests

VT_API = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

_CACHE = {}


def enrich_ip_with_virustotal(ip: str) -> dict:
    if not ip:
        return {"status": "no_ip"}
    if ip in _CACHE:
        return _CACHE[ip]

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        res = {"status": "no_key"}
        _CACHE[ip] = res
        return res
    try:
        headers = {"x-apikey": api_key}
        resp = requests.get(VT_API.format(ip=ip), headers=headers, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            res = {
                "status": "ok",
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "harmless": stats.get("harmless"),
            }
            _CACHE[ip] = res
            return res
        res = {"status": f"http_{resp.status_code}"}
        _CACHE[ip] = res
        return res
    except Exception as e:
        res = {"status": "error", "error": str(e)}
        _CACHE[ip] = res
        return res
