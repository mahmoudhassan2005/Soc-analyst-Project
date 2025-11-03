import os
import requests

ABUSE_API = "https://api.abuseipdb.com/api/v2/check"

_CACHE = {}


def enrich_ip_with_abuseipdb(ip: str) -> dict:
    if not ip:
        return {"status": "no_ip"}
    if ip in _CACHE:
        return _CACHE[ip]

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        res = {"status": "no_key"}
        _CACHE[ip] = res
        return res
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 365}
        resp = requests.get(ABUSE_API, headers=headers, params=params, timeout=8)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            res = {
                "status": "ok",
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "totalReports": data.get("totalReports"),
                "isWhitelisted": data.get("isWhitelisted"),
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
