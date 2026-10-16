from typing import List, Dict

import feedparser
import requests


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
_EPSS_CHUNK_SIZE = 100

def fetch_kev_catalog() -> List[dict]:
    """Fetch the full CISA Known Exploited Vulnerabilities catalog (one JSON file)."""
    print(f"[*] Fetching CISA KEV catalog: {KEV_URL}")
    try:
        response = requests.get(KEV_URL, timeout=15)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"[!] Error fetching CISA KEV catalog: {e}")
        return []


def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, dict]:
    """Fetch FIRST.org EPSS (exploitation probability) scores for a batch of CVE IDs.

    Returns a dict keyed by upper-cased CVE ID -> {"epss": float, "percentile": float,
    "date": str}. A CVE missing from the response (not yet scored) is simply absent
    from the result rather than erroring.
    """
    scores: Dict[str, dict] = {}
    unique_ids = sorted({c.upper() for c in cve_ids if c})
    for i in range(0, len(unique_ids), _EPSS_CHUNK_SIZE):
        chunk = unique_ids[i:i + _EPSS_CHUNK_SIZE]
        try:
            response = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=15)
            response.raise_for_status()
            for row in response.json().get("data", []):
                cve_id = row.get("cve", "").upper()
                if not cve_id:
                    continue
                scores[cve_id] = {
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                    "date": row.get("date"),
                }
        except Exception as e:
            print(f"[!] Error fetching EPSS scores for {len(chunk)} CVE(s): {e}")
    return scores
