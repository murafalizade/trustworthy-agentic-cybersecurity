"""Elasticsearch-backed log source for the IDAgent.

Instead of tailing raw log files, this pulls from the banking-* indices that
Filebeat ships (access/error/application/network) and does the heavy
reduction *in Elasticsearch* before the LLM ever sees anything:

  1. aggregate_window()  -- one cheap per-source-IP summary across all four
     log types for the window (counts, distinct paths, status histogram,
     user-agents, nginx errors, Suricata alert signatures). This stays tiny
     no matter how many raw lines there were.
  2. flag_summary()      -- deterministic, deliberately over-sensitive
     thresholds decide which IPs are even worth the LLM's attention. It is a
     smoke detector, not a verdict: it errs toward flagging so a real attack
     is never hidden from the agent; the LLM makes the actual call.
  3. fetch_samples()     -- only for flagged IPs, pull a handful of real log
     lines (projected to the useful fields) so the LLM can confirm a payload.

ES never pushes; the agent polls on its own cadence (see es_main.py).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

from elasticsearch import Elasticsearch

from cybersecurity_agent.agents.id_agent.utils.indicators import classify_ip, scan_patterns
from cybersecurity_agent.utils.settings import get_settings

settings = get_settings()

# Lab default -- the agent reaches Elasticsearch over the compose `default`
# network (see labs/docker-compose.yml). Overridable via ELASTICSEARCH_URL.
_DEFAULT_ES_URL = "http://elasticsearch:9200"

ACCESS_INDEX = "banking-access-*"
ERROR_INDEX = "banking-error-*"
APP_INDEX = "banking-application-*"
NET_INDEX = "banking-network-*"

# --- "smoke detector" thresholds (dumb, over-sensitive on purpose) ---------
REQ_THRESHOLD = 50          # requests from one IP in the window = too fast for a human
DISTINCT_PATH_THRESHOLD = 20  # many distinct URLs = looks like scanning
CLIENT_ERROR_THRESHOLD = 10   # 401/403/404 burst = probing / brute force
ERROR_LINE_THRESHOLD = 10     # nginx error lines = probing / malformed requests
# Known attacker tooling in the user-agent.
_TOOL_UA = ("sqlmap", "nikto", "nmap", "masscan", "hydra", "dirb", "gobuster", "wpscan", "nuclei")

_MAX_IPS = 200              # terms-agg bucket cap per index
_SAMPLES_PER_INDEX = 6      # raw lines pulled per index for a flagged IP


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ESLogSource:
    def __init__(self, url: Optional[str] = None):
        self.url = url or settings.ELASTICSEARCH_URL or _DEFAULT_ES_URL
        kwargs: dict = {"request_timeout": 20}
        if settings.ELASTICSEARCH_API_KEY:
            kwargs["api_key"] = settings.ELASTICSEARCH_API_KEY.get_secret_value()
        elif settings.ELASTICSEARCH_USERNAME and settings.ELASTICSEARCH_PASSWORD:
            kwargs["basic_auth"] = (
                settings.ELASTICSEARCH_USERNAME,
                settings.ELASTICSEARCH_PASSWORD.get_secret_value(),
            )
        self.client = Elasticsearch(self.url, **kwargs)

    # -- startup ------------------------------------------------------------
    def wait_until_ready(self, retries: int = 30, delay: float = 2.0) -> bool:
        """Block until ES answers a ping, so a slow-starting cluster doesn't
        crash the agent on boot. Returns False if it never came up."""
        for _ in range(retries):
            try:
                if self.client.ping():
                    return True
            except Exception:
                pass
            time.sleep(delay)
        return False

    # -- internal helpers ---------------------------------------------------
    def _range(self, since: datetime, now: datetime) -> dict:
        return {"range": {"@timestamp": {"gte": _iso(since), "lt": _iso(now)}}}

    def _terms_agg(self, index, ip_field, since, now, sub_aggs=None, extra_filter=None):
        """Run a per-IP terms aggregation over `index` for the window and
        return {ip: bucket}. Any index/mapping problem is swallowed (an
        index may simply not exist yet) so one bad source never blanks the
        whole window."""
        filters = [self._range(since, now)]
        if extra_filter:
            filters.append(extra_filter)
        body_aggs = {"by_ip": {"terms": {"field": ip_field, "size": _MAX_IPS}}}
        if sub_aggs:
            body_aggs["by_ip"]["aggs"] = sub_aggs
        try:
            resp = self.client.search(
                index=index,
                size=0,
                query={"bool": {"filter": filters}},
                aggregations=body_aggs,
            )
        except Exception as exc:
            print(f"[id-agent] ES agg failed on {index} ({type(exc).__name__}): {exc}", flush=True)
            return {}
        buckets = resp.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
        out = {}
        for b in buckets:
            ip = str(b.get("key", "")).strip()
            if ip and ip not in ("127.0.0.1", "::1"):  # drop the nginx->app loopback hop
                out[ip] = b
        return out

    # -- step 1: window summary --------------------------------------------
    def aggregate_window(self, since: datetime, now: datetime) -> dict:
        """One compact per-source-IP summary across all four log types."""
        summaries: dict[str, dict] = {}

        def row(ip):
            return summaries.setdefault(ip, {
                "source_ip": ip,
                "access_requests": 0, "distinct_paths": 0,
                "status_counts": {}, "client_errors": 0,
                "methods": [], "user_agents": [], "services": set(),
                "app_requests": 0, "app_top_paths": [], "app_errors": 0,
                "error_lines": 0,
                "net_alerts": 0, "net_signatures": [], "net_max_severity": None,
            })

        # access.log -- real client is remote_addr (nginx logs the downstream peer)
        access = self._terms_agg(
            ACCESS_INDEX, "remote_addr", since, now,
            sub_aggs={
                "distinct_paths": {"cardinality": {"field": "request_uri"}},
                "statuses": {"terms": {"field": "status", "size": 12}},
                "methods": {"terms": {"field": "request_method", "size": 6}},
                "services": {"terms": {"field": "service", "size": 6}},
                "uas": {"terms": {"field": "http_user_agent.keyword", "size": 3}},
            },
        )
        for ip, b in access.items():
            r = row(ip)
            r["access_requests"] = b["doc_count"]
            r["distinct_paths"] = b.get("distinct_paths", {}).get("value", 0)
            for s in b.get("statuses", {}).get("buckets", []):
                code = str(s["key"])
                r["status_counts"][code] = s["doc_count"]
                if code[:1] in ("4",):
                    r["client_errors"] += s["doc_count"]
            r["methods"] = [m["key"] for m in b.get("methods", {}).get("buckets", [])]
            r["user_agents"] = [u["key"] for u in b.get("uas", {}).get("buckets", [])]
            r["services"].update(s["key"] for s in b.get("services", {}).get("buckets", []))

        # application.log -- real client is x_forwarded_for (remote_addr is the nginx hop)
        app = self._terms_agg(
            APP_INDEX, "x_forwarded_for", since, now,
            sub_aggs={
                "top_paths": {"terms": {"field": "path", "size": 5}},
                "services": {"terms": {"field": "service", "size": 6}},
                "errors": {"range": {"field": "status", "ranges": [{"from": 500}]}},
            },
        )
        for ip, b in app.items():
            r = row(ip)
            r["app_requests"] = b["doc_count"]
            r["app_top_paths"] = [p["key"] for p in b.get("top_paths", {}).get("buckets", [])]
            r["services"].update(s["key"] for s in b.get("services", {}).get("buckets", []))
            for rng in b.get("errors", {}).get("buckets", []):
                r["app_errors"] += rng.get("doc_count", 0)

        # error.log -- client IP parsed by the error pipeline
        errors = self._terms_agg(ERROR_INDEX, "nginx.error.client", since, now)
        for ip, b in errors.items():
            row(ip)["error_lines"] = b["doc_count"]

        # network -- Suricata alerts only (flow records are noise)
        net = self._terms_agg(
            NET_INDEX, "src_ip", since, now,
            sub_aggs={
                "sigs": {"terms": {"field": "alert.signature.keyword", "size": 5}},
                "max_sev": {"max": {"field": "alert.severity"}},
            },
            extra_filter={"term": {"event_type": "alert"}},
        )
        for ip, b in net.items():
            r = row(ip)
            r["net_alerts"] = b["doc_count"]
            r["net_signatures"] = [s["key"] for s in b.get("sigs", {}).get("buckets", [])]
            sev = b.get("max_sev", {}).get("value")
            r["net_max_severity"] = int(sev) if sev is not None else None

        for r in summaries.values():
            r["services"] = sorted(r["services"])
        return summaries

    # -- step 2: dumb pre-filter -------------------------------------------
    def flag_summary(self, s: dict) -> list[str]:
        """Return the list of threshold reasons this IP tripped (empty = boring)."""
        reasons = []
        total_req = s["access_requests"] + s["app_requests"]
        if total_req >= REQ_THRESHOLD:
            reasons.append(f"high request volume ({total_req})")
        if s["distinct_paths"] >= DISTINCT_PATH_THRESHOLD:
            reasons.append(f"many distinct paths ({s['distinct_paths']})")
        if s["client_errors"] >= CLIENT_ERROR_THRESHOLD:
            reasons.append(f"4xx burst ({s['client_errors']})")
        if s["error_lines"] >= ERROR_LINE_THRESHOLD:
            reasons.append(f"nginx error burst ({s['error_lines']})")
        if s["net_alerts"] >= 1:
            reasons.append(f"suricata alert(s) ({s['net_alerts']})")
        if s["app_errors"] >= 1:
            reasons.append(f"app 5xx ({s['app_errors']})")
        for ua in s["user_agents"]:
            if any(t in ua.lower() for t in _TOOL_UA):
                reasons.append(f"attacker tool UA ({ua})")
                break
        return reasons

    # -- step 3: raw samples for flagged IPs -------------------------------
    def _samples_from(self, index, ip_field, ip, since, now, project):
        try:
            resp = self.client.search(
                index=index,
                size=_SAMPLES_PER_INDEX,
                query={"bool": {"filter": [self._range(since, now), {"term": {ip_field: ip}}]}},
                sort=[{"@timestamp": {"order": "desc"}}],
            )
        except Exception:
            return []
        return [project(h.get("_source", {})) for h in resp.get("hits", {}).get("hits", [])]

    def fetch_samples(self, ip: str, since: datetime, now: datetime) -> list[str]:
        lines: list[str] = []
        lines += self._samples_from(
            ACCESS_INDEX, "remote_addr", ip, since, now,
            lambda d: f"[access/{d.get('service','?')}] {d.get('request_method','')} "
                      f"{d.get('request_uri','')} -> {d.get('status','')} ua={d.get('http_user_agent','')}",
        )
        lines += self._samples_from(
            APP_INDEX, "x_forwarded_for", ip, since, now,
            lambda d: f"[app/{d.get('service','?')}] rid={d.get('request_id','')} "
                      f"{d.get('method','')} {d.get('path','')} -> {d.get('status','')} "
                      f"query={d.get('query',{})} body={d.get('body',{})}",
        )
        lines += self._samples_from(
            ERROR_INDEX, "nginx.error.client", ip, since, now,
            lambda d: f"[error/{d.get('service','?')}] {d.get('message','')[:300]}",
        )
        lines += self._samples_from(
            NET_INDEX, "src_ip", ip, since, now,
            lambda d: f"[net] {d.get('proto','')} {d.get('src_ip','')}:{d.get('src_port','')}"
                      f"->{d.get('dest_ip','')}:{d.get('dest_port','')} "
                      f"alert={(d.get('alert') or {}).get('signature','')}",
        )
        return lines

    # -- step 3b: deterministic enrichment (no LLM) ------------------------
    def enrich(self, ip: str, sample_lines: list[str]) -> dict:
        joined = "\n".join(sample_lines)
        return {
            "ip_classification": classify_ip(ip),
            "signature_matches": scan_patterns(joined),
        }
