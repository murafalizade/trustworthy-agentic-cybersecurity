"""Shared window-triage loop for the IDAgent.

This is the one implementation of the polling process described in
`es_main.py`: aggregate a window in Elasticsearch -> dumb threshold
pre-filter -> enrich the flagged IPs -> one batched LLM call -> verdicts.

`es_main.py` (CLI) and `ui/id_app.py` (Streamlit) both drive it; neither owns
the logic, so the behaviour is identical whichever one you start. The only
thing a caller supplies is an `on_event` sink for observability and an
optional `stop_event` so a long-running watcher can be shut down between
windows.

Events emitted (dicts, always with a "type" key):
  window_start   {since, until}
  window_result  {since, until, active_ips, flagged: [report, ...]}
  verdict        {since, until, report, verdict}        -- one per flagged IP
  window_done    {since, until, flagged, anomalous, benign}
  error          {stage, error}                          -- loop survives it
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from typing import Callable, Optional

from cybersecurity_agent.agents.id_agent.agent import IDAgent
from cybersecurity_agent.agents.id_agent.es_source import ESLogSource, _now

# 3-minute tumbling window (long enough that slow/low-volume recon still adds
# up past the thresholds, short enough to detect within a few minutes).
WINDOW_SECONDS = 180
# A plain instruct model (returns answer text in `content`). The nemotron
# "reasoning" models spend their budget on hidden reasoning_content and return
# an empty content string, which the window triage cannot parse.
MODEL_NAME = "mistralai/mistral-large-4-1t-a52b"

EventSink = Callable[[dict], None]


def collect_window(source: ESLogSource, since: datetime, until: datetime) -> tuple[int, list[dict]]:
    """Steps 1-3 for one window: aggregate, pre-filter, enrich.

    Returns (number of active IPs seen, per-IP reports for the flagged ones).
    No LLM involved — this is the deterministic half, so the UI can show what
    tripped the smoke detector before (and independently of) the AI verdict.
    """
    summaries = source.aggregate_window(since, until)
    reports: list[dict] = []
    for ip, s in summaries.items():
        reasons = source.flag_summary(s)
        if not reasons:
            continue
        samples = source.fetch_samples(ip, since, until)
        enrich = source.enrich(ip, samples)
        reports.append({
            **s,
            "prefilter_reasons": reasons,
            "sample_lines": samples,
            "ip_classification": enrich["ip_classification"],
            "signature_matches": enrich["signature_matches"],
        })
    return len(summaries), reports


def run_window_loop(
    agent: IDAgent,
    source: ESLogSource,
    on_event: EventSink,
    window_seconds: int = WINDOW_SECONDS,
    stop_event: Optional[threading.Event] = None,
) -> None:
    """Poll Elasticsearch forever (or until `stop_event`), triaging a window
    at a time and reporting everything through `on_event`."""
    stop_event = stop_event or threading.Event()

    # First tick covers the window just before startup.
    since = _now() - timedelta(seconds=window_seconds)

    while not stop_event.is_set():
        until = _now()
        on_event({"type": "window_start", "since": since, "until": until})

        try:
            active_ips, reports = collect_window(source, since, until)
        except Exception as exc:
            on_event({
                "type": "error", "stage": "aggregate",
                "error": f"{type(exc).__name__}: {exc}",
            })
            since = until
            _wait(stop_event, window_seconds)
            continue

        on_event({
            "type": "window_result", "since": since, "until": until,
            "active_ips": active_ips, "flagged": reports,
        })

        if reports:
            try:
                triage = agent.triage_window(reports)
            except Exception as exc:
                # One bad LLM call must not kill a long-running watcher.
                on_event({
                    "type": "error", "stage": "triage",
                    "error": f"{type(exc).__name__}: {exc}",
                })
            else:
                by_ip = {r["source_ip"]: r for r in reports}
                anomalous = 0
                for v in triage.verdicts:
                    anomalous += bool(v.is_anomaly)
                    on_event({
                        "type": "verdict", "since": since, "until": until,
                        "report": by_ip.get(v.source_ip), "verdict": v,
                    })
                on_event({
                    "type": "window_done", "since": since, "until": until,
                    "flagged": len(reports), "anomalous": anomalous,
                    "benign": len(triage.verdicts) - anomalous,
                })
        else:
            on_event({
                "type": "window_done", "since": since, "until": until,
                "flagged": 0, "anomalous": 0, "benign": 0,
            })

        since = until
        _wait(stop_event, window_seconds)


def _wait(stop_event: threading.Event, seconds: int) -> None:
    """Sleep between windows, but wake up immediately on a stop request so the
    UI's Stop button doesn't have to wait out a whole window."""
    stop_event.wait(timeout=seconds)
