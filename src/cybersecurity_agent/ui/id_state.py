"""Process-wide state for the ID Agent watcher behind the Streamlit console.

The triage loop runs on a background thread, which has no Streamlit script
context and therefore cannot touch `st.session_state`. This module holds one
plain singleton that the worker thread writes to and every script rerun reads
from, guarded by a lock. It also owns starting/stopping the thread, so the
view (`id_app.py`) only renders snapshots.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Optional

from cybersecurity_agent.agents.id_agent.agent import IDAgent
from cybersecurity_agent.agents.id_agent.es_source import ESLogSource
from cybersecurity_agent.agents.id_agent.runner import run_window_loop

_MAX_EVENTS = 300
_MAX_FINDINGS = 200
_MAX_WINDOWS = 100


def _wait_for_es(
    source: ESLogSource,
    stop_event: threading.Event,
    retries: int = 10,
    delay: float = 1.0,
) -> bool:
    """Like ESLogSource.wait_until_ready, but re-checks the stop request
    between pings so Stop doesn't have to wait out a slow-starting cluster."""
    for _ in range(retries):
        if stop_event.is_set():
            return False
        try:
            if source.client.ping():
                return True
        except Exception:
            pass
        stop_event.wait(delay)
    return False


class WatcherState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.events: deque = deque(maxlen=_MAX_EVENTS)  # raw loop events, newest last
        self.findings: list[dict] = []                  # one row per IP verdict
        self.windows: list[dict] = []                   # one row per completed window
        self.thread: Optional[threading.Thread] = None
        self.stop_event: Optional[threading.Event] = None
        self.status = "idle"                            # idle | connecting | running | error
        self.status_detail = ""

    # -- written from the worker thread ---------------------------------
    def record(self, evt: dict) -> None:
        """`on_event` sink for run_window_loop. Flattens the events the UI
        tabulates (verdicts, finished windows) and keeps the raw stream for
        the event log."""
        with self.lock:
            stamped = {"ts": time.strftime("%H:%M:%S"), **evt}
            self.events.append(stamped)

            if evt["type"] == "verdict":
                v = evt["verdict"]
                report = evt["report"] or {}
                self.findings.append({
                    "ts": stamped["ts"],
                    "window": f"{evt['since']:%H:%M:%S}-{evt['until']:%H:%M:%S}",
                    "source_ip": v.source_ip,
                    "ai_flagged": v.is_anomaly,
                    "severity": v.severity,
                    "reason": v.reason,
                    "indicators": list(v.indicators),
                    "prefilter_reasons": report.get("prefilter_reasons", []),
                    "report": report,
                })
                del self.findings[:-_MAX_FINDINGS]

            elif evt["type"] == "window_done":
                self.windows.append({
                    "window": f"{evt['since']:%H:%M:%S}-{evt['until']:%H:%M:%S}",
                    "flagged": evt["flagged"],
                    "anomalous": evt["anomalous"],
                    "benign": evt["benign"],
                })
                del self.windows[:-_MAX_WINDOWS]

            elif evt["type"] == "error":
                self.status_detail = f"last error ({evt['stage']}): {evt['error']}"

    def set_status(self, status: str, detail: str = "") -> None:
        with self.lock:
            self.status = status
            self.status_detail = detail

    # -- read from the script thread ------------------------------------
    def snapshot(self) -> dict:
        with self.lock:
            return {
                "events": list(self.events),
                "findings": list(self.findings),
                "windows": list(self.windows),
                "status": self.status,
                "status_detail": self.status_detail,
            }

    def is_running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def clear(self) -> None:
        with self.lock:
            self.events.clear()
            self.findings.clear()
            self.windows.clear()

    # -- run control ----------------------------------------------------
    def start(self, model_name: str, es_url: str, window_seconds: int) -> None:
        if self.is_running():
            return
        stop_event = threading.Event()

        def _worker() -> None:
            try:
                agent = IDAgent(model_name=model_name)
                source = ESLogSource(url=es_url)
                self.set_status("connecting", f"connecting to {source.url} ...")
                if not _wait_for_es(source, stop_event):
                    if stop_event.is_set():
                        self.set_status("idle", "stopped before Elasticsearch came up")
                    else:
                        self.set_status("error", f"Elasticsearch at {source.url} is not reachable")
                    return
                self.set_status("running", f"watching {source.url} in {window_seconds}s windows")
                run_window_loop(
                    agent, source,
                    on_event=self.record,
                    window_seconds=window_seconds,
                    stop_event=stop_event,
                )
                self.set_status("idle", "stopped")
            except Exception as exc:
                # A crashed worker has to be visible in the UI, never silent —
                # for an IDS, "no alerts" and "not running" must not look alike.
                self.set_status("error", f"{type(exc).__name__}: {exc}")

        self.stop_event = stop_event
        self.thread = threading.Thread(target=_worker, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        if self.stop_event is not None:
            self.stop_event.set()
        self.set_status("idle", "stop requested")


_state: Optional[WatcherState] = None
_state_lock = threading.Lock()


def get_state() -> WatcherState:
    """The one watcher state for this process (survives Streamlit reruns)."""
    global _state
    with _state_lock:
        if _state is None:
            _state = WatcherState()
        return _state
