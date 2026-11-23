from datetime import timedelta

import pandas as pd
import streamlit as st

from cybersecurity_agent.agents.id_agent.agent import IDAgent
from cybersecurity_agent.agents.id_agent.es_source import ESLogSource, _now
from cybersecurity_agent.agents.id_agent.runner import (
    MODEL_NAME,
    WINDOW_SECONDS,
    collect_window,
)
from cybersecurity_agent.ui.id_state import get_state

st.set_page_config(page_title="ID Agent Console", layout="wide")

# Streamlit runs on the host while Elasticsearch is published by the lab
# compose stack, so the in-container default (http://elasticsearch:9200) does
# not resolve from here.
DEFAULT_ES_URL = "http://localhost:9200"

SEVERITY_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦"}
# Most severe first, so ranking is just "lowest index wins".
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

state = get_state()


def scan_once(model_name: str, es_url: str, window_seconds: int) -> None:
    """Triage one window inline, so a demo doesn't have to wait out a polling
    interval. Identical pipeline to the loop — just a single pass over the
    last `window_seconds` instead of a tumbling schedule."""
    until = _now()
    since = until - timedelta(seconds=window_seconds)
    source = ESLogSource(url=es_url)
    if not source.wait_until_ready(retries=3, delay=1.0):
        st.error(f"Elasticsearch at {source.url} is not reachable")
        return

    active_ips, reports = collect_window(source, since, until)
    state.record({
        "type": "window_result", "since": since, "until": until,
        "active_ips": active_ips, "flagged": reports,
    })
    if not reports:
        state.record({"type": "window_done", "since": since, "until": until,
                      "flagged": 0, "anomalous": 0, "benign": 0})
        st.info(f"{active_ips} active IP(s) in the last {window_seconds}s, "
                f"none tripped a threshold — nothing sent to the model.")
        return
    print(reports)
    triage = IDAgent(model_name=model_name).triage_window(reports)
    by_ip = {r["source_ip"]: r for r in reports}
    anomalous = 0
    for v in triage.verdicts:
        anomalous += bool(v.is_anomaly)
        state.record({"type": "verdict", "since": since, "until": until,
                      "report": by_ip.get(v.source_ip), "verdict": v})
    state.record({"type": "window_done", "since": since, "until": until,
                  "flagged": len(reports), "anomalous": anomalous,
                  "benign": len(triage.verdicts) - anomalous})
    st.success(f"Reviewed {len(reports)} flagged IP(s): {anomalous} anomalous.")


# ---------------------------------------------------------------------------
# Sidebar: configuration + run control
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("ID Agent")
    running = state.is_running()

    model_name = st.text_input("NVIDIA NIM model", value=MODEL_NAME, disabled=running)
    es_url = st.text_input("Elasticsearch URL", value=DEFAULT_ES_URL, disabled=running)
    window_seconds = int(st.number_input(
        "Window (seconds)", min_value=30, max_value=3600,
        value=WINDOW_SECONDS, step=30, disabled=running,
        help="Tumbling window the agent aggregates and triages at a time.",
    ))

    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        if st.button("▶ Start", disabled=running, width="stretch"):
            state.start(model_name, es_url, window_seconds)
            st.rerun()
    with col2:
        if st.button("■ Stop", disabled=not running, width="stretch"):
            state.stop()
            st.rerun()

    if st.button("⟳ Triage last window now", disabled=running, width="stretch"):
        with st.spinner("Aggregating the window and asking the model..."):
            scan_once(model_name, es_url, window_seconds)

    if st.button("Clear findings", width="stretch"):
        state.clear()
        st.rerun()


# ---------------------------------------------------------------------------
# Main view
# ---------------------------------------------------------------------------
st.title("ID Agent console")
st.caption(
    "Elasticsearch window digest → deterministic threshold pre-filter → one batched LLM call. "
    "Every IP below reached the model; the AI verdict column is the model's own call."
)


def _verdict_table(findings: list[dict]) -> pd.DataFrame:
    return pd.DataFrame([{
        "Time": f["ts"],
        "Window": f["window"],
        "Source IP": f["source_ip"],
        "AI verdict": "🚨 suspicious" if f["ai_flagged"] else "✅ not suspicious",
        "Severity": f"{SEVERITY_ICON.get(f['severity'], '')} {f['severity']}" if f["ai_flagged"] else "—",
        "Tripped thresholds": ", ".join(f["prefilter_reasons"]) or "—",
        "Why": f["reason"],
    } for f in reversed(findings)])


def _render_evidence(f: dict) -> None:
    icon = "🚨" if f["ai_flagged"] else "✅"
    verdict = f"suspicious — {f['severity']}" if f["ai_flagged"] else "not suspicious"
    with st.expander(f"{icon} {f['source_ip']} · {f['window']} · {verdict}"):
        st.markdown(f"**AI reasoning** — {f['reason']}")
        if f["indicators"]:
            st.markdown("**Indicators**")
            st.write(f["indicators"])
        st.markdown("**Pre-filter reasons (deterministic thresholds)**")
        st.write(f["prefilter_reasons"] or ["—"])
        report = f["report"]
        if report:
            st.markdown("**Sample log lines sent to the model**")
            st.code("\n".join(report.get("sample_lines", [])) or "(none)", language="text")
            st.markdown("**Window digest**")
            st.json({k: v for k, v in report.items() if k != "sample_lines"}, expanded=False)


def _render_raw_event(evt: dict) -> None:
    etype = evt["type"]
    if etype == "window_result":
        st.text(f"{evt['ts']}  window_result  active_ips={evt['active_ips']} "
                f"flagged={len(evt['flagged'])}")
    elif etype == "verdict":
        v = evt["verdict"]
        st.text(f"{evt['ts']}  verdict        {v.source_ip} anomaly={v.is_anomaly} "
                f"severity={v.severity}")
    elif etype == "window_done":
        st.text(f"{evt['ts']}  window_done    flagged={evt['flagged']} "
                f"anomalous={evt['anomalous']} benign={evt['benign']}")
    elif etype == "error":
        st.text(f"{evt['ts']}  error          {evt['stage']}: {evt['error']}")
    else:
        st.text(f"{evt['ts']}  {etype}")


@st.fragment(run_every=2)
def live_view() -> None:
    snap = state.snapshot()
    status, detail = snap["status"], snap["status_detail"]

    if state.is_running():
        if status == "running":
            st.success(f"Watcher running — {detail}")
        else:
            st.info(f"Watcher starting — {detail}")
    elif status == "error":
        st.error(detail or "Watcher stopped with an error.")
    else:
        st.warning("Watcher stopped. Hit Start in the sidebar, or triage a single window.")

    findings = snap["findings"]
    flagged = [f for f in findings if f["ai_flagged"]]
    worst = min(
        (f["severity"] for f in flagged),
        key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else len(SEVERITY_ORDER),
        default=None,
    )

    st.divider()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Windows triaged", len(snap["windows"]))
    c2.metric("IPs reviewed by AI", len(findings))
    c3.metric("AI-flagged", len(flagged))
    c4.metric("Highest severity", f"{SEVERITY_ICON.get(worst, '')} {worst}" if worst else "—")

    st.subheader("Verdicts")
    if not findings:
        st.caption("Nothing triaged yet. Traffic that trips a threshold shows up here "
                   "within one window.")
    else:
        st.dataframe(_verdict_table(findings), width="stretch", hide_index=True)
        st.subheader("Evidence")
        for f in reversed(findings[-25:]):
            _render_evidence(f)

    st.divider()
    st.subheader("Window history")
    if snap["windows"]:
        st.dataframe(pd.DataFrame(list(reversed(snap["windows"]))),
                     width="stretch", hide_index=True)
    else:
        st.caption("No completed windows yet.")

    with st.expander("Raw loop events"):
        for evt in reversed(snap["events"][-60:]):
            _render_raw_event(evt)



if __name__ == "__main__":
    live_view()