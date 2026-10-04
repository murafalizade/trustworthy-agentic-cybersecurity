import threading
import time

import streamlit as st

from cybersecurity_agent.agents.cti_agents.agent import CTIAgent
from cybersecurity_agent.agents.cti_agents.main import DEFAULT_ATTACK_CASES, run_attack_cases
from cybersecurity_agent.agents.cti_agents.scheduler import run_periodic
from cybersecurity_agent.agents.cti_agents.tools import RSS_SOURCES
from cybersecurity_agent.agents.id_agents.agent import IDAgent

st.set_page_config(page_title="CTI -> ID Agent Playground", layout="wide")

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
defaults = {
    "events": [],
    "model_name": "openai/gpt-oss-20b",
    "cti_agent": None,
    "id_agent": None,
    "worker_thread": None,
    "stop_event": None,
    "worker_mode": None,  # None | "fetching" | "attack_suite"
}
for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


def make_on_event():
    events = st.session_state.events

    def _on_event(evt: dict):
        evt = {"ts": time.strftime("%H:%M:%S"), **evt}
        events.append(evt)
        del events[:-300]  # bound the log so a long fetching session doesn't grow forever

    return _on_event


def build_agents(model_name: str):
    on_event = make_on_event()
    id_agent = IDAgent(model_name=model_name, on_event=on_event)
    cti_agent = CTIAgent(model_name=model_name, id_agent=id_agent, on_event=on_event)
    st.session_state.id_agent = id_agent
    st.session_state.cti_agent = cti_agent


if st.session_state.cti_agent is None:
    build_agents(st.session_state.model_name)


def is_busy() -> bool:
    thread = st.session_state.worker_thread
    return thread is not None and thread.is_alive()


def start_worker(mode: str, target):
    stop_event = threading.Event()
    st.session_state.stop_event = stop_event
    st.session_state.worker_mode = mode
    thread = threading.Thread(target=target, args=(stop_event,), daemon=True)
    st.session_state.worker_thread = thread
    thread.start()


def stop_worker():
    if st.session_state.stop_event is not None:
        st.session_state.stop_event.set()


# ---------------------------------------------------------------------------
# Sidebar: model + controls
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("Configuration")
    model_name = st.text_input("NVIDIA NIM model", value=st.session_state.model_name)
    if st.button("Apply model", disabled=is_busy()):
        st.session_state.model_name = model_name
        build_agents(model_name)
        st.success(f"Agents reloaded with model '{model_name}'.")

    st.divider()
    st.subheader("RSS fetching")
    st.caption(", ".join(RSS_SOURCES.keys()))
    interval = st.number_input("Poll interval (seconds)", min_value=10, value=300, step=10)
    col1, col2 = st.columns(2)
    with col1:
        if st.button("▶ Start", disabled=is_busy(), key="start_fetch"):
            cti_agent = st.session_state.cti_agent

            def _fetch_worker(stop_event, cti_agent=cti_agent, interval=interval):
                run_periodic(cti_agent, interval_seconds=int(interval), stop_event=stop_event)

            start_worker("fetching", _fetch_worker)
    with col2:
        if st.button("Stop", disabled=st.session_state.worker_mode != "fetching", key="stop_fetch"):
            stop_worker()

    st.divider()
    st.subheader("Attack suite")
    st.caption(f"Replays {DEFAULT_ATTACK_CASES.name}")
    col3, col4 = st.columns(2)
    with col3:
        if st.button("Run", disabled=is_busy(), key="start_attacks"):
            cti_agent = st.session_state.cti_agent

            def _attack_worker(stop_event, cti_agent=cti_agent):
                run_attack_cases(cti_agent, DEFAULT_ATTACK_CASES, stop_event=stop_event)

            start_worker("attack_suite", _attack_worker)
    with col4:
        if st.button("Stop", disabled=st.session_state.worker_mode != "attack_suite", key="stop_attacks"):
            stop_worker()

# ---------------------------------------------------------------------------
# Manual testing
# ---------------------------------------------------------------------------
st.title("CTI & ID Agent Playground")

with st.form("manual_test_form", clear_on_submit=False):
    manual_text = st.text_area("Feed text / payload to test manually", height=100)
    submitted = st.form_submit_button("Submit to CTI Agent")
    if submitted and manual_text.strip():
        with st.spinner("Processing..."):
            st.session_state.cti_agent.process_and_route(manual_text.strip())

st.divider()

# ---------------------------------------------------------------------------
# Live agent-to-agent conversation log
# ---------------------------------------------------------------------------
AVATARS = {"CTI": "🛰️", "ID": "🛡️"}
NAMES = {"CTI": "CTI Agent", "ID": "ID Agent"}


def render_event(evt: dict):
    agent = evt["agent"]
    etype = evt["type"]

    with st.chat_message(NAMES[agent], avatar=AVATARS[agent]):
        trace_id = evt.get("trace_id")
        trace_suffix = f" · trace `{trace_id[:8]}`" if trace_id else ""
        st.caption(f"{evt['ts']} · {NAMES[agent]} · {etype}{trace_suffix}")

        if etype == "received" and agent == "CTI":
            st.write("Received feed text:")
            st.code(evt["text"][:500], language=None)

        elif etype == "analysis":
            alert = evt["alert"]
            st.write(f"🔍 **Analysis** — threat: `{alert['is_cybersecurity_threat']}`, severity: `{alert['severity']}`")
            if alert.get("cve_or_id"):
                st.write(f"CVE/ID: `{alert['cve_or_id']}`")
            if alert.get("extracted_iocs"):
                st.write("IoCs: " + ", ".join(f"`{i}`" for i in alert["extracted_iocs"]))
            st.write(alert["summary"])

        elif etype == "handoff":
            st.write("Threat detected — handing off to **ID Agent**.")

        elif etype == "skipped":
            st.write("Threat detected, but no ID Agent is wired in.")

        elif etype == "benign":
            st.write("Not a threat. No action taken.")

        elif etype == "error":
            st.error(f"{evt['error']}")

        elif etype == "received" and agent == "ID":
            alert = evt["alert"]
            st.write(f"Received alert from CTI Agent (severity: `{alert['severity']}`)")

        elif etype == "decision":
            d = evt["decision"]
            st.write(f"**Decision** — should_act: `{d['should_act']}`, action: `{d['action']}`, target: `{d['target']}`")
            st.caption(d["reasoning"])

        elif etype == "action_result":
            st.write(f"**Executed** `{evt['action']}` → `{evt['target']}`")
            st.json(evt["result"])


@st.fragment(run_every=2)
def event_log():
    thread = st.session_state.worker_thread
    if thread is not None and not thread.is_alive():
        st.session_state.worker_thread = None
        st.session_state.worker_mode = None

    mode = st.session_state.worker_mode
    if mode == "fetching":
        st.info(f"Polling RSS sources every {int(interval)}s...")
    elif mode == "attack_suite":
        st.info("Running attack suite...")

    if st.button("Clear log"):
        st.session_state.events.clear()

    for evt in reversed(st.session_state.events[-100:]):
        render_event(evt)


event_log()
