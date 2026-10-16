import asyncio
import atexit
import threading
import time

import pandas as pd
import streamlit as st

from cybersecurity_agent.agents.cti_agents.agent import CTIAgent

st.set_page_config(page_title="CTI Agent Playground", layout="wide")

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
    "worker_mode": None,  # None | "fetching" | "reviewing"
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
    cti_agent = CTIAgent(model_name=model_name, on_event=on_event)
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


# Ctrl+C on the terminal running `streamlit run` doesn't reach the fetch
# worker thread at all — it only stops Streamlit's own server loop, leaving
# the thread (and the batch of LLM calls it's waiting on) running in the
# background indefinitely. Firing the same stop signal on interpreter exit
# gives that thread a chance to notice and unwind instead of being orphaned.
atexit.register(stop_worker)


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
    st.subheader("CTI intel ingest (KEV + AI relevance triage)")
    interval = st.number_input("Poll interval (seconds)", min_value=10, value=300, step=10)
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Start", disabled=is_busy(), key="start_fetch"):
            cti_agent = st.session_state.cti_agent

            def _fetch_worker(stop_event, cti_agent=cti_agent, interval=interval):
                # start_worker hands us a threading.Event (shared with the
                # Stop button, which lives on the main thread), but
                # run_intel_sync_periodic waits on an asyncio.Event local to
                # this thread's own loop — bridge the two by polling.
                async def _run():
                    async_stop = asyncio.Event()

                    async def _bridge_stop():
                        while not stop_event.is_set():
                            await asyncio.sleep(0.5)
                        async_stop.set()

                    bridge = asyncio.create_task(_bridge_stop())
                    try:
                        await cti_agent.run_intel_sync_periodic(
                            interval_seconds=int(interval), stop_event=async_stop
                        )
                    finally:
                        bridge.cancel()

                asyncio.run(_run())
            start_worker("fetching", _fetch_worker)
    with col2:
        if st.button("Stop", disabled=st.session_state.worker_mode != "fetching", key="stop_fetch"):
            stop_worker()

st.title("CTI & ID Agent Playground")
st.divider()


st.subheader("CVE Intel Store")


@st.fragment(run_every=5)
def intel_table():
    records = st.session_state.cti_agent.intel_store.all_cve_records()
    if not records:
        st.caption("No CVE intel recorded yet.")
        return
    df = pd.DataFrame([{
        "CVE/Source": r.source,
        "Description": r.description,
        "Vulnerability": r.vulnerability,
        "Reason": r.reason,
        "Actions": r.actions,
    } for r in records])
    st.dataframe(df, width='stretch', hide_index=True)


intel_table()

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

        if etype == "error":
            st.error(f"{evt['error']}")

        elif etype == "intel_received":
            st.write(f"Reviewing CVE record `{evt['record']['source']}` from the intel store.")

        elif etype == "tool_call":
            st.write(f"🔧 **{evt['tool']}**`({evt.get('args', {})})` → `{evt['result']}`")

        elif etype == "approval_requested":
            st.warning(f"⚠️ Waiting on human approval for: `{evt['command']}`")

        elif etype == "approval_resolved":
            verdict = "✅ approved" if evt["approved"] else "❌ denied"
            st.write(f"Command {verdict}: `{evt['command']}`")

        elif etype == "intel_decision":
            d = evt["decision"]
            tag = "defended" if d["defended"] else "left as relevant (not resolved)"
            st.write(f"**Intel decision** — `{evt['cve_id']}` → {tag}")
            st.caption(d["reasoning"])


@st.fragment(run_every=2)
def event_log():
    thread = st.session_state.worker_thread
    if thread is not None and not thread.is_alive():
        st.session_state.worker_thread = None
        st.session_state.worker_mode = None

    mode = st.session_state.worker_mode
    if mode == "fetching":
        st.info("Running CTI intel ingest cycle...")

    if st.button("Clear log"):
        st.session_state.events.clear()

    for evt in reversed(st.session_state.events[-100:]):
        render_event(evt)


event_log()
