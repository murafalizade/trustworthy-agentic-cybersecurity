"""CLI entry point for the Elasticsearch-backed triage loop (IDAgent).

Every window (default 3 min) it:
  1. asks Elasticsearch for a compact per-source-IP summary across access /
     error / application / network logs for the window (es_source.aggregate_window),
  2. applies dumb, over-sensitive thresholds to decide which IPs are worth the
     LLM's time (es_source.flag_summary),
  3. for the flagged IPs only, pulls a few real sample lines + deterministic
     enrichment (es_source.fetch_samples / enrich),
  4. sends the whole flagged set to the LLM in ONE call and prints a verdict
     per IP (IDAgent.triage_window).

ES never pushes; this loop polls. Boring IPs never reach the LLM, and an
attack flood of thousands of lines collapses to one tiny summary row, so the
per-window LLM cost stays bounded regardless of traffic volume.

The loop itself lives in `runner.py` so the Streamlit UI (ui/id_app.py) runs
the exact same process; this module is just the stdout rendering of it.
"""

from cybersecurity_agent.agents.id_agent.agent import IDAgent
from cybersecurity_agent.agents.id_agent.es_source import ESLogSource
from cybersecurity_agent.agents.id_agent.runner import (
    MODEL_NAME,
    WINDOW_SECONDS,
    run_window_loop,
)


def _print_event(evt: dict) -> None:
    etype = evt["type"]

    if etype == "error":
        print(f"[id-agent] ERROR {evt['stage']} window ({evt['error']})", flush=True)

    elif etype == "window_result" and not evt["flagged"]:
        print(f"[id-agent] window {evt['since']:%H:%M:%S}-{evt['until']:%H:%M:%S}: "
              f"{evt['active_ips']} active IP(s), none suspicious", flush=True)

    elif etype == "verdict":
        v = evt["verdict"]
        if not v.is_anomaly:
            return
        print(f"\nALERTTTTT [{v.source_ip}] severity={v.severity}", flush=True)
        print(f"  -> {v.reason}", flush=True)
        if v.indicators:
            print(f"  -> indicators={v.indicators}", flush=True)

    elif etype == "window_done" and evt["flagged"]:
        if not evt["anomalous"]:
            print(f"[id-agent] window clear: {evt['flagged']} IP(s) checked, "
                  f"none anomalous", flush=True)
            return
        print(f"\n[id-agent] window done: {evt['anomalous']} anomalous, {evt['benign']} benign "
              f"of {evt['flagged']} flagged\n", flush=True)


def main() -> None:
    agent = IDAgent(model_name=MODEL_NAME)
    source = ESLogSource()

    print(f"[id-agent] connecting to Elasticsearch at {source.url} ...", flush=True)
    if not source.wait_until_ready():
        raise RuntimeError(f"Elasticsearch at {source.url} never became reachable")
    print(f"[id-agent] connected. triaging every {WINDOW_SECONDS}s "
          f"over banking-access/error/application/network\n", flush=True)

    run_window_loop(agent, source, on_event=_print_event, window_seconds=WINDOW_SECONDS)


if __name__ == "__main__":
    main()
