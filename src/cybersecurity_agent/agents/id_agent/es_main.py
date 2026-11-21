"""Elasticsearch-backed triage loop for the IDAgent.

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
"""

import time
from datetime import timedelta

from cybersecurity_agent.agents.id_agent.agent import IDAgent
from cybersecurity_agent.agents.id_agent.es_source import ESLogSource, _now

# 3-minute tumbling window (long enough that slow/low-volume recon still adds
# up past the thresholds, short enough to detect within a few minutes).
WINDOW_SECONDS = 180
# A plain instruct model (returns answer text in `content`). The nemotron
# "reasoning" models spend their budget on hidden reasoning_content and return
# an empty content string, which the window triage cannot parse.
MODEL_NAME = "nvidia/nemotron-3.5-lightning-30b-a3b"


def _print_window(verdicts, flagged_count: int) -> None:
    anomalies = [v for v in verdicts if v.is_anomaly]
    if not anomalies:
        print(f"[id-agent] window clear: {flagged_count} IP(s) checked, none anomalous", flush=True)
        return
    for v in anomalies:
        print(f"\nALERTTTTT [{v.source_ip}] severity={v.severity}", flush=True)
        print(f"  -> {v.reason}", flush=True)
        if v.indicators:
            print(f"  -> indicators={v.indicators}", flush=True)
    benign = len(verdicts) - len(anomalies)
    print(f"\n[id-agent] window done: {len(anomalies)} anomalous, {benign} benign "
          f"of {flagged_count} flagged\n", flush=True)


def main() -> None:
    agent = IDAgent(model_name=MODEL_NAME)
    source = ESLogSource()

    print(f"[id-agent] connecting to Elasticsearch at {source.url} ...", flush=True)
    if not source.wait_until_ready():
        raise RuntimeError(f"Elasticsearch at {source.url} never became reachable")
    print(f"[id-agent] connected. triaging every {WINDOW_SECONDS}s "
          f"over banking-access/error/application/network\n", flush=True)

    # First tick covers the window just before startup.
    since = _now() - timedelta(seconds=WINDOW_SECONDS)

    while True:
        now = _now()
        try:
            summaries = source.aggregate_window(since, now)
        except Exception as exc:
            print(f"[id-agent] ERROR aggregating window ({type(exc).__name__}): {exc}", flush=True)
            time.sleep(WINDOW_SECONDS)
            since = now
            continue

        # Step 2+3: keep only IPs that trip a threshold, enrich them with real
        # sample lines + deterministic findings.
        reports = []
        for ip, s in summaries.items():
            reasons = source.flag_summary(s)
            if not reasons:
                continue
            samples = source.fetch_samples(ip, since, now)
            enrich = source.enrich(ip, samples)
            reports.append({
                **s,
                "prefilter_reasons": reasons,
                "sample_lines": samples,
                "ip_classification": enrich["ip_classification"],
                "signature_matches": enrich["signature_matches"],
            })

        if not reports:
            print(f"[id-agent] window {since:%H:%M:%S}-{now:%H:%M:%S}: "
                  f"{len(summaries)} active IP(s), none suspicious", flush=True)
        else:
            try:
                triage = agent.triage_window(reports)
                _print_window(triage.verdicts, len(reports))
            except Exception as exc:
                # One bad LLM call must not kill a long-running watcher.
                print(f"[id-agent] ERROR triaging window ({type(exc).__name__}): {exc}", flush=True)

        since = now
        time.sleep(WINDOW_SECONDS)


if __name__ == "__main__":
    main()
