import threading
from typing import Optional

from cybersecurity_agent.agents.cti_agents.agent import CTIAgent


def run_periodic(
    agent: CTIAgent,
    interval_seconds: int = 3600,
    sources=None,
    limit_per_source: int = 5,
    stop_event: Optional[threading.Event] = None,
):
    stop_event = stop_event or threading.Event()
    print(f"Starting periodic RSS polling every {interval_seconds}s")
    while not stop_event.is_set():
        try:
            agent.run_feed_cycle(sources=sources, limit_per_source=limit_per_source)
        except Exception as e:
            print(f"Feed cycle failed: {e}")
        stop_event.wait(interval_seconds)
    print("Periodic RSS polling stopped.")
