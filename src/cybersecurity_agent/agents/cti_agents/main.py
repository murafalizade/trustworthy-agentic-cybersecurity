import argparse
import json
import threading
from pathlib import Path
from typing import Optional

from cybersecurity_agent.agents.cti_agents.agent import CTIAgent
from cybersecurity_agent.agents.cti_agents.scheduler import run_periodic
from cybersecurity_agent.agents.id_agents.agent import IDAgent

DEFAULT_ATTACK_CASES = Path(__file__).resolve().parents[3] / "cybersecurity_agent" / "datasets" / "attack_cases.json"


def run_attack_cases(agent: CTIAgent, path: Path, stop_event: Optional[threading.Event] = None):
    with open(path, "r", encoding="utf-8") as attacks:
        cases = json.load(attacks)
        for case in cases.get("test_cases", []):
            if stop_event and stop_event.is_set():
                break
            agent.process_and_route(case.get("payload"))


def run_manual(agent: CTIAgent):
    print("[*] Manual mode: paste feed text / attack payloads to test, empty line to quit.")
    while True:
        try:
            text = input("> ").strip()
        except EOFError:
            break
        if not text:
            break
        agent.process_and_route(text)


def main():
    parser = argparse.ArgumentParser(description="CTI Agent playground runner")
    parser.add_argument(
        "mode",
        nargs="?",
        default="attacks",
        choices=["attacks", "manual", "feeds-once", "feeds"],
        help=(
            "attacks: replay datasets/attack_cases.json (default). "
            "manual: hand-type payloads interactively. "
            "feeds-once: poll RSS sources a single time. "
            "feeds: poll RSS sources periodically (see --interval)."
        ),
    )
    parser.add_argument("--interval", type=int, default=3600, help="Seconds between polls in 'feeds' mode (default: 3600)")
    parser.add_argument("--attack-file", type=Path, default=DEFAULT_ATTACK_CASES, help="Path to attack_cases.json")
    parser.add_argument("--model", default="openai/gpt-oss-20b", help="NVIDIA NIM model name")
    args = parser.parse_args()

    id_agent = IDAgent(model_name=args.model)
    agent = CTIAgent(model_name=args.model, id_agent=id_agent)

    if args.mode == "attacks":
        run_attack_cases(agent, args.attack_file)
    elif args.mode == "manual":
        run_manual(agent)
    elif args.mode == "feeds-once":
        agent.run_feed_cycle()
    elif args.mode == "feeds":
        run_periodic(agent, interval_seconds=args.interval)


if __name__ == "__main__":
    main()
