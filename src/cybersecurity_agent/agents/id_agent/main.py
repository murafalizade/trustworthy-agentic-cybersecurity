"""Live log ingestion loop for the IDAgent.

Tails the target system's logs (NOT the attacker's own campaign log or tool
output — those are ground truth for grading, never agent input, see
labs/README.md) from a shared read-only volume, prints every line as it
streams in, groups repetition-sensitive logs (auth, http access) into small
per-source-IP batches so brute-force/scan patterns are visible across lines
rather than judged one weak line at a time, and prints an ALERTTTTT banner
whenever the agent's verdict is an anomaly.
"""

import re
import time
from pathlib import Path

from cybersecurity_agent.agents.id_agent.agent import IDAgent

LOG_DIR = Path("/var/log/lab")

# auth.log / nginx-access.log carry the repetition signal (failed logins,
# path scans) that only shows up across multiple lines from the same
# source, so they're batched by IP. nginx-error.log is thinner and is more
# useful analyzed line-by-line as corroborating context.
BATCHED_FILES = ("auth.log", "nginx-access.log")
LINE_BY_LINE_FILES = ("nginx-error.log",)

POLL_INTERVAL_SECONDS = 10
MAX_BATCH_LINES = 5

_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


class LogTailer:
    """Remembers its own read offset so repeated polls only return new lines."""

    def __init__(self, path: Path):
        self.path = path
        self._offset = 0

    def read_new_lines(self) -> list[str]:
        if not self.path.exists():
            return []
        with self.path.open("r", errors="replace") as f:
            f.seek(self._offset)
            lines = f.readlines()
            self._offset = f.tell()
        return [line.rstrip("\n") for line in lines if line.strip()]


def _extract_ip(line: str) -> str:
    match = _IP_PATTERN.search(line)
    return match.group(1) if match else "unknown"


def _group_by_ip(lines: list[str]) -> list[list[str]]:
    groups: dict[str, list[str]] = {}
    for line in lines:
        groups.setdefault(_extract_ip(line), []).append(line)
    return list(groups.values())


def _chunk(lines: list[str], size: int) -> list[list[str]]:
    return [lines[i:i + size] for i in range(0, len(lines), size)]


def _analyze_and_report(agent: IDAgent, label: str, lines: list[str]) -> None:
    log_text = "\n".join(lines)
    try:
        verdict = agent.analyze_log(log_text, context=f"source_file={label}")
    except Exception as exc:
        # Network hiccups / API timeouts against the LLM backend must not
        # take down a long-running watcher — log and keep tailing instead
        # of letting one slow call kill the whole process.
        print(f"[id-agent] ERROR analyzing {label} batch ({type(exc).__name__}): {exc}", flush=True)
        return

    if verdict.is_anomaly:
        print(f"\nALERTTTTT: {log_text}", flush=True)
        print(
            f"  -> severity={verdict.severity} reason={verdict.reason} "
            f"indicators={verdict.indicators}\n",
            flush=True,
        )
    else:
        print(f"[id-agent] ok ({verdict.severity}): {verdict.reason}", flush=True)


def main() -> None:
    agent = IDAgent(model_name="openai/gpt-oss-20b")
    watched = BATCHED_FILES + LINE_BY_LINE_FILES
    tailers = {name: LogTailer(LOG_DIR / name) for name in watched}

    print(f"[id-agent] watching {LOG_DIR} for: {', '.join(watched)}", flush=True)
    print(f"[id-agent] polling every {POLL_INTERVAL_SECONDS}s\n", flush=True)

    while True:
        for filename in watched:
            new_lines = tailers[filename].read_new_lines()
            if not new_lines:
                continue

            # stream every raw line to the console as it arrives, like tail -f
            for line in new_lines:
                print(f"[{filename}] {line}", flush=True)

            batches = (
                _group_by_ip(new_lines) if filename in BATCHED_FILES
                else [[line] for line in new_lines]
            )

            for batch in batches:
                for chunk in _chunk(batch, MAX_BATCH_LINES):
                    _analyze_and_report(agent, filename, chunk)

        # sleep between polls so we don't hammer the LLM API or risk
        # request timeouts from piling up too many batches at once
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
