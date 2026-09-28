# Cybersecurity Agent

A CTI → ID agent playground: a **CTI Agent** analyzes raw threat feed text (RSS
sources or manual/attack-case payloads) using an NVIDIA NIM LLM, extracts a
structured `ThreatAlert`, and hands off any real threat to an **ID Agent**,
which decides whether to trigger an automated remediation action (block IP,
revoke user, run SQL, run bash — all toy/simulated actions).

## Features

- **CTI Agent** — pulls entries from RSS feeds (Talos, BleepingComputer) or
  accepts manual/pasted text, extracts IoCs/CVEs/severity via structured LLM
  output, and routes threats to the ID Agent.
- **ID Agent** — receives structured alerts and decides `should_act` /
  `action` / `target` based on severity and confidence.
- **Attack suite** — replay a bundled set of test cases
  (`datasets/attack_cases.json`) to exercise the pipeline without live feeds.
- **Streamlit UI** — live agent-to-agent conversation log, manual test input,
  and controls to start/stop RSS polling or the attack suite.
- **CLI** — run the pipeline headlessly in `attacks`, `manual`, `feeds-once`,
  or `feeds` (periodic) mode.

## Requirements

- Python 3.13+
- [uv](https://docs.astral.sh/uv/)
- An NVIDIA NIM API key

## Setup

```bash
uv sync
cp .env.example .env
# then edit .env and set NVIDIA_API_KEY
```

## Usage

### Streamlit UI

```bash
uv run streamlit run src/cybersecurity_agent/ui/app.py
```

### CLI

```bash
uv run python -m cybersecurity_agent.agents.cti_agents.main [mode] [options]
```

Modes:

| Mode         | Description                                       |
|--------------|----------------------------------------------------|
| `attacks`    | Replay `datasets/attack_cases.json` (default)      |
| `manual`     | Type feed text / payloads interactively             |
| `feeds-once` | Poll RSS sources a single time                      |
| `feeds`      | Poll RSS sources periodically (`--interval` seconds) |

Other options: `--model` (NVIDIA NIM model name), `--attack-file` (path to an
alternate attack cases JSON).

## Docker

```bash
docker build -t cybersecurity-agent .
docker run -p 8501:8501 --env-file .env cybersecurity-agent
```

The container serves the Streamlit UI on port `8501`.

## Configuration

| Variable          | Description               |
|-------------------|----------------------------|
| `NVIDIA_API_KEY`  | API key for NVIDIA NIM endpoints (required) |

## Project layout

```
src/cybersecurity_agent/
├── config.py                 # env/config helpers
├── datasets/attack_cases.json # sample attack payloads
├── ui/app.py                  # Streamlit playground UI
└── agents/
    ├── cti_agents/            # feed fetching, threat extraction, routing
    └── id_agents/             # remediation decision + toy action tools
```

## Disclaimer

This is a research/educational playground. The remediation "actions"
(`block_ip`, `revoke_user`, `run_sql`, `run_bash`) are simulated and do not
touch any real infrastructure.
