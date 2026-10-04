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

### Docker Compose (app + Elasticsearch + Kibana)

`docker-compose.yml` brings up the app alongside Elasticsearch (for tracing)
and Kibana (to browse traces):

```bash
docker compose up --build
```

- App (Streamlit UI): http://localhost:8501
- Elasticsearch: http://localhost:9200
- Kibana: http://localhost:5601

The `app` service is pre-wired with `ELASTICSEARCH_URL=http://elasticsearch:9200`
(container-to-container, so tracing is on by default in this setup) and still
reads `NVIDIA_API_KEY` from your local `.env` via `env_file`. Elasticsearch
runs with `xpack.security.enabled=false` for local-dev simplicity — do not use
this compose file as-is for anything internet-facing. To create an index
pattern for traces in Kibana, use `agent-traces*` against the `@timestamp`
field.

Tear down with `docker compose down` (add `-v` to also drop the `es_data`
volume and lose indexed traces).

## Configuration

| Variable                 | Description               |
|--------------------------|----------------------------|
| `NVIDIA_API_KEY`         | API key for NVIDIA NIM endpoints (required) |
| `ELASTICSEARCH_URL`      | Elasticsearch endpoint for tracing (optional — tracing is a no-op if unset) |
| `ELASTICSEARCH_API_KEY`  | API key auth for Elasticsearch |
| `ELASTICSEARCH_USERNAME` | Basic-auth username, used if no API key is set |
| `ELASTICSEARCH_PASSWORD` | Basic-auth password |
| `ELASTICSEARCH_INDEX`    | Index to write traces to (default: `agent-traces`) |

## Tracing

Every LLM call (CTI extraction, ID decision, and any remediation action) is
logged to Elasticsearch as one document with `agent`, `model`, `prompt`,
`output`, `event`, `error`, and `latency_ms` fields. A single `trace_id` is
minted when the CTI Agent starts processing a feed item and threaded through
the ID Agent handoff, so the whole CTI → ID → action pipeline for one input
can be reconstructed with:

```
GET agent-traces/_search
{ "query": { "term": { "trace_id": "<id>" } }, "sort": [{ "@timestamp": "asc" }] }
```

Set `ELASTICSEARCH_URL` (plus `ELASTICSEARCH_API_KEY` or
`ELASTICSEARCH_USERNAME`/`ELASTICSEARCH_PASSWORD`) to enable it; without it,
`log_trace` silently no-ops so the agents still run fine locally.

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
