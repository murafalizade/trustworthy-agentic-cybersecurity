import time
import uuid
from typing import Any, Optional

from elasticsearch import Elasticsearch

from cybersecurity_agent.config import get_elasticsearch_config

_client: Optional[Elasticsearch] = None
_client_init_attempted = False
_template_ensured = False
_INDEX_TEMPLATE_NAME = "agent-traces-template"


def new_trace_id() -> str:
    """Generate a fresh trace id, one per CTI->ID pipeline run."""
    return str(uuid.uuid4())


def _get_client() -> Optional[Elasticsearch]:
    global _client, _client_init_attempted
    if _client_init_attempted:
        return _client
    _client_init_attempted = True

    cfg = get_elasticsearch_config()
    if not cfg.enabled:
        return None

    kwargs: dict = {}
    if cfg.api_key:
        kwargs["api_key"] = cfg.api_key
    elif cfg.username and cfg.password:
        kwargs["basic_auth"] = (cfg.username, cfg.password)

    try:
        _client = Elasticsearch(cfg.url, **kwargs)
        _ensure_index_template(_client, cfg.index)
    except Exception as e:
        print(f"[tracing] Failed to initialize Elasticsearch client: {e}")
        _client = None
    return _client


def _ensure_index_template(client: Elasticsearch, index: str) -> None:
    global _template_ensured
    if _template_ensured:
        return
    _template_ensured = True
    try:
        client.indices.put_index_template(
            name=_INDEX_TEMPLATE_NAME,
            index_patterns=[f"{index}*"],
            template={
                "mappings": {
                    "properties": {
                        "trace_id": {"type": "keyword"},
                        "agent": {"type": "keyword"},
                        "event": {"type": "keyword"},
                        "model": {"type": "keyword"},
                        "error": {"type": "text"},
                        "latency_ms": {"type": "float"},
                        "prompt": {"type": "flattened"},
                        "output": {"type": "flattened"},
                    }
                }
            },
        )
    except Exception as e:
        print(f"[tracing] Failed to ensure index template: {e}")


def log_trace(
    trace_id: str,
    agent: str,
    model: str,
    prompt: Any,
    output: Any,
    *,
    event: str,
    error: Optional[str] = None,
    latency_ms: Optional[float] = None,
    extra: Optional[dict] = None,
) -> None:
    client = _get_client()
    doc = {
        "trace_id": trace_id,
        "agent": agent,
        "event": event,
        "model": model,
        "prompt": prompt,
        "output": output,
        "error": error,
        "latency_ms": latency_ms,
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if extra:
        doc.update(extra)

    if client is None:
        return

    try:
        client.index(index=get_elasticsearch_config().index, document=doc)
    except Exception as e:
        print(f"[tracing] Failed to write trace to Elasticsearch (trace_id={trace_id}): {e}")
