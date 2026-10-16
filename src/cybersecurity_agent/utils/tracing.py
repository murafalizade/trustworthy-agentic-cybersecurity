import time
import uuid
from typing import Any, Optional

from elasticsearch import Elasticsearch

from cybersecurity_agent.utils.settings import get_settings

_client: Optional[Elasticsearch] = None
_client_init_attempted = False
_template_ensured = False
_INDEX_TEMPLATE_NAME = "agent-traces-template"

settings = get_settings()

def new_trace_id() -> str:
    """Generate a fresh trace id, one per CTI->ID pipeline run."""
    return str(uuid.uuid4())


def _get_client() -> Optional[Elasticsearch]:
    global _client, _client_init_attempted
    if _client_init_attempted:
        return _client
    _client_init_attempted = True

    if not settings.is_trace_enable:
        print("System is on development mode, tracing is disabled")
        return None

    kwargs: dict = {}
    if settings.ELASTICSEARCH_API_KEY:
        kwargs["api_key"] = settings.ELASTICSEARCH_API_KEY
    elif settings.ELASTICSEARCH_USERNAME and settings.ELASTICSEARCH_PASSWORD:
        kwargs["basic_auth"] = (settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD)

    try:
        _client = Elasticsearch(settings.ELASTICSEARCH_URL, **kwargs)
        _ensure_index_template(_client, settings.index)
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
        client.index(index=settings.ELASTICSEARCH_INDEX, document=doc)
    except Exception as e:
        print(f"[tracing] Failed to write trace to Elasticsearch (trace_id={trace_id}): {e}")
