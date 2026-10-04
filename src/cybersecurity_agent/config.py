import os
from dataclasses import dataclass
from typing import Optional

import dotenv


dotenv.load_dotenv()

def get_nvidia_api_key() -> str:
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        raise RuntimeError(
            "NVIDIA_API_KEY environment variable is not set. "
            "Export it locally, or pass it at container runtime via "
            "`docker run -e NVIDIA_API_KEY=...` / --env-file (never bake it into the image)."
        )
    return api_key


@dataclass
class ElasticsearchConfig:
    url: Optional[str]
    api_key: Optional[str]
    username: Optional[str]
    password: Optional[str]
    index: str

    @property
    def enabled(self) -> bool:
        return bool(self.url)


def get_elasticsearch_config() -> ElasticsearchConfig:
    """
    Elasticsearch is optional: if ELASTICSEARCH_URL isn't set, tracing is a no-op.
    Auth is either an API key (preferred) or username/password, matching the two
    auth modes the `elasticsearch` client supports out of the box.
    """
    return ElasticsearchConfig(
        url=os.environ.get("ELASTICSEARCH_URL"),
        api_key=os.environ.get("ELASTICSEARCH_API_KEY"),
        username=os.environ.get("ELASTICSEARCH_USERNAME"),
        password=os.environ.get("ELASTICSEARCH_PASSWORD"),
        index=os.environ.get("ELASTICSEARCH_INDEX", "agent-traces"),
    )
