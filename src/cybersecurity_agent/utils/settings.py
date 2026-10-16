from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE_PATH = BASE_DIR / "../../../.env"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(validate_default=True, env_file=ENV_FILE_PATH)

    NVIDIA_API_KEY: SecretStr = "API_KEY"
    ENV: str = 'development'
    ELASTICSEARCH_URL: Optional[str] = None
    ELASTICSEARCH_API_KEY: Optional[SecretStr] = None
    ELASTICSEARCH_USERNAME: Optional[str] = None
    ELASTICSEARCH_PASSWORD: Optional[SecretStr] = None
    ELASTICSEARCH_INDEX: str = 'agent-traces'

    # Free-text description of the vendors/products/stack we actually run,
    # used by the CTI intel ingest cycle to judge whether a KEV entry is
    # relevant to us before saving it. Empty/unset fails open (treat
    # everything as relevant) rather than silently dropping intel.
    MONITORED_STACK: Optional[str] = None

    def is_trace_enable(self):
        return self.ENV == 'production'

@lru_cache()
def get_settings():
    return Settings()