from functools import lru_cache
from typing import Optional

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(validate_default=True, env_file='../../../.env')

    NVIDIA_API_KEY: SecretStr
    ENV: str = 'development'
    ELASTICSEARCH_URL: Optional[str] = None
    ELASTICSEARCH_API_KEY: Optional[SecretStr] = None
    ELASTICSEARCH_USERNAME: Optional[str] = None
    ELASTICSEARCH_PASSWORD: Optional[SecretStr] = None
    ELASTICSEARCH_INDEX: str = 'agent-traces'


    def is_trace_enable(self):
        return self.ENV == 'production'

@lru_cache()
def get_settings():
    return Settings()