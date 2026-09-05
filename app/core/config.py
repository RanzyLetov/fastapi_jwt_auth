from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Any

class Settings(BaseSettings):
    ALGORITHM: str = "HS256"

    ACCESS_KEY: str = "default_access_fallback_secret"
    REFRESH_KEY: str = "default_refresh_fallback_secret"

    CORS_ORIGINS: Any = ["http://localhost:3000"] 

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def split_cors_origins(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
    
settings = Settings()