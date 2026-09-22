from typing import Any

from pydantic import EmailStr, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ALGORITHM: str = "HS256"

    SECRET_KEY: str = "default_access_fallback_secret"

    CORS_ORIGINS: Any = ["http://localhost:3000"]

    SMTP_HOST: str = Field(default=...)
    SMTP_PORT: int = Field(default=...)
    SMTP_USER: EmailStr = Field(default=...)
    SMTP_PASSWORD: SecretStr = Field(default=...)

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def split_cors_origins(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
