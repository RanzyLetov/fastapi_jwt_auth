from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    ACCESS_KEY: str
    REFRESH_KEY: str

    ALGORITHM = "HS256"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding=".env")
    
settings = Settings()