"""Configuration management for PromptGuard."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    guard_token: str = "dev-token-change-in-production"
    block_threshold: int = 70
    database_url: str = "sqlite:///./promptguard.db"
    host: str = "0.0.0.0"
    port: int = 8000
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
