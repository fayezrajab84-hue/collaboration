from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    scan_workspace_dir: str = "/tmp/scan_workspace"
    zap_base_url: str = "http://zap:8080"
    zap_api_key: str = "changeme"
    max_clone_depth: int = 1
    scan_timeout_seconds: int = 600

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
