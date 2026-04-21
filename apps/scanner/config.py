from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    scan_workspace_dir: str = "/tmp/scan_workspace"
    zap_base_url: str = "http://zap:8080"
    zap_api_key: str = "changeme"
    interactsh_url: str = Field(default="", alias="INTERACTSH_URL")
    # Playwright crawler sidecar (apps/crawler). When set, the DAST scanner
    # calls it to enumerate URLs instead of running Chromium in-process.
    # Leave empty to fall back to the legacy in-process crawl.
    crawler_url: str = Field(default="", alias="CRAWLER_URL")
    crawler_timeout_secs: int = 900
    max_clone_depth: int = 1
    scan_timeout_seconds: int = 1440  # 24 min — leave headroom under API's 25-min axios timeout

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
