"""Runtime configuration, read from environment variables.

Secrets are never hard-coded or committed. Locally they come from the shell;
on Render they are set in the dashboard as environment variables.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_key: str
    enable_docs: bool
    version: str = "dev"


def load_settings() -> Settings:
    api_key = os.environ.get("API_KEY", "")
    # Fail closed: refuse to start without a reasonably strong key, rather
    # than silently running an unauthenticated service.
    if len(api_key) < 32:
        raise RuntimeError(
            "API_KEY environment variable must be set (at least 32 characters). "
            "Generate one with: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    return Settings(
        api_key=api_key,
        enable_docs=os.environ.get("ENABLE_DOCS", "false").lower() == "true",
        version=os.environ.get("RENDER_GIT_COMMIT", "dev")[:7],
    )
