"""HTTP entry point for the Malicious Email Scorer backend."""

from fastapi import Depends, FastAPI

from app.analysis import analyze
from app.config import Settings, load_settings
from app.models import AnalysisResult, EmailAnalysisRequest
from app.security import require_api_key


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()

    # Interactive API docs are off by default: no need to advertise the API
    # surface publicly. Turn on locally with ENABLE_DOCS=true.
    docs_url = "/docs" if settings.enable_docs else None
    app = FastAPI(
        title="Malicious Email Scorer",
        docs_url=docs_url,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.settings = settings

    @app.get("/health")
    def health() -> dict[str, str]:
        """Unauthenticated liveness check (used by Render and the keep-alive ping).

        Also reports the deployed commit (set by Render), so a deploy can be
        confirmed before the add-on starts relying on it. The repository is
        public, so the commit id reveals nothing.
        """
        return {"status": "ok", "version": settings.version}

    @app.post(
        "/analyze",
        response_model=AnalysisResult,
        dependencies=[Depends(require_api_key)],
    )
    def analyze_email(email: EmailAnalysisRequest) -> AnalysisResult:
        # Note: we never log the email content - it may contain private data.
        return analyze(email)

    return app
