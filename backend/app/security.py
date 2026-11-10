"""Authentication of requests coming from the Gmail add-on."""

import hmac

from fastapi import Header, HTTPException, Request, status


def require_api_key(request: Request, x_api_key: str = Header(default="")) -> None:
    """FastAPI dependency: reject requests without the correct X-API-Key header.

    hmac.compare_digest takes the same time whether the first or the last
    character is wrong, so an attacker cannot guess the key byte by byte by
    measuring response times (a "timing attack").
    """
    expected = request.app.state.settings.api_key
    if not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        # Deliberately vague: don't reveal whether the key was missing or wrong.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
