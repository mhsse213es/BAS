"""
F2 (groupF.txt): CORS origin configuration, isolated from main.py so this
logic is unit-testable without pulling in the full app (database engine,
scoring, etc.).

Mirrors the Go orchestrator's own origin concept: both read
PUBLIC_BASE_URL, so this API's CORS and the orchestrator's browser
WebSocket origin check (orchestrator/internal/ws/hub.go's
SetAllowedOrigin) are derived from the same configured value rather than
drifting apart as two independently configured security settings.
"""
from urllib.parse import urlparse
import os


def parse_origin(url: str) -> str | None:
    """Extract scheme://host[:port] from a URL. Returns None for an
    empty or unparseable value (no scheme or no host) -- CORS allow_origins
    must never contain an empty string, which some browsers would wrongly
    treat as "no restriction"."""
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def allowed_origins(public_base_url: str | None = None, extra_origins: str | None = None) -> list[str]:
    """Builds the CORS allow_origins list. public_base_url/extra_origins
    default to the real PUBLIC_BASE_URL/CORS_ALLOWED_ORIGINS env vars when
    not passed explicitly (tests pass them explicitly to avoid mutating
    process-wide env state). extra_origins is a comma-separated list for
    deployments that need an additional origin beyond the primary public
    base URL (e.g. a separate admin console host).

    An unset/unparseable public_base_url with no extra_origins yields an
    empty list -- the safe default (no cross-origin browser access at
    all) rather than falling back to a wildcard, since this API currently
    has no deployment that calls it from a browser at all (see the F2
    finding's own trace)."""
    if public_base_url is None:
        public_base_url = os.getenv("PUBLIC_BASE_URL", "")
    if extra_origins is None:
        extra_origins = os.getenv("CORS_ALLOWED_ORIGINS", "")

    origins: list[str] = []
    primary = parse_origin(public_base_url)
    if primary:
        origins.append(primary)
    for o in extra_origins.split(","):
        o = o.strip()
        if o and o not in origins:
            origins.append(o)
    return origins
