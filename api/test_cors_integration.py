"""F2 (groupF.txt): a real ASGI-level preflight/origin integration test
against Starlette's actual CORSMiddleware -- not just the pure
allowed_origins() logic (test_cors_config.py already covers that).

Builds a minimal stub app with the SAME CORSMiddleware configuration
main.py applies, rather than importing main.py itself: main.py's module-
level imports pull in database.py/models.py/scoring.py (sqlalchemy,
asyncpg, weasyprint) which this environment cannot install without the
original venv's (broken) native dependencies. CORSMiddleware's behavior
is a Starlette primitive independent of which routes sit behind it, so
this still exercises the real header-level enforcement, not a
reimplementation of it.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from cors_config import allowed_origins


def make_app(public_base_url: str) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins(public_base_url=public_base_url, extra_origins=""),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @app.get("/api/agents")
    def list_agents():
        return []

    return app


def test_preflight_from_configured_origin_is_allowed():
    client = TestClient(make_app("https://bas.internal"))
    resp = client.options(
        "/api/agents",
        headers={
            "Origin": "https://bas.internal",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "https://bas.internal"


def test_preflight_from_disallowed_origin_is_rejected():
    client = TestClient(make_app("https://bas.internal"))
    resp = client.options(
        "/api/agents",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    # Starlette's CORSMiddleware answers a disallowed-origin preflight
    # with 400, and (critically) omits access-control-allow-origin
    # entirely -- the browser enforces the actual block client-side based
    # on that header's absence.
    assert "access-control-allow-origin" not in resp.headers


def test_actual_get_from_disallowed_origin_has_no_cors_header():
    # The server still answers the real GET (CORS is a browser-enforced
    # mechanism, not a server-side access-control decision) -- what
    # matters is that no access-control-allow-origin header appears, so
    # a real browser's own fetch() call rejects the cross-origin response.
    client = TestClient(make_app("https://bas.internal"))
    resp = client.get("/api/agents", headers={"Origin": "https://evil.example.com"})
    assert resp.status_code == 200
    assert "access-control-allow-origin" not in resp.headers


def test_actual_get_from_configured_origin_has_cors_header():
    client = TestClient(make_app("https://bas.internal"))
    resp = client.get("/api/agents", headers={"Origin": "https://bas.internal"})
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "https://bas.internal"


def test_no_configured_origin_rejects_every_cross_origin_request():
    # The safe default (PUBLIC_BASE_URL unset): no origin is ever
    # allowed, matching allowed_origins()'s own "empty list, not a
    # wildcard" contract.
    client = TestClient(make_app(""))
    resp = client.get("/api/agents", headers={"Origin": "https://anything.example.com"})
    assert "access-control-allow-origin" not in resp.headers
