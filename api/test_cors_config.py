"""F2 (groupF.txt): tests for the CORS origin-list logic, kept dependency-
free (no fastapi/sqlalchemy import) so they run without the full app's
heavy stack."""
from cors_config import parse_origin, allowed_origins


def test_parse_origin_extracts_scheme_and_host():
    assert parse_origin("https://bas.internal") == "https://bas.internal"


def test_parse_origin_strips_path():
    assert parse_origin("https://bas.internal/some/path") == "https://bas.internal"


def test_parse_origin_keeps_explicit_port():
    assert parse_origin("http://localhost:8080") == "http://localhost:8080"


def test_parse_origin_empty_string_returns_none():
    assert parse_origin("") is None


def test_parse_origin_unparseable_value_returns_none():
    assert parse_origin("not-a-url-no-scheme") is None


def test_allowed_origins_empty_config_returns_empty_list():
    # The safe default: no cross-origin browser access at all, not a
    # wildcard fallback.
    assert allowed_origins(public_base_url="", extra_origins="") == []


def test_allowed_origins_uses_public_base_url_as_primary():
    assert allowed_origins(public_base_url="https://bas.internal", extra_origins="") == [
        "https://bas.internal"
    ]


def test_allowed_origins_appends_extra_origins():
    got = allowed_origins(
        public_base_url="https://bas.internal",
        extra_origins="https://admin.bas.internal, https://secondary.example.com",
    )
    assert got == [
        "https://bas.internal",
        "https://admin.bas.internal",
        "https://secondary.example.com",
    ]


def test_allowed_origins_dedupes_extra_origin_matching_primary():
    got = allowed_origins(
        public_base_url="https://bas.internal",
        extra_origins="https://bas.internal",
    )
    assert got == ["https://bas.internal"]


def test_allowed_origins_reads_real_env_vars_when_args_omitted(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://from-env.example.com")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "")
    assert allowed_origins() == ["https://from-env.example.com"]
