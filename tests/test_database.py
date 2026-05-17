from sqlalchemy.pool import NullPool

from courier.config import Settings
from courier.database import asyncpg_engine_kwargs, create_app_session_factory, create_audit_session_factory


def test_asyncpg_engine_kwargs_disable_statement_cache_for_pooler_urls():
    kwargs = asyncpg_engine_kwargs(
        "postgresql+asyncpg://courier@pooler.example.com:6543/courier"
        "?prepared_statement_cache_size=0"
    )

    assert kwargs["connect_args"]["statement_cache_size"] == 0
    assert callable(kwargs["connect_args"]["prepared_statement_name_func"])
    assert kwargs["connect_args"]["prepared_statement_name_func"]().startswith("__asyncpg_")
    assert kwargs["connect_args"]["prepared_statement_name_func"]() != kwargs["connect_args"][
        "prepared_statement_name_func"
    ]()
    assert kwargs["poolclass"] is NullPool


def test_asyncpg_engine_kwargs_keep_regular_urls_unchanged():
    assert asyncpg_engine_kwargs("postgresql+asyncpg://courier@postgres:5432/courier") == {}


def test_session_factories_apply_pooler_engine_kwargs(monkeypatch):
    calls = []

    def fake_create_async_engine(url, **kwargs):
        calls.append((url, kwargs))
        return object()

    monkeypatch.setattr("courier.database.create_async_engine", fake_create_async_engine)
    settings = Settings(
        app_database_url="postgresql+asyncpg://courier@app-pooler.example.com:6543/courier"
        "?prepared_statement_cache_size=0",
        audit_database_url="postgresql+asyncpg://courier@audit-pooler.example.com:6543/courier"
        "?prepared_statement_cache_size=0",
    )

    create_app_session_factory(settings)
    create_audit_session_factory(settings)

    assert len(calls) == 2
    assert calls[0][0] == settings.app_database_url
    assert calls[1][0] == settings.audit_database_url
    for _url, kwargs in calls:
        assert kwargs["pool_pre_ping"] is True
        assert kwargs["poolclass"] is NullPool
        assert kwargs["connect_args"]["statement_cache_size"] == 0
        assert callable(kwargs["connect_args"]["prepared_statement_name_func"])
