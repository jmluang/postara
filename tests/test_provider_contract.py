from datetime import datetime, timezone

import pytest

from courier.providers.base import MessageQuery, UnsupportedProviderFeature
from courier.providers.gmail import GmailAdapter


def test_gmail_adapter_rejects_unsupported_query_filters():
    adapter = GmailAdapter()
    query = MessageQuery(limit=20, text_contains="invoice")

    with pytest.raises(UnsupportedProviderFeature) as exc:
        adapter.validate_query(query)

    assert exc.value.fields == ["text_contains"]


def test_gmail_adapter_accepts_mvp_query_filters():
    adapter = GmailAdapter()
    query = MessageQuery(
        limit=20,
        unread_only=True,
        since=datetime(2026, 5, 1, tzinfo=timezone.utc),
        before=datetime(2026, 5, 16, tzinfo=timezone.utc),
        from_address="billing@example.com",
    )

    assert adapter.validate_query(query) is None
