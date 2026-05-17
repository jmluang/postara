from courier.audit import AuditEvent, AuditOutbox, sanitize_extra


def test_sanitize_extra_redacts_sensitive_prefixes_recursively():
    extra = {
        "api_key": "secret",
        "TokenValue": "secret",
        "nested": {
            "html_body": "<p>secret</p>",
            "message_uid": 42,
        },
    }

    sanitized = sanitize_extra(extra)

    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["TokenValue"] == "[REDACTED]"
    assert sanitized["nested"]["html_body"] == "[REDACTED]"
    assert sanitized["nested"]["message_uid"] == 42


def test_audit_outbox_sanitizes_events_before_storing():
    outbox = AuditOutbox()
    event = AuditEvent(
        action="apikey.rotate",
        actor_type="account_key",
        actor_id="1",
        status="success",
        request_id="req_1234567890abcdef",
        client_ip="127.0.0.1",
        user_agent="tests",
        target_account_id=1,
        extra={"secret": "raw", "safe": "ok"},
    )

    outbox.enqueue(event)

    assert outbox.pending[0].event.extra == {"secret": "[REDACTED]", "safe": "ok"}
    assert outbox.pending[0].delivered_at is None
