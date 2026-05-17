"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-05-16
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS app")
    op.execute("CREATE SCHEMA IF NOT EXISTS audit")

    op.create_table(
        "accounts",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("auth_type", sa.Text(), nullable=False),
        sa.Column("encrypted_password", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.SmallInteger(), nullable=False),
        sa.Column("oauth_refresh_token", sa.LargeBinary(), nullable=True),
        sa.Column("oauth_access_token", sa.LargeBinary(), nullable=True),
        sa.Column("oauth_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("imap_host", sa.Text(), nullable=False),
        sa.Column("imap_port", sa.Integer(), nullable=False),
        sa.Column("api_key_prefix", sa.String(length=8), nullable=False),
        sa.Column("api_key_hash", sa.LargeBinary(), nullable=False),
        sa.Column("api_key_hash_version", sa.SmallInteger(), nullable=False),
        sa.Column("previous_api_key_hash", sa.LargeBinary(), nullable=True),
        sa.Column("previous_api_key_hash_version", sa.SmallInteger(), nullable=True),
        sa.Column("previous_valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        schema="app",
    )
    op.create_index("ix_app_accounts_email", "accounts", ["email"], unique=True, schema="app")
    op.create_index("ix_app_accounts_api_key_prefix", "accounts", ["api_key_prefix"], unique=True, schema="app")

    op.create_table(
        "audit_outbox",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("event", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivery_attempts", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        schema="app",
    )

    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("actor_type", sa.Text(), nullable=False),
        sa.Column("actor_id", sa.Text(), nullable=True),
        sa.Column("client_ip", postgresql.INET(), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target_account_id", sa.BigInteger(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("extra", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("request_id", sa.Text(), nullable=False),
        schema="audit",
    )
    op.create_index("ix_audit_events_timestamp", "events", [sa.text("timestamp DESC")], schema="audit")
    op.create_index("ix_audit_events_target_account_timestamp", "events", ["target_account_id", sa.text("timestamp DESC")], schema="audit")
    op.create_index("ix_audit_events_action_timestamp", "events", ["action", sa.text("timestamp DESC")], schema="audit")
    op.create_index("ix_audit_events_request_id", "events", ["request_id"], schema="audit")


def downgrade() -> None:
    op.drop_index("ix_audit_events_request_id", table_name="events", schema="audit")
    op.drop_index("ix_audit_events_action_timestamp", table_name="events", schema="audit")
    op.drop_index("ix_audit_events_target_account_timestamp", table_name="events", schema="audit")
    op.drop_index("ix_audit_events_timestamp", table_name="events", schema="audit")
    op.drop_table("events", schema="audit")
    op.drop_table("audit_outbox", schema="app")
    op.drop_index("ix_app_accounts_api_key_prefix", table_name="accounts", schema="app")
    op.drop_index("ix_app_accounts_email", table_name="accounts", schema="app")
    op.drop_table("accounts", schema="app")
    op.execute("DROP SCHEMA IF EXISTS audit")
    op.execute("DROP SCHEMA IF EXISTS app")
