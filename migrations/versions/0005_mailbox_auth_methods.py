"""mailbox auth methods

Revision ID: 0005_mailbox_auth_methods
Revises: 0004_api_key_scopes
Create Date: 2026-05-17
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0005_mailbox_auth_methods"
down_revision = "0004_api_key_scopes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("accounts", "encrypted_password", nullable=True, schema="app")
    op.alter_column("accounts", "key_version", nullable=True, schema="app")
    op.add_column("accounts", sa.Column("oauth_scopes", postgresql.JSONB(), nullable=True), schema="app")
    op.add_column("accounts", sa.Column("oauth_subject", sa.Text(), nullable=True), schema="app")
    op.add_column("accounts", sa.Column("oauth_email", sa.Text(), nullable=True), schema="app")
    op.create_table(
        "pending_mailbox_verifications",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("mailbox_id", sa.BigInteger(), nullable=True),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("auth_type", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("encrypted_password", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.SmallInteger(), nullable=False),
        sa.Column("code_hash", sa.LargeBinary(), nullable=False),
        sa.Column("code_hash_version", sa.SmallInteger(), nullable=False, server_default="1"),
        sa.Column("attempts", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("status", sa.Text(), nullable=False, server_default="verifying"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        schema="app",
    )
    op.create_index(
        "ix_app_pending_mailbox_verifications_user_id",
        "pending_mailbox_verifications",
        ["user_id"],
        schema="app",
    )
    op.create_index(
        "ix_app_pending_mailbox_verifications_mailbox_id",
        "pending_mailbox_verifications",
        ["mailbox_id"],
        schema="app",
    )
    op.create_index(
        "ix_app_pending_mailbox_verifications_email",
        "pending_mailbox_verifications",
        ["email"],
        schema="app",
    )
    op.create_index(
        "ix_app_pending_mailbox_verifications_status",
        "pending_mailbox_verifications",
        ["status"],
        schema="app",
    )
    op.create_index(
        "ix_app_pending_mailbox_verifications_expires_at",
        "pending_mailbox_verifications",
        ["expires_at"],
        schema="app",
    )


def downgrade() -> None:
    op.drop_index("ix_app_pending_mailbox_verifications_expires_at", table_name="pending_mailbox_verifications", schema="app")
    op.drop_index("ix_app_pending_mailbox_verifications_status", table_name="pending_mailbox_verifications", schema="app")
    op.drop_index("ix_app_pending_mailbox_verifications_email", table_name="pending_mailbox_verifications", schema="app")
    op.drop_index("ix_app_pending_mailbox_verifications_mailbox_id", table_name="pending_mailbox_verifications", schema="app")
    op.drop_index("ix_app_pending_mailbox_verifications_user_id", table_name="pending_mailbox_verifications", schema="app")
    op.drop_table("pending_mailbox_verifications", schema="app")
    op.drop_column("accounts", "oauth_email", schema="app")
    op.drop_column("accounts", "oauth_subject", schema="app")
    op.drop_column("accounts", "oauth_scopes", schema="app")
    op.alter_column("accounts", "key_version", nullable=False, schema="app")
    op.alter_column("accounts", "encrypted_password", nullable=False, schema="app")
