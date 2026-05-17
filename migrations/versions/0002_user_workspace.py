"""user workspace

Revision ID: 0002_user_workspace
Revises: 0001_initial_schema
Create Date: 2026-05-16
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_user_workspace"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False, server_default="member"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        schema="app",
    )
    op.create_index("ix_app_users_email", "users", ["email"], unique=True, schema="app")

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("token_prefix", sa.String(length=8), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        schema="app",
    )
    op.create_index("ix_app_user_sessions_user_id", "user_sessions", ["user_id"], schema="app")
    op.create_index("ix_app_user_sessions_token_prefix", "user_sessions", ["token_prefix"], unique=True, schema="app")
    op.create_index("ix_app_user_sessions_expires_at", "user_sessions", ["expires_at"], schema="app")

    op.create_table(
        "api_keys",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("prefix", sa.String(length=8), nullable=False),
        sa.Column("key_hash", sa.LargeBinary(), nullable=False),
        sa.Column("hash_version", sa.SmallInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        schema="app",
    )
    op.create_index("ix_app_api_keys_user_id", "api_keys", ["user_id"], schema="app")
    op.create_index("ix_app_api_keys_prefix", "api_keys", ["prefix"], unique=True, schema="app")

    op.add_column("accounts", sa.Column("user_id", sa.BigInteger(), nullable=True), schema="app")
    op.create_index("ix_app_accounts_user_id", "accounts", ["user_id"], schema="app")


def downgrade() -> None:
    op.drop_index("ix_app_accounts_user_id", table_name="accounts", schema="app")
    op.drop_column("accounts", "user_id", schema="app")
    op.drop_index("ix_app_api_keys_prefix", table_name="api_keys", schema="app")
    op.drop_index("ix_app_api_keys_user_id", table_name="api_keys", schema="app")
    op.drop_table("api_keys", schema="app")
    op.drop_index("ix_app_user_sessions_expires_at", table_name="user_sessions", schema="app")
    op.drop_index("ix_app_user_sessions_token_prefix", table_name="user_sessions", schema="app")
    op.drop_index("ix_app_user_sessions_user_id", table_name="user_sessions", schema="app")
    op.drop_table("user_sessions", schema="app")
    op.drop_index("ix_app_users_email", table_name="users", schema="app")
    op.drop_table("users", schema="app")
