"""auth attempt buckets

Revision ID: 0007_auth_attempt_buckets
Revises: 0006_mailbox_api_name_unique
Create Date: 2026-05-19
"""

from alembic import op
import sqlalchemy as sa


revision = "0007_auth_attempt_buckets"
down_revision = "0006_mailbox_api_name_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_attempt_buckets",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("bucket_type", sa.Text(), nullable=False),
        sa.Column("bucket_key", sa.Text(), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("challenge_required_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("bucket_type", "bucket_key", name="uq_app_auth_attempt_buckets_type_key"),
        schema="app",
    )
    op.create_index("ix_app_auth_attempt_buckets_bucket_type", "auth_attempt_buckets", ["bucket_type"], schema="app")
    op.create_index("ix_app_auth_attempt_buckets_bucket_key", "auth_attempt_buckets", ["bucket_key"], schema="app")
    op.create_index(
        "ix_app_auth_attempt_buckets_window_started_at",
        "auth_attempt_buckets",
        ["window_started_at"],
        schema="app",
    )
    op.create_index("ix_app_auth_attempt_buckets_locked_until", "auth_attempt_buckets", ["locked_until"], schema="app")


def downgrade() -> None:
    op.drop_index("ix_app_auth_attempt_buckets_locked_until", table_name="auth_attempt_buckets", schema="app")
    op.drop_index("ix_app_auth_attempt_buckets_window_started_at", table_name="auth_attempt_buckets", schema="app")
    op.drop_index("ix_app_auth_attempt_buckets_bucket_key", table_name="auth_attempt_buckets", schema="app")
    op.drop_index("ix_app_auth_attempt_buckets_bucket_type", table_name="auth_attempt_buckets", schema="app")
    op.drop_table("auth_attempt_buckets", schema="app")
