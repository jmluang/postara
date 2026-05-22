"""mailbox connection health

Revision ID: 0008_mailbox_health
Revises: 0007_auth_attempt_buckets
Create Date: 2026-05-22
"""

from alembic import op
import sqlalchemy as sa


revision = "0008_mailbox_health"
down_revision = "0007_auth_attempt_buckets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "accounts",
        sa.Column("health_status", sa.Text(), nullable=False, server_default="unknown"),
        schema="app",
    )
    op.add_column(
        "accounts",
        sa.Column("health_checked_at", sa.DateTime(timezone=True), nullable=True),
        schema="app",
    )
    op.add_column(
        "accounts",
        sa.Column("health_detail", sa.Text(), nullable=True),
        schema="app",
    )


def downgrade() -> None:
    op.drop_column("accounts", "health_detail", schema="app")
    op.drop_column("accounts", "health_checked_at", schema="app")
    op.drop_column("accounts", "health_status", schema="app")
