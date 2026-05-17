"""add api key scopes

Revision ID: 0004_api_key_scopes
Revises: 0003_account_user_email_unique
Create Date: 2026-05-17
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0004_api_key_scopes"
down_revision = "0003_account_user_email_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("api_keys", sa.Column("mailbox_id", sa.BigInteger(), nullable=True), schema="app")
    op.add_column(
        "api_keys",
        sa.Column("scopes", postgresql.JSONB(), nullable=False, server_default=sa.text("'[\"read\"]'::jsonb")),
        schema="app",
    )
    op.create_index("ix_app_api_keys_mailbox_id", "api_keys", ["mailbox_id"], schema="app")
    op.alter_column("api_keys", "scopes", server_default=None, schema="app")


def downgrade() -> None:
    op.drop_index("ix_app_api_keys_mailbox_id", table_name="api_keys", schema="app")
    op.drop_column("api_keys", "scopes", schema="app")
    op.drop_column("api_keys", "mailbox_id", schema="app")
