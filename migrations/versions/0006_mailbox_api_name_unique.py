"""mailbox api name unique

Revision ID: 0006_mailbox_api_name_unique
Revises: 0005_mailbox_auth_methods
Create Date: 2026-05-18
"""

from alembic import op


revision = "0006_mailbox_api_name_unique"
down_revision = "0005_mailbox_auth_methods"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint("uq_app_accounts_user_id_name", "accounts", ["user_id", "name"], schema="app")


def downgrade() -> None:
    op.drop_constraint("uq_app_accounts_user_id_name", "accounts", schema="app", type_="unique")
