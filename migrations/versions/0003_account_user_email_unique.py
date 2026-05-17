"""scope account email uniqueness to user

Revision ID: 0003_account_user_email_unique
Revises: 0002_user_workspace
Create Date: 2026-05-17
"""

from alembic import op


revision = "0003_account_user_email_unique"
down_revision = "0002_user_workspace"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_app_accounts_email", table_name="accounts", schema="app")
    op.create_index("ix_app_accounts_email", "accounts", ["email"], unique=False, schema="app")
    op.create_unique_constraint(
        "uq_app_accounts_user_id_email",
        "accounts",
        ["user_id", "email"],
        schema="app",
    )


def downgrade() -> None:
    op.drop_constraint("uq_app_accounts_user_id_email", "accounts", schema="app", type_="unique")
    op.drop_index("ix_app_accounts_email", table_name="accounts", schema="app")
    op.create_index("ix_app_accounts_email", "accounts", ["email"], unique=True, schema="app")
