"""Identity Security Enhancements

Revision ID: 20260724_0002
Revises: 20260723_0001
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "20260724_0002"
down_revision = "20260723_0001"
branch_labels = None
depends_on = None


def upgrade():

    # ----------------------------
    # users table
    # ----------------------------

    op.add_column(
        "users",
        sa.Column(
            "failed_login_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    op.add_column(
        "users",
        sa.Column(
            "locked_until",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    op.add_column(
        "users",
        sa.Column(
            "last_login_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # ----------------------------
    # refresh_tokens
    # ----------------------------

    op.add_column(
        "refresh_tokens",
        sa.Column(
            "user_agent",
            sa.String(500),
            nullable=True,
        ),
    )

    op.add_column(
        "refresh_tokens",
        sa.Column(
            "ip_address",
            sa.String(64),
            nullable=True,
        ),
    )

    # ----------------------------
    # audit_events
    # ----------------------------

    op.create_table(
        "audit_events",

        sa.Column(
            "id",
            sa.Uuid(),
            primary_key=True,
        ),

        sa.Column(
            "user_id",
            sa.Uuid(),
            nullable=True,
        ),

        sa.Column(
            "event_type",
            sa.String(100),
            nullable=False,
        ),

        sa.Column(
            "ip_address",
            sa.String(64),
        ),

        sa.Column(
            "user_agent",
            sa.String(500),
        ),

        sa.Column(
            "details",
            sa.JSON(),
        ),

        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),

        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
    )

    op.create_index(
        "ix_audit_events_user_id",
        "audit_events",
        ["user_id"],
    )

    op.create_index(
        "ix_audit_events_event_type",
        "audit_events",
        ["event_type"],
    )


def downgrade():

    op.drop_index(
        "ix_audit_events_event_type",
        table_name="audit_events",
    )

    op.drop_index(
        "ix_audit_events_user_id",
        table_name="audit_events",
    )

    op.drop_table("audit_events")

    op.drop_column(
        "refresh_tokens",
        "ip_address",
    )

    op.drop_column(
        "refresh_tokens",
        "user_agent",
    )

    op.drop_column(
        "users",
        "last_login_at",
    )

    op.drop_column(
        "users",
        "locked_until",
    )

    op.drop_column(
        "users",
        "failed_login_attempts",
    )