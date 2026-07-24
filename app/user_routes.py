from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import CurrentUser
from app.models import AuditEvent
from app.schemas import AuditEventResponse, UserResponse

router = APIRouter(
    prefix="/users",
    tags=["Users"],
)


@router.get(
    "/me",
    response_model=UserResponse,
)
async def get_current_user_profile(
    current_user: CurrentUser,
) -> UserResponse:
    """
    Return the authenticated user's profile.

    The user is identified from the JWT access token supplied in the
    Authorization header.
    """

    return UserResponse(
        id=str(current_user.id),
        email=current_user.email,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        role=current_user.role,
        is_active=current_user.is_active,
        is_email_verified=current_user.is_email_verified,
        created_at=current_user.created_at,
    )


@router.get(
    "/me/audit-events",
    response_model=list[AuditEventResponse],
)
async def get_current_user_audit_events(
    current_user: CurrentUser,
    session: AsyncSession = Depends(get_db),
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
        description="Maximum number of audit events to return",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Number of audit events to skip",
    ),
) -> list[AuditEventResponse]:
    """
    Return identity and security events for the authenticated user.

    Events are returned newest first.

    Examples include:

    - USER_REGISTERED
    - EMAIL_VERIFIED
    - LOGIN_SUCCEEDED
    - LOGIN_FAILED
    - ACCOUNT_LOCKED
    - PASSWORD_CHANGED
    - PASSWORD_RESET_COMPLETED
    - SESSION_REVOKED
    - LOGOUT
    """

    result = await session.execute(
        select(AuditEvent)
        .where(
            AuditEvent.user_id == current_user.id,
        )
        .order_by(
            AuditEvent.created_at.desc(),
        )
        .offset(offset)
        .limit(limit)
    )

    audit_events = result.scalars().all()

    return [
        AuditEventResponse(
            id=str(event.id),
            event_type=event.event_type,
            ip_address=event.ip_address,
            user_agent=event.user_agent,
            details=event.details,
            created_at=event.created_at,
        )
        for event in audit_events
    ]