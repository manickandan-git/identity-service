from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import create_audit_event
from app.database import get_db
from app.datetime_utils import utc_now
from app.dependencies import CurrentUser
from app.models import RefreshToken
from app.schemas import MessageResponse, SessionResponse

router = APIRouter(
    prefix="/auth/sessions",
    tags=["Sessions"],
)

@router.get(
    "",
    response_model=list[SessionResponse],
)
async def list_sessions(
    current_user: CurrentUser,
    session: AsyncSession = Depends(get_db),
) -> list[SessionResponse]:
    """
    Return all active refresh-token sessions for the authenticated user.

    Expired and revoked sessions are excluded.
    """

    result = await session.execute(
        select(RefreshToken)
        .where(
            RefreshToken.user_id == current_user.id,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > utc_now(),
        )
        .order_by(RefreshToken.created_at.desc())
    )

    refresh_sessions = result.scalars().all()

    return [
        SessionResponse(
            id=str(refresh_session.id),
            token_id=refresh_session.token_id,
            user_agent=refresh_session.user_agent,
            ip_address=refresh_session.ip_address,
            created_at=refresh_session.created_at,
            expires_at=refresh_session.expires_at,
        )
        for refresh_session in refresh_sessions
    ]


@router.delete(
    "/{session_id}",
    response_model=MessageResponse,
)
async def revoke_session(
    session_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser,
    session: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Revoke one refresh-token session belonging to the authenticated user.

    A user cannot revoke another user's session because the database query
    always filters by both session ID and current user ID.
    """

    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.id == session_id,
            RefreshToken.user_id == current_user.id,
        )
    )

    refresh_session = result.scalar_one_or_none()

    if refresh_session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session was not found",
        )

    if refresh_session.revoked_at is not None:
        return MessageResponse(
            message="Session is already revoked",
        )

    refresh_session.revoked_at = utc_now()

    await create_audit_event(
        session,
        user_id=current_user.id,
        event_type="SESSION_REVOKED",
        request=request,
        details={
            "session_id": str(refresh_session.id),
            "token_id": refresh_session.token_id,
        },
    )

    await session.commit()

    return MessageResponse(
        message="Session revoked successfully",
    )