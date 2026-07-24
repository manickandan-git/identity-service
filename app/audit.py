from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditEvent


def get_client_ip(request: Request) -> str | None:
    """
    Return the best available client IP address.

    When the application runs behind a reverse proxy or API gateway,
    X-Forwarded-For may contain the original client IP followed by one
    or more proxy addresses.

    Example:
        X-Forwarded-For: 203.0.113.10, 10.0.0.5
    """

    forwarded_for = request.headers.get("x-forwarded-for")

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")

    if real_ip:
        return real_ip.strip()

    if request.client:
        return request.client.host

    return None


def get_user_agent(request: Request) -> str | None:
    """
    Return the calling browser, application, or HTTP client's user-agent.
    """

    user_agent = request.headers.get("user-agent")

    if not user_agent:
        return None

    # Keep the value within the database column limit.
    return user_agent[:500]


async def create_audit_event(
    session: AsyncSession,
    *,
    event_type: str,
    request: Request | None = None,
    user_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditEvent:
    """
    Add an audit event to the current database transaction.

    This function calls flush(), but it does not call commit(). The calling
    route or service should commit the transaction after all related changes
    succeed.

    That keeps the business operation and its audit event within the same
    transaction.

    Example:

        await create_audit_event(
            session,
            user_id=user.id,
            event_type="LOGIN_SUCCEEDED",
            request=request,
            details={
                "role": user.role.value,
            },
        )

        await session.commit()
    """

    if request is not None:
        if ip_address is None:
            ip_address = get_client_ip(request)

        if user_agent is None:
            user_agent = get_user_agent(request)

    event = AuditEvent(
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details,
    )

    session.add(event)
    await session.flush()

    return event