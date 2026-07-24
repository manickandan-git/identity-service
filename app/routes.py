from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import create_audit_event, get_client_ip, get_user_agent
from app.config import get_settings
from app.database import get_db
from app.datetime_utils import as_utc, utc_now
from app.dependencies import CurrentUser
from app.models import (
    PasswordResetToken,
    RefreshToken,
    User,
    UserRole,
    VerificationToken,
)
from app.schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    ResendVerificationRequest,
    ResendVerificationResponse,
    ResetPasswordRequest,
    TokenResponse,
    VerifyEmailRequest,
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

settings = get_settings()

password_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


# ============================================================
# Internal helpers
# ============================================================


def normalize_email(email: str) -> str:
    return email.strip().lower()


def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(
    plain_password: str,
    password_hash: str,
) -> bool:
    try:
        return password_context.verify(
            plain_password,
            password_hash,
        )
    except (TypeError, ValueError):
        return False


def generate_secure_token() -> str:
    """
    Generate a cryptographically secure token.

    The raw token is returned to the user, while only its SHA-256
    hash is stored in the database.
    """

    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8"),
    ).hexdigest()


def create_access_token(user: User) -> str:
    now = utc_now()
    expiration = now + timedelta(
        minutes=settings.access_token_expire_minutes,
    )

    payload: dict[str, Any] = {
        "sub": str(user.id),
        "email": user.email,
        "role": (
            user.role.value
            if hasattr(user.role, "value")
            else str(user.role)
        ),
        "type": "access",
        "iat": now,
        "exp": expiration,
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def create_refresh_token(
    user: User,
    token_id: str,
) -> str:
    now = utc_now()
    expiration = now + timedelta(
        days=settings.refresh_token_expire_days,
    )

    payload: dict[str, Any] = {
        "sub": str(user.id),
        "jti": token_id,
        "type": "refresh",
        "iat": now,
        "exp": expiration,
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_jwt_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def expose_development_token(token: str) -> str | None:
    """
    Return raw verification or reset tokens only outside production.

    In production, the Notification Service should email the token
    or a URL containing the token.
    """

    if settings.app_env.lower() in {
        "development",
        "dev",
        "test",
        "testing",
        "local",
    }:
        return token

    return None


async def find_user_by_email(
    session: AsyncSession,
    email: str,
) -> User | None:
    result = await session.execute(
        select(User).where(
            User.email == normalize_email(email),
        )
    )

    return result.scalar_one_or_none()


async def revoke_all_user_sessions(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> None:
    now = utc_now()

    await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )


async def create_refresh_session(
    session: AsyncSession,
    user: User,
    request: Request,
) -> tuple[str, RefreshToken]:
    token_id = secrets.token_hex(32)
    expires_at = utc_now() + timedelta(
        days=settings.refresh_token_expire_days,
    )

    refresh_session = RefreshToken(
        user_id=user.id,
        token_id=token_id,
        user_agent=get_user_agent(request),
        ip_address=get_client_ip(request),
        expires_at=expires_at,
    )

    session.add(refresh_session)
    await session.flush()

    raw_refresh_token = create_refresh_token(
        user,
        token_id,
    )

    return raw_refresh_token, refresh_session


# ============================================================
# Registration
# ============================================================


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    payload: RegisterRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> RegisterResponse:
    """
    Register a new buyer or seller.

    Public registration of administrator accounts is blocked.
    """

    email = normalize_email(str(payload.email))

    if payload.role == UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator accounts cannot be publicly registered",
        )

    existing_user = await find_user_by_email(
        session,
        email,
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = User(
        email=email,
        first_name=payload.first_name.strip(),
        last_name=payload.last_name.strip(),
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
        is_email_verified=False,
    )

    session.add(user)
    await session.flush()

    raw_verification_token = generate_secure_token()

    verification_token = VerificationToken(
        user_id=user.id,
        token_hash=hash_token(raw_verification_token),
        expires_at=utc_now()
        + timedelta(
            minutes=settings.email_verification_expire_minutes,
        ),
    )

    session.add(verification_token)

    await create_audit_event(
        session,
        user_id=user.id,
        event_type="USER_REGISTERED",
        request=request,
        details={
            "email": user.email,
            "role": user.role.value,
        },
    )

    await session.commit()
    await session.refresh(user)

    return RegisterResponse(
        user_id=str(user.id),
        email=user.email,
        role=user.role,
        message=(
            "Registration successful. "
            "Check your email to verify your account."
        ),
        verification_token=expose_development_token(
            raw_verification_token,
        ),
    )


# ============================================================
# Email verification
# ============================================================


@router.post(
    "/verify-email",
    response_model=MessageResponse,
)
async def verify_email(
    payload: VerifyEmailRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> MessageResponse:
    token_digest = hash_token(payload.token)

    result = await session.execute(
        select(VerificationToken).where(
            VerificationToken.token_hash == token_digest,
        )
    )

    verification_token = result.scalar_one_or_none()

    if verification_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification token",
        )

    if verification_token.used_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token has already been used",
        )

    if as_utc(verification_token.expires_at) <= utc_now():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token has expired",
        )

    user_result = await session.execute(
        select(User).where(
            User.id == verification_token.user_id,
        )
    )

    user = user_result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account was not found",
        )

    user.is_email_verified = True
    verification_token.used_at = utc_now()

    await create_audit_event(
        session,
        user_id=user.id,
        event_type="EMAIL_VERIFIED",
        request=request,
    )

    await session.commit()

    return MessageResponse(
        message="Email verified successfully",
    )


@router.post(
    "/resend-verification",
    response_model=ResendVerificationResponse,
)
async def resend_verification(
    payload: ResendVerificationRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> ResendVerificationResponse:
    """
    Generate a replacement verification token.

    The endpoint always returns a generic response to prevent email
    address enumeration.
    """

    generic_message = (
        "If an eligible account exists, "
        "a verification message has been sent."
    )

    user = await find_user_by_email(
        session,
        str(payload.email),
    )

    if user is None or user.is_email_verified:
        return ResendVerificationResponse(
            message=generic_message,
        )

    # Invalidate all unused verification tokens.
    await session.execute(
        update(VerificationToken)
        .where(
            VerificationToken.user_id == user.id,
            VerificationToken.used_at.is_(None),
        )
        .values(used_at=utc_now())
    )

    raw_token = generate_secure_token()

    replacement_token = VerificationToken(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        expires_at=utc_now()
        + timedelta(
            minutes=settings.email_verification_expire_minutes,
        ),
    )

    session.add(replacement_token)

    await create_audit_event(
        session,
        user_id=user.id,
        event_type="EMAIL_VERIFICATION_RESENT",
        request=request,
    )

    await session.commit()

    return ResendVerificationResponse(
        message=generic_message,
        verification_token=expose_development_token(
            raw_token,
        ),
    )


# ============================================================
# Login
# ============================================================


@router.post(
    "/login",
    response_model=TokenResponse,
)
async def login(
    payload: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> TokenResponse:
    user = await find_user_by_email(
        session,
        str(payload.email),
    )

    invalid_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if user is None:
        # Do not reveal whether the email exists.
        raise invalid_credentials

    now = utc_now()

    if user.locked_until is not None:
        if as_utc(user.locked_until) > now:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=(
                    "Account is temporarily locked. "
                    "Try again later."
                ),
            )

        # Lock period expired.
        user.locked_until = None
        user.failed_login_attempts = 0

    if not verify_password(
        payload.password,
        user.password_hash,
    ):
        user.failed_login_attempts += 1

        await create_audit_event(
            session,
            user_id=user.id,
            event_type="LOGIN_FAILED",
            request=request,
            details={
                "failed_attempts": user.failed_login_attempts,
            },
        )

        if (
            user.failed_login_attempts
            >= settings.max_failed_login_attempts
        ):
            user.locked_until = now + timedelta(
                minutes=settings.account_lock_minutes,
            )

            await create_audit_event(
                session,
                user_id=user.id,
                event_type="ACCOUNT_LOCKED",
                request=request,
                details={
                    "locked_until": (
                        user.locked_until.isoformat()
                    ),
                    "failed_attempts": (
                        user.failed_login_attempts
                    ),
                },
            )

        await session.commit()
        raise invalid_credentials

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    if not user.is_email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification is required",
        )

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now

    access_token = create_access_token(user)

    refresh_token, refresh_session = (
        await create_refresh_session(
            session,
            user,
            request,
        )
    )

    await create_audit_event(
        session,
        user_id=user.id,
        event_type="LOGIN_SUCCEEDED",
        request=request,
        details={
            "session_id": str(refresh_session.id),
        },
    )

    await session.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=(
            settings.access_token_expire_minutes * 60
        ),
    )


@router.post(
    "/token",
    response_model=TokenResponse,
)
async def token_login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    OAuth2 password flow endpoint used by Swagger UI Authorize.

    Swagger sends `username` and `password` form fields.
    Here, `username` is treated as the account email.
    """

    payload = LoginRequest(
        email=form_data.username,
        password=form_data.password,
    )

    return await login(
        payload=payload,
        request=request,
        session=session,
    )


# ============================================================
# Refresh-token rotation
# ============================================================


@router.post(
    "/refresh",
    response_model=TokenResponse,
)
async def refresh_access_token(
    payload: RefreshRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> TokenResponse:
    claims = decode_jwt_token(payload.refresh_token)

    if claims.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A refresh token is required",
        )

    subject = claims.get("sub")
    token_id = claims.get("jti")

    if not subject or not token_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    try:
        user_id = uuid.UUID(subject)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        ) from exc

    token_result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.token_id == token_id,
            RefreshToken.user_id == user_id,
        )
    )

    stored_token = token_result.scalar_one_or_none()

    if stored_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh session was not found",
        )

    if stored_token.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    if as_utc(stored_token.expires_at) <= utc_now():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )

    user_result = await session.execute(
        select(User).where(User.id == user_id)
    )

    user = user_result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is unavailable",
        )

    # Revoke the current refresh token.
    stored_token.revoked_at = utc_now()

    # Create a replacement refresh session.
    new_refresh_token, new_refresh_session = (
        await create_refresh_session(
            session,
            user,
            request,
        )
    )

    new_access_token = create_access_token(user)

    await create_audit_event(
        session,
        user_id=user.id,
        event_type="REFRESH_TOKEN_ROTATED",
        request=request,
        details={
            "old_session_id": str(stored_token.id),
            "new_session_id": str(new_refresh_session.id),
        },
    )

    await session.commit()

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=(
            settings.access_token_expire_minutes * 60
        ),
    )


# ============================================================
# Logout
# ============================================================


@router.post(
    "/logout",
    response_model=MessageResponse,
)
async def logout(
    payload: LogoutRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> MessageResponse:
    claims = decode_jwt_token(payload.refresh_token)

    if claims.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A refresh token is required",
        )

    token_id = claims.get("jti")
    subject = claims.get("sub")

    if not token_id or not subject:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token",
        )

    try:
        user_id = uuid.UUID(subject)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token",
        ) from exc

    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.token_id == token_id,
            RefreshToken.user_id == user_id,
        )
    )

    refresh_session = result.scalar_one_or_none()

    if (
        refresh_session is not None
        and refresh_session.revoked_at is None
    ):
        refresh_session.revoked_at = utc_now()

        await create_audit_event(
            session,
            user_id=user_id,
            event_type="LOGOUT",
            request=request,
            details={
                "session_id": str(refresh_session.id),
            },
        )

        await session.commit()

    return MessageResponse(
        message="Logged out successfully",
    )


# ============================================================
# Forgot password
# ============================================================


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> ForgotPasswordResponse:
    """
    Create a single-use password-reset token.

    The same public response is returned for registered and unknown
    email addresses.
    """

    generic_message = (
        "If an account exists for this email, "
        "password-reset instructions have been sent."
    )

    user = await find_user_by_email(
        session,
        str(payload.email),
    )

    if user is None or not user.is_active:
        return ForgotPasswordResponse(
            message=generic_message,
        )

    # Invalidate all previous unused reset tokens.
    await session.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        )
        .values(used_at=utc_now())
    )

    raw_reset_token = generate_secure_token()

    password_reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_token(raw_reset_token),
        expires_at=utc_now()
        + timedelta(
            minutes=settings.password_reset_expire_minutes,
        ),
    )

    session.add(password_reset_token)

    await create_audit_event(
        session,
        user_id=user.id,
        event_type="PASSWORD_RESET_REQUESTED",
        request=request,
    )

    await session.commit()

    return ForgotPasswordResponse(
        message=generic_message,
        reset_token=expose_development_token(
            raw_reset_token,
        ),
    )


# ============================================================
# Reset password
# ============================================================


@router.post(
    "/reset-password",
    response_model=MessageResponse,
)
async def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> MessageResponse:
    token_digest = hash_token(payload.token)

    result = await session.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_digest,
        )
    )

    reset_token = result.scalar_one_or_none()

    if reset_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password-reset token",
        )

    if reset_token.used_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password-reset token has already been used",
        )

    if as_utc(reset_token.expires_at) <= utc_now():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password-reset token has expired",
        )

    user_result = await session.execute(
        select(User).where(
            User.id == reset_token.user_id,
        )
    )

    user = user_result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is unavailable",
        )

    if verify_password(
        payload.new_password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "The new password must be different "
                "from the current password"
            ),
        )

    user.password_hash = hash_password(
        payload.new_password,
    )

    user.failed_login_attempts = 0
    user.locked_until = None
    reset_token.used_at = utc_now()

    # Password reset revokes every active session.
    await revoke_all_user_sessions(
        session,
        user.id,
    )

    await create_audit_event(
        session,
        user_id=user.id,
        event_type="PASSWORD_RESET_COMPLETED",
        request=request,
        details={
            "all_sessions_revoked": True,
        },
    )

    await session.commit()

    return MessageResponse(
        message=(
            "Password reset successfully. "
            "Please sign in with your new password."
        ),
    )


# ============================================================
# Authenticated password change
# ============================================================


@router.post(
    "/change-password",
    response_model=MessageResponse,
)
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    current_user: CurrentUser,
    session: AsyncSession = Depends(get_db),
) -> MessageResponse:
    if not verify_password(
        payload.current_password,
        current_user.password_hash,
    ):
        await create_audit_event(
            session,
            user_id=current_user.id,
            event_type="PASSWORD_CHANGE_FAILED",
            request=request,
            details={
                "reason": "invalid_current_password",
            },
        )

        await session.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    if verify_password(
        payload.new_password,
        current_user.password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "The new password must be different "
                "from the current password"
            ),
        )

    current_user.password_hash = hash_password(
        payload.new_password,
    )

    current_user.failed_login_attempts = 0
    current_user.locked_until = None

    # Revoke all refresh-token sessions after password change.
    await revoke_all_user_sessions(
        session,
        current_user.id,
    )

    await create_audit_event(
        session,
        user_id=current_user.id,
        event_type="PASSWORD_CHANGED",
        request=request,
        details={
            "all_sessions_revoked": True,
        },
    )

    await session.commit()

    return MessageResponse(
        message=(
            "Password changed successfully. "
            "Please sign in again."
        ),
    )