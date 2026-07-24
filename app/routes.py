import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.datetime_utils import as_utc, utc_now
from app.models import PasswordResetToken, RefreshToken, User, VerificationToken
from app.schemas import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    ResetPasswordRequest,
    TokenResponse,
    VerifyEmailRequest,
)
from app.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_opaque_token,
    hash_password,
    hash_token,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await db.scalar(select(User).where(User.email == payload.email.lower()))
    if existing:
        raise HTTPException(status_code=409, detail="Email is already registered")

    user = User(
        email=payload.email.lower(),
        first_name=payload.first_name.strip(),
        last_name=payload.last_name.strip(),
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    await db.flush()

    raw_token = generate_opaque_token()
    db.add(
        VerificationToken(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            expires_at=utc_now() + timedelta(minutes=settings.email_verification_expire_minutes),
        )
    )
    await db.commit()

    return RegisterResponse(
        user_id=str(user.id),
        email=user.email,
        role=user.role,
        message="Registration successful. Verify your email before logging in.",
        verification_token=raw_token if settings.app_env in {"development", "test"} else None,
    )


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(payload: VerifyEmailRequest, db: AsyncSession = Depends(get_db)):
    token_record = await db.scalar(
        select(VerificationToken).where(VerificationToken.token_hash == hash_token(payload.token))
    )
    now = utc_now()
    if not token_record or token_record.used_at or as_utc(token_record.expires_at) < now:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    user = await db.get(User, token_record.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_email_verified = True
    token_record.used_at = now
    await db.commit()
    return MessageResponse(message="Email verified successfully")


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(User).where(User.email == payload.email.lower()))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    if not user.is_email_verified:
        raise HTTPException(status_code=403, detail="Email verification is required")

    token_id = uuid.uuid4().hex
    access_token, expires_in = create_access_token(str(user.id), user.role.value)
    refresh_token = create_refresh_token(str(user.id), user.role.value, token_id)
    db.add(
        RefreshToken(
            user_id=user.id,
            token_id=token_id,
            expires_at=utc_now() + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, db: AsyncSession = Depends(get_db)):
    try:
        claims = decode_token(payload.refresh_token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    if claims.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Refresh token required")

    token_id = claims.get("jti")
    subject = claims.get("sub")
    record = await db.scalar(select(RefreshToken).where(RefreshToken.token_id == token_id))
    now = utc_now()
    if not record or record.revoked_at or as_utc(record.expires_at) < now:
        raise HTTPException(status_code=401, detail="Refresh token is revoked or expired")

    try:
        user_id = uuid.UUID(subject)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=401, detail="Invalid token subject") from exc

    user = await db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User is unavailable")

    record.revoked_at = now
    new_token_id = uuid.uuid4().hex
    db.add(
        RefreshToken(
            user_id=user.id,
            token_id=new_token_id,
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    access_token, expires_in = create_access_token(str(user.id), user.role.value)
    refresh_token = create_refresh_token(str(user.id), user.role.value, new_token_id)
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(payload: LogoutRequest, db: AsyncSession = Depends(get_db)):
    try:
        claims = decode_token(payload.refresh_token)
    except ValueError:
        return MessageResponse(message="Logged out")

    token_id = claims.get("jti")
    if token_id:
        record = await db.scalar(select(RefreshToken).where(RefreshToken.token_id == token_id))
        if record and not record.revoked_at:
            record.revoked_at = utc_now()
            await db.commit()
    return MessageResponse(message="Logged out")


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    generic_message = "If the account exists, password reset instructions have been sent."
    user = await db.scalar(select(User).where(User.email == payload.email.lower()))
    if not user or not user.is_active:
        return ForgotPasswordResponse(message=generic_message)

    await db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        )
        .values(used_at=utc_now())
    )

    raw_token = generate_opaque_token()
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            expires_at=utc_now() + timedelta(minutes=settings.password_reset_expire_minutes),
        )
    )
    await db.commit()

    # Production: publish an event for Notification Service instead of returning the token.
    return ForgotPasswordResponse(
        message=generic_message,
        reset_token=raw_token if settings.app_env in {"development", "test"} else None,
    )


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    payload: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    record = await db.scalar(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == hash_token(payload.token)
        )
    )
    now = utc_now()
    if not record or record.used_at or as_utc(record.expires_at) < now:
        raise HTTPException(status_code=400, detail="Invalid or expired password reset token")

    user = await db.get(User, record.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid or expired password reset token")
    if verify_password(payload.new_password, user.password_hash):
        raise HTTPException(status_code=400, detail="New password must differ from current password")

    user.password_hash = hash_password(payload.new_password)
    record.used_at = now
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    await db.commit()
    return MessageResponse(message="Password reset successfully. Sign in with your new password.")
