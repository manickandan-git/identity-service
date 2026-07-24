from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models import UserRole


# ============================================================
# Registration
# ============================================================


class RegisterRequest(BaseModel):
    """
    Request body for buyer, seller, or administrator registration.

    In a production marketplace, public registration should normally allow
    only BUYER and SELLER roles. ADMIN accounts should be created through
    a protected administrative process.
    """

    email: EmailStr

    password: str = Field(
        min_length=10,
        max_length=128,
        examples=["StrongPassword123!"],
    )

    first_name: str = Field(
        min_length=1,
        max_length=100,
        examples=["John"],
    )

    last_name: str = Field(
        min_length=1,
        max_length=100,
        examples=["Buyer"],
    )

    role: UserRole = UserRole.BUYER


class RegisterResponse(BaseModel):
    """
    Response returned after successful registration.
    """

    user_id: str
    email: EmailStr
    role: UserRole
    message: str

    # Returned only in development and test environments.
    # In production, the verification token should be sent by email.
    verification_token: str | None = None


# ============================================================
# Email verification
# ============================================================


class VerifyEmailRequest(BaseModel):
    """
    Request body used to verify a user's email address.
    """

    token: str = Field(
        min_length=1,
        examples=["email-verification-token"],
    )


class ResendVerificationRequest(BaseModel):
    """
    Requests a new email-verification token.
    """

    email: EmailStr


class ResendVerificationResponse(BaseModel):
    """
    Generic response for email-verification requests.

    The same message should be returned whether or not an account exists.
    This prevents attackers from discovering registered email addresses.
    """

    message: str

    # Development and test environments only.
    verification_token: str | None = None


# ============================================================
# Login and JWT tokens
# ============================================================


class LoginRequest(BaseModel):
    """
    User login request.
    """

    email: EmailStr

    password: str = Field(
        min_length=1,
        max_length=128,
        examples=["StrongPassword123!"],
    )


class TokenResponse(BaseModel):
    """
    Access and refresh tokens returned after login or token rotation.
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    """
    Request body used to rotate a refresh token.
    """

    refresh_token: str = Field(
        min_length=1,
    )


class LogoutRequest(BaseModel):
    """
    Request body used to revoke a refresh-token session.
    """

    refresh_token: str = Field(
        min_length=1,
    )


# ============================================================
# Password recovery
# ============================================================


class ForgotPasswordRequest(BaseModel):
    """
    Requests password-reset instructions for an email address.
    """

    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    """
    Generic forgot-password response.

    The same response should be returned for existing and unknown emails.
    """

    message: str

    # Development and test environments only.
    reset_token: str | None = None


class ResetPasswordRequest(BaseModel):
    """
    Resets a password using a single-use reset token.
    """

    token: str = Field(
        min_length=1,
    )

    new_password: str = Field(
        min_length=10,
        max_length=128,
        examples=["NewStrongPassword456!"],
    )


class ChangePasswordRequest(BaseModel):
    """
    Changes the password for an authenticated user.
    """

    current_password: str = Field(
        min_length=1,
        max_length=128,
    )

    new_password: str = Field(
        min_length=10,
        max_length=128,
        examples=["NewStrongPassword456!"],
    )


# ============================================================
# User profile
# ============================================================


class UserResponse(BaseModel):
    """
    Public representation of the authenticated user.

    Password hashes, login failures, and token information are never exposed.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    first_name: str
    last_name: str
    role: UserRole
    is_active: bool
    is_email_verified: bool
    created_at: datetime


# ============================================================
# Login sessions
# ============================================================


class SessionResponse(BaseModel):
    """
    Represents an active refresh-token session.
    """

    id: str
    token_id: str
    user_agent: str | None = None
    ip_address: str | None = None
    created_at: datetime
    expires_at: datetime


# ============================================================
# Audit events
# ============================================================


class AuditEventResponse(BaseModel):
    """
    Represents a user-visible security or identity audit event.
    """

    id: str
    event_type: str
    ip_address: str | None = None
    user_agent: str | None = None
    details: dict | None = None
    created_at: datetime


# ============================================================
# Common responses
# ============================================================


class MessageResponse(BaseModel):
    """
    Standard response for operations that return only a message.
    """

    message: str