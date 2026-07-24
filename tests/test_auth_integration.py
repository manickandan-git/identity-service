from __future__ import annotations

from httpx import AsyncClient


async def test_register_buyer(
    client: AsyncClient,
    buyer_registration_payload: dict[str, str],
) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json=buyer_registration_payload,
    )

    assert response.status_code == 201, response.text

    body = response.json()

    assert body["email"] == buyer_registration_payload["email"]
    assert body["role"] == "BUYER"
    assert body["message"] == (
        "Registration successful. "
        "Check your email to verify your account."
    )
    assert body["user_id"]
    assert body["verification_token"]


async def test_duplicate_registration_is_rejected(
    client: AsyncClient,
    buyer_registration_payload: dict[str, str],
) -> None:
    first_response = await client.post(
        "/api/v1/auth/register",
        json=buyer_registration_payload,
    )

    assert first_response.status_code == 201

    second_response = await client.post(
        "/api/v1/auth/register",
        json=buyer_registration_payload,
    )

    assert second_response.status_code == 409
    assert second_response.json()["detail"] == (
        "An account with this email already exists"
    )


async def test_admin_public_registration_is_blocked(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@example.com",
            "password": "AdminPassword123!",
            "first_name": "Marketplace",
            "last_name": "Admin",
            "role": "ADMIN",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Administrator accounts cannot be publicly registered"
    )


async def test_verify_email(
    client: AsyncClient,
    registered_buyer: dict,
) -> None:
    response = await client.post(
        "/api/v1/auth/verify-email",
        json={
            "token": registered_buyer["verification_token"],
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": "Email verified successfully",
    }


async def test_verification_token_cannot_be_reused(
    client: AsyncClient,
    registered_buyer: dict,
) -> None:
    token = registered_buyer["verification_token"]

    first_response = await client.post(
        "/api/v1/auth/verify-email",
        json={"token": token},
    )

    assert first_response.status_code == 200

    second_response = await client.post(
        "/api/v1/auth/verify-email",
        json={"token": token},
    )

    assert second_response.status_code == 400
    assert second_response.json()["detail"] == (
        "Verification token has already been used"
    )


async def test_unverified_user_cannot_login(
    client: AsyncClient,
    buyer_registration_payload: dict[str, str],
    registered_buyer: dict,
) -> None:
    del registered_buyer

    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": buyer_registration_payload["email"],
            "password": buyer_registration_payload["password"],
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Email verification is required"
    )


async def test_verified_user_can_login(
    client: AsyncClient,
    verified_buyer: dict,
) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json=verified_buyer["credentials"],
    )

    assert response.status_code == 200, response.text

    body = response.json()

    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 900


async def test_login_with_incorrect_password_is_rejected(
    client: AsyncClient,
    verified_buyer: dict,
) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": verified_buyer["credentials"]["email"],
            "password": "IncorrectPassword123!",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid email or password"
    )


async def test_unknown_email_login_is_rejected(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "unknown@example.com",
            "password": "UnknownPassword123!",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid email or password"
    )


async def test_get_current_user_profile(
    client: AsyncClient,
    authenticated_buyer: dict,
) -> None:
    response = await client.get(
        "/api/v1/users/me",
        headers=authenticated_buyer["headers"],
    )

    assert response.status_code == 200, response.text

    body = response.json()

    assert body["email"] == "buyer@example.com"
    assert body["first_name"] == "John"
    assert body["last_name"] == "Buyer"
    assert body["role"] == "BUYER"
    assert body["is_active"] is True
    assert body["is_email_verified"] is True
    assert body["created_at"]


async def test_profile_requires_access_token(
    client: AsyncClient,
) -> None:
    response = await client.get(
        "/api/v1/users/me",
    )

    assert response.status_code == 401


async def test_refresh_token_rotation(
    client: AsyncClient,
    authenticated_buyer: dict,
) -> None:
    original_refresh_token = authenticated_buyer["refresh_token"]

    response = await client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": original_refresh_token,
        },
    )

    assert response.status_code == 200, response.text

    body = response.json()

    assert body["access_token"]
    assert body["refresh_token"]
    assert body["refresh_token"] != original_refresh_token
    assert body["token_type"] == "bearer"


async def test_old_refresh_token_is_rejected_after_rotation(
    client: AsyncClient,
    authenticated_buyer: dict,
) -> None:
    original_refresh_token = authenticated_buyer["refresh_token"]

    first_response = await client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": original_refresh_token,
        },
    )

    assert first_response.status_code == 200

    second_response = await client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": original_refresh_token,
        },
    )

    assert second_response.status_code == 401
    assert second_response.json()["detail"] == (
        "Refresh token has been revoked"
    )


async def test_access_token_cannot_be_used_as_refresh_token(
    client: AsyncClient,
    authenticated_buyer: dict,
) -> None:
    response = await client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": authenticated_buyer["access_token"],
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "A refresh token is required"
    )


async def test_logout_revokes_refresh_token(
    client: AsyncClient,
    authenticated_buyer: dict,
) -> None:
    refresh_token = authenticated_buyer["refresh_token"]

    logout_response = await client.post(
        "/api/v1/auth/logout",
        json={
            "refresh_token": refresh_token,
        },
    )

    assert logout_response.status_code == 200
    assert logout_response.json() == {
        "message": "Logged out successfully",
    }

    refresh_response = await client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": refresh_token,
        },
    )

    assert refresh_response.status_code == 401
    assert refresh_response.json()["detail"] == (
        "Refresh token has been revoked"
    )


async def test_forgot_password_for_existing_user(
    client: AsyncClient,
    verified_buyer: dict,
) -> None:
    response = await client.post(
        "/api/v1/auth/forgot-password",
        json={
            "email": verified_buyer["credentials"]["email"],
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["message"] == (
        "If an account exists for this email, "
        "password-reset instructions have been sent."
    )
    assert body["reset_token"]


async def test_forgot_password_does_not_reveal_unknown_email(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/forgot-password",
        json={
            "email": "unknown@example.com",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["message"] == (
        "If an account exists for this email, "
        "password-reset instructions have been sent."
    )
    assert body["reset_token"] is None


async def test_reset_password(
    client: AsyncClient,
    verified_buyer: dict,
) -> None:
    old_password = verified_buyer["credentials"]["password"]
    new_password = "NewBuyerPassword456!"

    forgot_response = await client.post(
        "/api/v1/auth/forgot-password",
        json={
            "email": verified_buyer["credentials"]["email"],
        },
    )

    assert forgot_response.status_code == 200

    reset_token = forgot_response.json()["reset_token"]

    reset_response = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": reset_token,
            "new_password": new_password,
        },
    )

    assert reset_response.status_code == 200
    assert reset_response.json() == {
        "message": (
            "Password reset successfully. "
            "Please sign in with your new password."
        ),
    }

    old_login_response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": verified_buyer["credentials"]["email"],
            "password": old_password,
        },
    )

    assert old_login_response.status_code == 401

    new_login_response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": verified_buyer["credentials"]["email"],
            "password": new_password,
        },
    )

    assert new_login_response.status_code == 200


async def test_reset_token_cannot_be_reused(
    client: AsyncClient,
    verified_buyer: dict,
) -> None:
    forgot_response = await client.post(
        "/api/v1/auth/forgot-password",
        json={
            "email": verified_buyer["credentials"]["email"],
        },
    )

    reset_token = forgot_response.json()["reset_token"]

    first_response = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": reset_token,
            "new_password": "NewBuyerPassword456!",
        },
    )

    assert first_response.status_code == 200

    second_response = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": reset_token,
            "new_password": "AnotherPassword789!",
        },
    )

    assert second_response.status_code == 400
    assert second_response.json()["detail"] == (
        "Password-reset token has already been used"
    )


async def test_password_reset_revokes_existing_sessions(
    client: AsyncClient,
    authenticated_buyer: dict,
) -> None:
    existing_refresh_token = authenticated_buyer["refresh_token"]

    forgot_response = await client.post(
        "/api/v1/auth/forgot-password",
        json={
            "email": authenticated_buyer["credentials"]["email"],
        },
    )

    reset_token = forgot_response.json()["reset_token"]

    reset_response = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": reset_token,
            "new_password": "BuyerPasswordAfterReset123!",
        },
    )

    assert reset_response.status_code == 200

    refresh_response = await client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": existing_refresh_token,
        },
    )

    assert refresh_response.status_code == 401
    assert refresh_response.json()["detail"] == (
        "Refresh token has been revoked"
    )


async def test_authenticated_user_can_change_password(
    client: AsyncClient,
    authenticated_buyer: dict,
) -> None:
    old_password = authenticated_buyer["credentials"]["password"]
    new_password = "ChangedBuyerPassword456!"

    response = await client.post(
        "/api/v1/auth/change-password",
        headers=authenticated_buyer["headers"],
        json={
            "current_password": old_password,
            "new_password": new_password,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": (
            "Password changed successfully. "
            "Please sign in again."
        ),
    }

    old_login_response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": authenticated_buyer["credentials"]["email"],
            "password": old_password,
        },
    )

    assert old_login_response.status_code == 401

    new_login_response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": authenticated_buyer["credentials"]["email"],
            "password": new_password,
        },
    )

    assert new_login_response.status_code == 200


async def test_change_password_rejects_incorrect_current_password(
    client: AsyncClient,
    authenticated_buyer: dict,
) -> None:
    response = await client.post(
        "/api/v1/auth/change-password",
        headers=authenticated_buyer["headers"],
        json={
            "current_password": "IncorrectCurrentPassword123!",
            "new_password": "ChangedBuyerPassword456!",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Current password is incorrect"
    )


async def test_new_password_must_be_different(
    client: AsyncClient,
    authenticated_buyer: dict,
) -> None:
    current_password = authenticated_buyer["credentials"]["password"]

    response = await client.post(
        "/api/v1/auth/change-password",
        headers=authenticated_buyer["headers"],
        json={
            "current_password": current_password,
            "new_password": current_password,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "The new password must be different "
        "from the current password"
    )