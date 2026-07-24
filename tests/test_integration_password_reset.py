from tests.helpers import register_verify_login


async def test_forgot_and_reset_password(client):
    old_password = "StrongPassword123!"
    new_password = "DifferentPassword456!"
    tokens = await register_verify_login(client, password=old_password)

    forgot = await client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "buyer@example.com"},
    )
    assert forgot.status_code == 200
    reset_token = forgot.json()["reset_token"]
    assert reset_token

    reset = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "new_password": new_password},
    )
    assert reset.status_code == 200

    old_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "buyer@example.com", "password": old_password},
    )
    assert old_login.status_code == 401

    new_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "buyer@example.com", "password": new_password},
    )
    assert new_login.status_code == 200

    revoked_refresh = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert revoked_refresh.status_code == 401


async def test_forgot_password_does_not_reveal_unknown_email(client):
    response = await client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "unknown@example.com"},
    )
    assert response.status_code == 200
    assert response.json()["reset_token"] is None


async def test_reset_token_cannot_be_reused(client):
    await register_verify_login(client)
    forgot = await client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "buyer@example.com"},
    )
    token = forgot.json()["reset_token"]

    first = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "NewPassword123!"},
    )
    assert first.status_code == 200

    second = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "AnotherPassword123!"},
    )
    assert second.status_code == 400
