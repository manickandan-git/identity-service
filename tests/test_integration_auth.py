from tests.helpers import register_verify_login


async def test_complete_registration_login_and_get_me(client):
    tokens = await register_verify_login(client)

    response = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "buyer@example.com"
    assert body["role"] == "BUYER"
    assert body["is_email_verified"] is True


async def test_get_me_requires_authentication(client):
    response = await client.get("/api/v1/users/me")
    assert response.status_code == 401


async def test_refresh_token_is_rotated(client):
    tokens = await register_verify_login(client)

    first_refresh = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert first_refresh.status_code == 200

    replay = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert replay.status_code == 401
