async def register_verify_login(client, email="buyer@example.com", password="StrongPassword123!"):
    registration = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "first_name": "Test",
            "last_name": "Buyer",
            "role": "BUYER",
        },
    )
    assert registration.status_code == 201, registration.text
    verification_token = registration.json()["verification_token"]

    verification = await client.post(
        "/api/v1/auth/verify-email",
        json={"token": verification_token},
    )
    assert verification.status_code == 200, verification.text

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login.status_code == 200, login.text
    return login.json()
