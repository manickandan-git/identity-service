from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app


TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


# ============================================================
# Event loop
# ============================================================


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """
    Create one asyncio event loop for the complete test session.

    Session scope prevents database engines and async connections from being
    shared across different event loops.
    """

    loop = asyncio.new_event_loop()

    yield loop

    loop.close()


# ============================================================
# Test database engine
# ============================================================


@pytest_asyncio.fixture(scope="session")
async def test_engine() -> AsyncGenerator[AsyncEngine, None]:
    """
    Create an in-memory SQLite database for integration tests.

    StaticPool ensures every test database connection uses the same
    in-memory SQLite database.
    """

    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={
            "check_same_thread": False,
        },
        poolclass=StaticPool,
    )

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)

    await engine.dispose()


# ============================================================
# Test database session factory
# ============================================================


@pytest_asyncio.fixture(scope="session")
async def test_session_factory(
    test_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """
    Return a session factory connected to the test database.
    """

    return async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


# ============================================================
# Database cleanup
# ============================================================


@pytest_asyncio.fixture(autouse=True)
async def clean_database(
    test_engine: AsyncEngine,
) -> AsyncGenerator[None, None]:
    """
    Remove all records before every test.

    Tables remain available throughout the test session, but each test starts
    with an empty database.
    """

    async with test_engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            await connection.execute(table.delete())

    yield


# ============================================================
# Database dependency override
# ============================================================


@pytest_asyncio.fixture
async def override_database_dependency(
    test_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[None, None]:
    """
    Replace the production get_db dependency with the test database session.
    """

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with test_session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db] = override_get_db

    yield

    app.dependency_overrides.clear()


# ============================================================
# HTTP test client
# ============================================================


@pytest_asyncio.fixture
async def client(
    override_database_dependency: None,
) -> AsyncGenerator[AsyncClient, None]:
    """
    Return an asynchronous HTTP client connected directly to FastAPI.

    No external web server is required.
    """

    transport = ASGITransport(
        app=app,
        raise_app_exceptions=True,
    )

    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={
            "User-Agent": "Marketplace-Integration-Test/1.0",
            "X-Forwarded-For": "127.0.0.1",
        },
    ) as async_client:
        yield async_client


# ============================================================
# Reusable test helpers
# ============================================================


@pytest.fixture
def buyer_registration_payload() -> dict[str, str]:
    return {
        "email": "buyer@example.com",
        "password": "BuyerPassword123!",
        "first_name": "John",
        "last_name": "Buyer",
        "role": "BUYER",
    }


@pytest.fixture
def seller_registration_payload() -> dict[str, str]:
    return {
        "email": "seller@example.com",
        "password": "SellerPassword123!",
        "first_name": "Sarah",
        "last_name": "Seller",
        "role": "SELLER",
    }


@pytest_asyncio.fixture
async def registered_buyer(
    client: AsyncClient,
    buyer_registration_payload: dict[str, str],
) -> dict:
    """
    Register a buyer and return the API response.
    """

    response = await client.post(
        "/api/v1/auth/register",
        json=buyer_registration_payload,
    )

    assert response.status_code == 201, response.text

    return response.json()


@pytest_asyncio.fixture
async def verified_buyer(
    client: AsyncClient,
    buyer_registration_payload: dict[str, str],
    registered_buyer: dict,
) -> dict:
    """
    Register and verify a buyer.
    """

    verification_token = registered_buyer.get(
        "verification_token"
    )

    assert verification_token is not None, (
        "The verification token was not returned. "
        "Set APP_ENV=test in the test environment."
    )

    response = await client.post(
        "/api/v1/auth/verify-email",
        json={
            "token": verification_token,
        },
    )

    assert response.status_code == 200, response.text

    return {
        "registration": registered_buyer,
        "credentials": {
            "email": buyer_registration_payload["email"],
            "password": buyer_registration_payload["password"],
        },
    }


@pytest_asyncio.fixture
async def authenticated_buyer(
    client: AsyncClient,
    verified_buyer: dict,
) -> dict:
    """
    Register, verify, and authenticate a buyer.

    Returns access token, refresh token, and authorization headers.
    """

    response = await client.post(
        "/api/v1/auth/login",
        json=verified_buyer["credentials"],
    )

    assert response.status_code == 200, response.text

    token_data = response.json()
    access_token = token_data["access_token"]

    return {
        "access_token": access_token,
        "refresh_token": token_data["refresh_token"],
        "headers": {
            "Authorization": f"Bearer {access_token}",
        },
        "credentials": verified_buyer["credentials"],
        "registration": verified_buyer["registration"],
    }