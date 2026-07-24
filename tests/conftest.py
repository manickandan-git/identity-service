import os
from pathlib import Path

os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_identity.db"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-that-is-not-for-production"

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
import gc
import time

from app.database import Base, engine
from app.main import app

TEST_DB = Path("test_identity.db")


@pytest_asyncio.fixture(autouse=True)
async def reset_database():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


@pytest.fixture(scope="session", autouse=True)
def remove_test_database():
    yield
    # Force Python to clear unreferenced memory handles
    gc.collect() 
    
    if TEST_DB.exists():
        try:
            TEST_DB.unlink()
        except PermissionError:
            # Windows sometimes needs a fraction of a second to release the file handle
            time.sleep(0.1)
            TEST_DB.unlink()
