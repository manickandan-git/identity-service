from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.config import get_settings
from app.database import engine
from app.routes import router as auth_router
from app.session_routes import router as session_router
from app.user_routes import router as user_router

settings = get_settings()
APP_VERSION = "0.3.0"


@asynccontextmanager
async def lifespan(
    _app: FastAPI,
) -> AsyncIterator[None]:
    """
    Run application startup and shutdown operations.

    Database schema changes should be handled by Alembic migrations.
    The application does not create tables automatically.
    """

    # Confirm that the database is reachable during startup.
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))

    yield

    # Close database connection pools during shutdown.
    await engine.dispose()


app = FastAPI(
    title=settings.app_name,
    version=APP_VERSION,
    description=(
        "Automated Swagger docs demonstration for Marketplace Stage 1 Identity Service,"
        "Marketplace Stage 1 Identity Service supporting registration, "
        "email verification, login, JWT authentication, password recovery, "
        "session management, account lockout, and audit events."
    ),
    swagger_ui_parameters={"syntaxHighlight": {"theme": "obsidian"}},
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# ============================================================
# Middleware
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Health endpoints
# ============================================================


@app.get(
    "/",
    tags=["Health"],
)
async def root() -> dict[str, str]:
    return {
        "service": settings.app_name,
        "version": APP_VERSION,
        "status": "running",
        "documentation": "/docs",
    }


@app.get(
    "/health",
    tags=["Health"],
)
async def health_check() -> dict[str, str]:
    """
    Basic process-level health check.
    """

    return {
        "status": "healthy",
        "service": settings.app_name,
        "environment": settings.app_env,
    }


@app.get(
    "/ready",
    tags=["Health"],
)
async def readiness_check() -> dict[str, str]:
    """
    Confirm that the application can communicate with PostgreSQL.
    """

    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))

    return {
        "status": "ready",
        "database": "connected",
    }


# ============================================================
# API routers
# ============================================================

app.include_router(
    auth_router,
    prefix=settings.api_v1_prefix,
)

app.include_router(
    session_router,
    prefix=settings.api_v1_prefix,
)

app.include_router(
    user_router,
    prefix=settings.api_v1_prefix,
)