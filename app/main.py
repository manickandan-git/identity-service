from fastapi import FastAPI

from app.config import get_settings
from app.routes import router as auth_router
from app.user_routes import router as user_router

settings = get_settings()

app = FastAPI(title=settings.app_name, version="0.2.0")


@app.get("/health", tags=["Operations"])
async def health():
    return {"status": "healthy", "service": settings.app_name}


app.include_router(auth_router, prefix=settings.api_v1_prefix)
app.include_router(user_router, prefix=settings.api_v1_prefix)
