FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY alembic ./alembic
COPY app ./app

RUN pip install --no-cache-dir .

EXPOSE 8001

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8001"]
