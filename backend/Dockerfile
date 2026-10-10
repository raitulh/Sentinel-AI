FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN groupadd --system --gid 10001 sentinel && useradd --system --uid 10001 --gid sentinel --home-dir /app sentinel
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install .
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
