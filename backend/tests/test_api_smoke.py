"""API integration tests run in environments with the full worker dependency set."""

import pytest

pytest.importorskip("celery", reason="Install backend project dependencies to run API integration tests")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database import Base, get_db
from app.main import app
from app import models  # noqa: F401 - register all models


@pytest.fixture()
def client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(settings, "allow_public_signup", True)
    monkeypatch.setattr(settings, "environment", "test")
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    # The in-memory engine is isolated per test; dispose it rather than dropping
    # tables in SQLite, which cannot ALTER cyclic foreign-key constraints.
    engine.dispose()


def register(client: TestClient, email: str, org: str) -> dict:
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "full_name": "Sentinel Test User",
            "password": "this-is-a-strong-test-password",
            "organization_name": org,
        },
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    return {"Authorization": f"Bearer {payload['access_token']}"}


def test_auth_project_lifecycle_and_tenant_isolation(client: TestClient):
    owner = register(client, "owner-a@example.com", "Workspace A")
    assert client.get("/api/v1/auth/me", headers=owner).status_code == 200

    created = client.post(
        "/api/v1/projects",
        headers=owner,
        json={"name": "Billing portal", "description": "Integration test project"},
    )
    assert created.status_code == 201, created.text
    project_id = created.json()["id"]

    assert client.get("/api/v1/projects", headers=owner).json()[0]["id"] == project_id

    other_org_user = register(client, "owner-b@example.com", "Workspace B")
    assert client.get(f"/api/v1/projects/{project_id}", headers=other_org_user).status_code == 404
    assert client.get("/api/v1/projects", headers=other_org_user).json() == []


def test_registration_allows_only_initial_owner_when_public_signup_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "allow_public_signup", False)
    register(client, "initial-owner@example.com", "Initial Workspace")
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "uninvited@example.com",
            "full_name": "Uninvited User",
            "password": "this-is-a-strong-test-password",
            "organization_name": "Unexpected Workspace",
        },
    )
    assert response.status_code == 403
