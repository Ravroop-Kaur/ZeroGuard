from fastapi.testclient import TestClient
from app.main import create_app

def test_admin_key_required_when_configured(monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "s3cret")
    c = TestClient(create_app())
    assert c.get("/audit", headers={"x-user-id": "root"}).status_code == 403
    assert c.get("/audit", headers={"x-user-id": "root", "x-admin-key": "wrong"}).status_code == 403
    assert c.get("/audit", headers={"x-user-id": "root", "x-admin-key": "s3cret"}).status_code == 200
    assert c.get("/audit", headers={"x-user-id": "aman", "x-admin-key": "s3cret"}).status_code == 403

def test_health_is_public():
    assert TestClient(create_app()).get("/health").json() == {"status": "ok"}
