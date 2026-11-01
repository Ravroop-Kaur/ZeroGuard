import pytest
from fastapi.testclient import TestClient
from app.main import create_app

@pytest.fixture
def c():
    return TestClient(create_app())

def req(c, user, res, dev=None):
    h = {"x-user-id": user, **({"x-device-id": dev} if dev else {})}
    return c.post("/access-request", params={"resource": res}, headers=h).json()

def test_hr_allowed(c):          assert req(c, "priya", "hr_db", "d-priya")["decision"] == "ALLOW"
def test_developer_denied(c):    assert req(c, "aman", "hr_db", "d-aman")["policy_id"] == "P002"
def test_inactive_denied(c):     assert req(c, "sam", "wiki")["decision"] == "DENY"
def test_no_mfa_stepup(c):       assert req(c, "neha", "hr_db", "d-neha")["decision"] == "STEP_UP_AUTHENTICATION"
def test_admin_bad_device(c):    assert req(c, "root", "source_code", "d-root")["policy_id"] == "P004"
def test_intern_denied(c):       assert req(c, "ravi", "source_code", "d-ravi")["policy_id"] == "P005"
def test_default_deny(c):        assert req(c, "ravi", "hr_db", "d-ravi")["reason"].startswith("No applicable")
def test_other_users_device_ignored(c):  # device not owned by the caller counts as missing
    assert req(c, "priya", "hr_db", "d-aman")["decision"] == "DENY"
def test_pep_blocks_and_allows(c):
    h = {"x-user-id": "aman", "x-device-id": "d-aman"}
    assert c.get("/resources/hr_db", headers=h).status_code == 403
    assert c.get("/resources/wiki", headers=h).status_code == 200
def test_admin_routes_protected_and_logged(c):
    assert c.get("/audit", headers={"x-user-id": "aman"}).status_code == 403
    assert c.get("/audit", headers={"x-user-id": "root"}).status_code == 200
def test_audit_tamper_detected(c):
    req(c, "priya", "hr_db", "d-priya")
    assert c.get("/audit/verify", headers={"x-user-id": "root"}).json()["intact"]
    c.app.state.db.execute("UPDATE audit_log SET decision='DENY' WHERE id=1"); c.app.state.db.commit()
    assert not c.get("/audit/verify", headers={"x-user-id": "root"}).json()["intact"]
