import pytest
from fastapi.testclient import TestClient
from app import auth
from app.main import create_app

PW = "demo-password"

@pytest.fixture
def c(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret")
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.delenv("DEMO_PASSWORD", raising=False)
    return TestClient(create_app(auth_mode="token"))

def login(c, u, pw=PW, otp=None):
    return c.post("/auth/login", json={"username": u, "password": pw, "otp": otp})

def bearer(r):
    return {"Authorization": "Bearer " + r.json()["token"]}

def code(c, u):
    return auth.totp(c.app.state.db.execute("SELECT totp_secret FROM users WHERE id=?", (u,)).fetchone()["totp_secret"])

def test_rfc6238_vector():
    assert auth.totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59) == "287082"

def test_password_hash_roundtrip():
    h = auth.hash_password("x")
    assert auth.check_password("x", h) and not auth.check_password("y", h) and not auth.check_password("x", "garbage")

def test_login_failures(c):
    assert login(c, "priya", "wrong").status_code == 401
    assert login(c, "nobody").status_code == 401
    assert login(c, "sam").status_code == 401            # disabled account

def test_header_identity_ignored_in_token_mode(c):
    assert c.post("/access-request?resource=wiki", headers={"x-user-id": "root"}).status_code == 401
    assert c.get("/audit", headers={"x-user-id": "root"}).status_code == 401

def test_mfa_comes_from_login_not_database(c):
    h = bearer(login(c, "priya"))                         # password only: MFA not proven
    assert c.post("/access-request?resource=hr_db", headers={**h, "x-device-id": "d-priya"}).json()["decision"] == "STEP_UP_AUTHENTICATION"
    h2 = bearer(login(c, "priya", otp=code(c, "priya")))  # password + code
    assert c.post("/access-request?resource=hr_db", headers={**h2, "x-device-id": "d-priya"}).json()["decision"] == "ALLOW"

def test_step_up_upgrades_session(c):
    h = bearer(login(c, "priya"))
    assert c.post("/auth/step-up", json={"otp": "000000"}, headers=h).status_code == 401
    r = c.post("/auth/step-up", json={"otp": code(c, "priya")}, headers=h)
    assert r.json()["user"]["mfa"] is True
    assert c.get("/resources/hr_db", headers={**bearer(r), "x-device-id": "d-priya"}).status_code == 200

def test_user_without_mfa_enrolment_cannot_step_up(c):
    assert c.post("/auth/step-up", json={"otp": "123456"}, headers=bearer(login(c, "neha"))).status_code == 401
    assert login(c, "neha", otp="123456").status_code == 401

def test_bad_tokens_rejected(c):
    good = login(c, "root").json()["token"]
    for t in (good[:-2] + "xx", "a.b.c", "", auth.make_token(b"other-key", {"sub": "root"}, 60), auth.make_token(b"test-secret", {"sub": "root"}, -10)):
        assert c.get("/auth/me", headers={"Authorization": "Bearer " + t}).status_code == 401
    none_alg = "eyJhbGciOiJub25lIn0." + good.split(".")[1] + "."
    assert c.get("/auth/me", headers={"Authorization": "Bearer " + none_alg}).status_code == 401

def test_admin_routes_need_admin_role(c):
    assert c.get("/audit", headers=bearer(login(c, "aman"))).status_code == 403
    assert c.get("/audit", headers=bearer(login(c, "root"))).status_code == 200

def test_simulate_is_admin_only(c):
    assert c.post("/simulate?user=aman&resource=hr_db", headers=bearer(login(c, "aman"))).status_code == 403
    r = c.post("/simulate?user=aman&resource=hr_db", headers={**bearer(login(c, "root")), "x-device-id": "d-aman"})
    assert r.json()["policy_id"] == "P002"

def test_lockout_after_repeated_failures(c):
    for _ in range(5):
        assert login(c, "ravi", "bad").status_code == 401
    assert login(c, "ravi").status_code == 429

def test_demo_code_off_by_default(c):
    assert c.get("/auth/demo-code?username=priya").status_code == 404

def test_audit_chain_stays_valid_after_logins(c):
    login(c, "priya", "bad"); h = bearer(login(c, "root"))
    assert c.get("/audit/verify", headers=h).json() == {"intact": True}
