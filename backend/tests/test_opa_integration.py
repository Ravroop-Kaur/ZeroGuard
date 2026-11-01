import json, pathlib
import httpx, pytest
from fastapi.testclient import TestClient
from app.main import create_app, SEED_POLICIES
from app.opa_service import make_opa_evaluator

AMAN = {"x-user-id": "aman", "x-device-id": "d-aman"}

def client_with(handler):
    ev = make_opa_evaluator("http://opa", transport=httpx.MockTransport(handler))
    return TestClient(create_app(evaluator=ev))

def ok(effect="ALLOW", reason="r"):
    return lambda req: httpx.Response(200, json={"result": {"effect": effect, "reason": reason, "policy_id": "P9", "policy_version": 3}})

def test_opa_allow_is_enforced_and_version_logged():
    c = client_with(ok())
    assert c.get("/resources/hr_db", headers=AMAN).status_code == 200      # OPA says ALLOW
    row = c.app.state.db.execute("SELECT policy_id, policy_version FROM audit_log").fetchone()
    assert (row["policy_id"], row["policy_version"]) == ("P9", 3)

def test_opa_down_fails_closed():
    def boom(req): raise httpx.ConnectError("down")
    assert client_with(boom).get("/resources/wiki", headers=AMAN).status_code == 403   # wiki is normally allowed

def test_opa_500_fails_closed():
    assert client_with(lambda r: httpx.Response(500)).get("/resources/wiki", headers=AMAN).status_code == 403

@pytest.mark.parametrize("body", [{}, {"result": {"effect": "MAYBE", "reason": "x"}}, {"result": "ALLOW"}])
def test_invalid_opa_answer_fails_closed(body):
    assert client_with(lambda r: httpx.Response(200, json=body)).get("/resources/wiki", headers=AMAN).status_code == 403

def test_input_comes_from_server_not_client():
    seen = {}
    def h(req):
        seen.update(json.loads(req.content)["input"]); return httpx.Response(200, json={"result": {"effect": "DENY", "reason": "x"}})
    client_with(h).post("/access-request", params={"resource": "hr_db", "role": "hr"},
                        headers={**AMAN, "x-role": "hr"})
    assert seen["user"]["role"] == "developer" and seen["authentication"]["mfa_verified"] is True

def test_rego_data_matches_seed_policies():
    data = json.loads((pathlib.Path(__file__).parents[2] / "policies" / "data.json").read_text())
    assert data["zeroguard"]["policies"] == [p.__dict__ for p in SEED_POLICIES]
