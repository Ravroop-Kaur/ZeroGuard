"""Calls OPA and validates its answer. Any failure raises, and the caller must fail closed."""
import httpx

EFFECTS = {"ALLOW", "DENY", "STEP_UP_AUTHENTICATION"}
DECISION_PATH = "/v1/data/zeroguard/authorization/decision"


class PolicyEngineError(Exception):
    pass


def make_opa_evaluator(base_url: str, timeout: float = 2.0, transport=None):
    client = httpx.Client(base_url=base_url, timeout=timeout, transport=transport)

    def evaluate(inp: dict) -> dict:
        try:
            r = client.post(DECISION_PATH, json={"input": inp})
            r.raise_for_status()
            res = r.json().get("result")
        except (httpx.HTTPError, ValueError) as e:
            raise PolicyEngineError(f"OPA unavailable: {e}") from e
        if not isinstance(res, dict) or res.get("effect") not in EFFECTS or not isinstance(res.get("reason"), str):
            raise PolicyEngineError("OPA returned an invalid decision")
        return {"effect": res["effect"], "reason": res["reason"],
                "policy_id": res.get("policy_id"), "policy_version": res.get("policy_version")}

    return evaluate
