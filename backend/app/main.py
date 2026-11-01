import hashlib, hmac, json, os, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .policy_engine import Policy, evaluate_access
from .opa_service import make_opa_evaluator

SEED_USERS = [  # id, name, role, status, mfa_verified
    ("aman", "Aman", "developer", "active", 1), ("priya", "Priya", "hr", "active", 1),
    ("root", "Root", "admin", "active", 1), ("ravi", "Ravi", "intern", "active", 1),
    ("sam", "Sam", "hr", "disabled", 1), ("neha", "Neha", "hr", "active", 0)]
SEED_DEVICES = [("d-aman", "aman", 1), ("d-priya", "priya", 1), ("d-root", "root", 0),
                ("d-ravi", "ravi", 1), ("d-neha", "neha", 1)]
SEED_RESOURCES = [("hr_db", "high", "HR records"), ("source_code", "high", "Private repo"),
                  ("wiki", "low", "Company wiki")]
SEED_POLICIES = [
    Policy("P001", "HR may use HR database with MFA and compliant device", "ALLOW", ["hr"], ["hr_db"], True, True),
    Policy("P002", "Developers cannot access HR database", "DENY", ["developer"], ["hr_db"]),
    Policy("P003", "Sensitive data requires MFA", "STEP_UP_AUTHENTICATION", [], [], False, None, 3),
    Policy("P004", "Admin on non-compliant device is denied", "DENY", ["admin"], [], None, False, 2),
    Policy("P005", "Interns cannot access source code", "DENY", ["intern"], ["source_code"]),
    Policy("P006", "Devs/admins may use source code with MFA and compliant device", "ALLOW", ["developer", "admin"], ["source_code"], True, True),
    Policy("P007", "Anyone may read the wiki", "ALLOW", [], ["wiki"])]


STATIC = Path(__file__).parent.parent / "static"   # React build output (frontend: npm run build)


def create_app(db_path=":memory:", evaluator=None):
    app = FastAPI(title="ZeroGuard")
    db = sqlite3.connect(db_path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name,role,status,mfa_verified);
    CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,user_id,compliant);
    CREATE TABLE IF NOT EXISTS resources(name TEXT PRIMARY KEY,sensitivity,description);
    CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY,body TEXT);
    CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,ts,user_id,resource,device_id,
        decision,reason,policy_id,policy_version,prev_hash,hash);""")
    db.executemany("INSERT OR IGNORE INTO users VALUES(?,?,?,?,?)", SEED_USERS)
    db.executemany("INSERT OR IGNORE INTO devices VALUES(?,?,?)", SEED_DEVICES)
    db.executemany("INSERT OR IGNORE INTO resources VALUES(?,?,?)", SEED_RESOURCES)
    db.executemany("INSERT OR REPLACE INTO policies VALUES(?,?)", [(p.id, json.dumps(p.__dict__)) for p in SEED_POLICIES])

    def python_evaluator(inp):   # local fallback when OPA_URL is not set (tests / quick demo)
        pols = [Policy(**json.loads(r["body"])) for r in db.execute("SELECT body FROM policies")]
        u = {**inp["user"], "mfa_verified": inp["authentication"]["mfa_verified"]}
        e, reason, pid, ver = evaluate_access(u, inp["resource"], inp["device"], pols)
        return {"effect": e, "reason": reason, "policy_id": pid, "policy_version": ver}

    engine_name = "custom"
    if evaluator is None:
        if os.environ.get("OPA_URL"):
            evaluator, engine_name = make_opa_evaluator(os.environ["OPA_URL"]), "opa"
        else:
            evaluator, engine_name = python_evaluator, "python-fallback"
    print(f"[zeroguard] policy engine: {engine_name}", flush=True)

    def log(user_id, resource, device_id, decision, reason, pid, ver):
        row = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else "GENESIS"
        ts = datetime.now(timezone.utc).isoformat()
        body = json.dumps([ts, user_id, resource, device_id, decision, reason, pid, ver, prev])
        db.execute("INSERT INTO audit_log(ts,user_id,resource,device_id,decision,reason,policy_id,"
                   "policy_version,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (ts, user_id, resource, device_id, decision, reason, pid, ver, prev,
                    hashlib.sha256(body.encode()).hexdigest()))
        db.commit()

    def decide(user_id, resource_name, device_id):
        # Role, MFA and device posture come from the SERVER database, never from the request body.
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        res = db.execute("SELECT * FROM resources WHERE name=?", (resource_name,)).fetchone()
        dev = db.execute("SELECT * FROM devices WHERE id=? AND user_id=?", (device_id, user_id)).fetchone()
        if user is None or res is None:   # unknown subject/resource: deny without asking the engine
            out = ("DENY", "Inactive or unknown account" if user is None else "Unknown resource", None, None)
        else:
            inp = {"user": {"id": user["id"], "role": user["role"], "status": user["status"]},
                   "resource": {"name": res["name"], "sensitivity": res["sensitivity"]},
                   "device": {"compliant": bool(dev and dev["compliant"])},   # missing/foreign device = non-compliant
                   "authentication": {"mfa_verified": bool(user["mfa_verified"])},
                   "action": "READ"}
            try:
                r = evaluator(inp)
                out = (r["effect"], r["reason"], r.get("policy_id"), r.get("policy_version"))
            except Exception:             # policy engine down or invalid answer: fail closed
                out = ("DENY", "POLICY_ENGINE_UNAVAILABLE", None, None)
        log(user_id, resource_name, device_id, *out)
        return out

    def require_admin(x_user_id, x_admin_key=None):
        key = os.environ.get("ADMIN_KEY")   # set when deployed: a shared secret on top of the demo identity header
        if key and not hmac.compare_digest(x_admin_key or "", key):
            log(x_user_id, "admin-api", None, "DENY", "Admin key missing or wrong", None, None)
            raise HTTPException(403, "Admin only")
        u = db.execute("SELECT role,status FROM users WHERE id=?", (x_user_id,)).fetchone()
        if not u or u["role"] != "admin" or u["status"] != "active":
            log(x_user_id, "admin-api", None, "DENY", "Admin route requires admin role", None, None)
            raise HTTPException(403, "Admin only")

    @app.get("/health", include_in_schema=False)
    def health():
        return {"status": "ok"}

    @app.get("/health/policy", include_in_schema=False)   # deployment debugging: can we reach the policy engine?
    def health_policy():
        probe = {"user": {"id": "probe", "role": "probe", "status": "active"}, "resource": {"name": "wiki", "sensitivity": "low"},
                 "device": {"compliant": True}, "authentication": {"mfa_verified": True}, "action": "READ"}
        try:
            return {"engine": engine_name, "reachable": True, "probe_effect": evaluator(probe)["effect"]}
        except Exception as e:
            return {"engine": engine_name, "reachable": False, "error": type(e).__name__}

    @app.post("/access-request")
    def access_request(resource: str, x_user_id: str = Header(), x_device_id: str = Header(None)):
        d, reason, pid, ver = decide(x_user_id, resource, x_device_id)
        return {"decision": d, "reason": reason, "policy_id": pid, "policy_version": ver}

    @app.get("/resources/{name}")   # Policy Enforcement Point: data returned only on ALLOW
    def protected_resource(name: str, x_user_id: str = Header(), x_device_id: str = Header(None)):
        d, reason, _, _ = decide(x_user_id, name, x_device_id)
        if d == "STEP_UP_AUTHENTICATION":
            raise HTTPException(401, reason)
        if d != "ALLOW":
            raise HTTPException(403, reason)
        return {"resource": name, "data": f"(simulated contents of {name})"}

    @app.get("/audit")
    def audit(x_user_id: str = Header(), x_admin_key: str = Header(None)):
        require_admin(x_user_id, x_admin_key)
        return [dict(r) for r in db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")]

    @app.get("/audit/verify")
    def verify(x_user_id: str = Header(), x_admin_key: str = Header(None)):
        require_admin(x_user_id, x_admin_key)
        prev = "GENESIS"
        for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
            body = json.dumps([r["ts"], r["user_id"], r["resource"], r["device_id"], r["decision"],
                               r["reason"], r["policy_id"], r["policy_version"], prev])
            if r["prev_hash"] != prev or r["hash"] != hashlib.sha256(body.encode()).hexdigest():
                return {"intact": False, "broken_at": r["id"]}
            prev = r["hash"]
        return {"intact": True}

    @app.get("/stats")
    def stats(x_user_id: str = Header(), x_admin_key: str = Header(None)):
        require_admin(x_user_id, x_admin_key)
        rows = db.execute("SELECT decision, COUNT(*) n FROM audit_log GROUP BY decision").fetchall()
        viol = db.execute("SELECT user_id, resource, COUNT(*) n FROM audit_log WHERE decision='DENY' "
                          "GROUP BY user_id, resource HAVING n>=2").fetchall()
        return {"by_decision": {r["decision"]: r["n"] for r in rows}, "repeated_denials": [dict(v) for v in viol]}

    @app.get("/policies")
    def policies(x_user_id: str = Header(), x_admin_key: str = Header(None)):
        require_admin(x_user_id, x_admin_key)
        return [json.loads(r["body"]) for r in db.execute("SELECT body FROM policies ORDER BY id")]

    @app.get("/", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    def dashboard():   # the page itself is public; every data call it makes is admin-checked server-side
        built = STATIC / "index.html"
        return FileResponse(built if built.exists() else Path(__file__).parent / "dashboard.html")

    if (STATIC / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

    app.state.db = db
    return app


app = create_app(os.environ.get("DB_PATH", "zeroguard.db"))
