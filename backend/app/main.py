import hashlib, hmac, json, os, secrets, time
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .policy_engine import Policy, evaluate_access
from .opa_service import make_opa_evaluator
from . import auth
from .db import DB

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


class Login(BaseModel):
    username: str
    password: str
    otp: str | None = None


class Otp(BaseModel):
    otp: str


def create_app(db_path=":memory:", evaluator=None, auth_mode=None):
    auth_mode = auth_mode or os.environ.get("AUTH_MODE", "token")   # "header" = demo/test identity header only
    secret = (os.environ.get("JWT_SECRET") or secrets.token_hex(32)).encode()
    demo_pw, fails = os.environ.get("DEMO_PASSWORD", "demo-password"), {}
    print(f"[zeroguard] auth mode: {auth_mode}", flush=True)
    app = FastAPI(title="ZeroGuard")
    db = DB(db_path)
    print(f"[zeroguard] database: {db.kind}", flush=True)
    serial = "SERIAL PRIMARY KEY" if db.pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
    for stmt in (
        "CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT,role TEXT,status TEXT,mfa_verified INTEGER,password_hash TEXT,totp_secret TEXT)",
        "CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,user_id TEXT,compliant INTEGER)",
        "CREATE TABLE IF NOT EXISTS resources(name TEXT PRIMARY KEY,sensitivity TEXT,description TEXT)",
        "CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY,body TEXT)",
        f"CREATE TABLE IF NOT EXISTS audit_log(id {serial},ts TEXT,user_id TEXT,resource TEXT,device_id TEXT,"
        "decision TEXT,reason TEXT,policy_id TEXT,policy_version INTEGER,prev_hash TEXT,hash TEXT)"):
        db.execute(stmt)
    for col in ("password_hash", "totp_secret"):   # upgrade an older database in place
        if col not in db.columns("users"):
            db.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
    for u in SEED_USERS:   # demo seed: password follows DEMO_PASSWORD; MFA secrets are derived once and then kept
        db.execute("INSERT INTO users(id,name,role,status,mfa_verified,password_hash,totp_secret) VALUES(?,?,?,?,?,?,?) "
                   "ON CONFLICT(id) DO UPDATE SET password_hash=excluded.password_hash",
                   (*u, auth.hash_password(demo_pw), auth.new_totp_secret(secret, u[0]) if u[4] else None))
    dummy_hash = auth.hash_password(secrets.token_hex(8))   # compared against when the username does not exist
    db.executemany("INSERT INTO devices VALUES(?,?,?) ON CONFLICT DO NOTHING", SEED_DEVICES)
    db.executemany("INSERT INTO resources VALUES(?,?,?) ON CONFLICT DO NOTHING", SEED_RESOURCES)
    db.executemany("INSERT INTO policies(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                   [(p.id, json.dumps(p.__dict__)) for p in SEED_POLICIES])

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
        with db.exclusive():   # read-last-hash + insert must not interleave, or the chain forks
            row = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else "GENESIS"
            ts = datetime.now(timezone.utc).isoformat()
            body = json.dumps([ts, user_id, resource, device_id, decision, reason, pid, ver, prev])
            db.execute("INSERT INTO audit_log(ts,user_id,resource,device_id,decision,reason,policy_id,"
                       "policy_version,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (ts, user_id, resource, device_id, decision, reason, pid, ver, prev,
                        hashlib.sha256(body.encode()).hexdigest()))

    def decide(user_id, resource_name, device_id, mfa=None):
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
                   "authentication": {"mfa_verified": bool(user["mfa_verified"] if mfa is None else mfa)},   # token mode: MFA proven at login
                   "action": "READ"}
            try:
                r = evaluator(inp)
                out = (r["effect"], r["reason"], r.get("policy_id"), r.get("policy_version"))
            except Exception:             # policy engine down or invalid answer: fail closed
                out = ("DENY", "POLICY_ENGINE_UNAVAILABLE", None, None)
        log(user_id, resource_name, device_id, *out)
        return out

    def require_admin(x_user_id, x_admin_key=None):
        key = os.environ.get("ADMIN_KEY") if auth_mode == "header" else None   # header mode only; token mode relies on the signed admin role
        if key and not hmac.compare_digest(x_admin_key or "", key):
            log(x_user_id, "admin-api", None, "DENY", "Admin key missing or wrong", None, None)
            raise HTTPException(403, "Admin only")
        u = db.execute("SELECT role,status FROM users WHERE id=?", (x_user_id,)).fetchone()
        if not u or u["role"] != "admin" or u["status"] != "active":
            log(x_user_id, "admin-api", None, "DENY", "Admin route requires admin role", None, None)
            raise HTTPException(403, "Admin only")

    def identity(x_user_id, authorization):
        """Returns (user_id, mfa_proven_or_None). Token mode ignores X-User-Id completely."""
        if auth_mode == "header":
            if not x_user_id:
                raise HTTPException(401, "Missing identity")
            return x_user_id, None
        raw = authorization or ""
        claims = auth.read_token(secret, raw[7:] if raw.lower().startswith("bearer ") else "")
        u = claims and db.execute("SELECT status FROM users WHERE id=?", (claims["sub"],)).fetchone()
        if not claims or not u or u["status"] != "active":
            raise HTTPException(401, "Invalid or expired token")
        return claims["sub"], bool(claims.get("mfa"))

    def admin(x_user_id, authorization, x_admin_key):
        uid, _ = identity(x_user_id, authorization)
        require_admin(uid, x_admin_key)
        return uid

    def session_for(u, mfa):
        info = {"id": u["id"], "name": u["name"], "role": u["role"], "mfa": mfa}
        return {"token": auth.make_token(secret, {"sub": u["id"], "mfa": mfa}, 1800), "user": info}

    @app.post("/auth/login")
    def login(body: Login):
        now = time.time()
        recent = [t for t in fails.get(body.username, []) if now - t < 300]
        if len(recent) >= 5:
            raise HTTPException(429, "Too many attempts. Try again in a few minutes.")
        u = db.execute("SELECT * FROM users WHERE id=?", (body.username,)).fetchone()
        pw_ok = auth.check_password(body.password, u["password_hash"] if u and u["password_hash"] else dummy_hash)   # always hash: no user-enumeration timing
        ok, mfa = bool(u) and u["status"] == "active" and pw_ok, False
        if ok and body.otp:
            ok = bool(u["totp_secret"]) and auth.totp_ok(u["totp_secret"], body.otp.strip())
            mfa = ok
        if not ok:
            if len(fails) < 1000:
                fails[body.username] = recent + [now]
            log(body.username[:40], "login", None, "DENY", "Login failed", None, None)
            raise HTTPException(401, "Invalid credentials")
        fails.pop(body.username, None)
        return session_for(u, mfa)

    @app.post("/auth/step-up")
    def step_up(body: Otp, x_user_id: str = Header(None), authorization: str = Header(None)):
        uid, _ = identity(x_user_id, authorization)
        u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not u["totp_secret"] or not auth.totp_ok(u["totp_secret"], body.otp.strip()):
            log(uid, "step-up", None, "DENY", "Invalid MFA code", None, None)
            raise HTTPException(401, "Invalid code")
        return session_for(u, True)

    @app.get("/auth/me")
    def me(x_user_id: str = Header(None), authorization: str = Header(None)):
        uid, mfa = identity(x_user_id, authorization)
        u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return session_for(u, bool(u["mfa_verified"]) if mfa is None else mfa)["user"]

    @app.get("/auth/demo-code", include_in_schema=False)   # DEMO ONLY: makes MFA demonstrable without an authenticator app
    def demo_code(username: str):
        u = db.execute("SELECT totp_secret FROM users WHERE id=?", (username,)).fetchone()
        if os.environ.get("DEMO_MODE") != "1" or not u or not u["totp_secret"]:
            raise HTTPException(404, "Not found")
        return {"code": auth.totp(u["totp_secret"])}

    @app.post("/simulate")   # admin tool: evaluate as another user (uses their stored MFA enrolment)
    def simulate(user: str, resource: str, x_user_id: str = Header(None), authorization: str = Header(None),
                 x_admin_key: str = Header(None), x_device_id: str = Header(None)):
        admin(x_user_id, authorization, x_admin_key)
        d, reason, pid, ver = decide(user, resource, x_device_id)
        return {"decision": d, "reason": reason, "policy_id": pid, "policy_version": ver}

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
    def access_request(resource: str, x_user_id: str = Header(None), authorization: str = Header(None), x_device_id: str = Header(None)):
        uid, mfa = identity(x_user_id, authorization)
        d, reason, pid, ver = decide(uid, resource, x_device_id, mfa)
        return {"decision": d, "reason": reason, "policy_id": pid, "policy_version": ver}

    @app.get("/resources/{name}")   # Policy Enforcement Point: data returned only on ALLOW
    def protected_resource(name: str, x_user_id: str = Header(None), authorization: str = Header(None), x_device_id: str = Header(None)):
        uid, mfa = identity(x_user_id, authorization)
        d, reason, _, _ = decide(uid, name, x_device_id, mfa)
        if d == "STEP_UP_AUTHENTICATION":
            raise HTTPException(401, reason)
        if d != "ALLOW":
            raise HTTPException(403, reason)
        return {"resource": name, "data": f"(simulated contents of {name})"}

    @app.get("/audit")
    def audit(x_user_id: str = Header(None), authorization: str = Header(None), x_admin_key: str = Header(None)):
        admin(x_user_id, authorization, x_admin_key)
        return [dict(r) for r in db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")]

    @app.get("/audit/verify")
    def verify(x_user_id: str = Header(None), authorization: str = Header(None), x_admin_key: str = Header(None)):
        admin(x_user_id, authorization, x_admin_key)
        prev = "GENESIS"
        for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
            body = json.dumps([r["ts"], r["user_id"], r["resource"], r["device_id"], r["decision"],
                               r["reason"], r["policy_id"], r["policy_version"], prev])
            if r["prev_hash"] != prev or r["hash"] != hashlib.sha256(body.encode()).hexdigest():
                return {"intact": False, "broken_at": r["id"]}
            prev = r["hash"]
        return {"intact": True}

    @app.get("/stats")
    def stats(x_user_id: str = Header(None), authorization: str = Header(None), x_admin_key: str = Header(None)):
        admin(x_user_id, authorization, x_admin_key)
        rows = db.execute("SELECT decision, COUNT(*) n FROM audit_log GROUP BY decision").fetchall()
        viol = db.execute("SELECT user_id, resource, COUNT(*) n FROM audit_log WHERE decision='DENY' "
                          "GROUP BY user_id, resource HAVING COUNT(*)>=2").fetchall()
        return {"by_decision": {r["decision"]: r["n"] for r in rows}, "repeated_denials": [dict(v) for v in viol]}

    @app.get("/policies")
    def policies(x_user_id: str = Header(None), authorization: str = Header(None), x_admin_key: str = Header(None)):
        admin(x_user_id, authorization, x_admin_key)
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


app = create_app(os.environ.get("DATABASE_URL") or os.environ.get("DB_PATH", "zeroguard.db"))
