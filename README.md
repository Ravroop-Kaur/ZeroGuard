# ZeroGuard (backend MVP)
Policy engine + enforcement point + hash-chained audit log. Dashboard (React) is the next step.

    cd backend
    pip install -r requirements.txt
    pytest -q
    uvicorn app.main:app --reload     # docs at http://127.0.0.1:8000/docs

Dashboard: open http://127.0.0.1:8000/ (choose "root" to view; "aman" shows the admin-only block).
Demo: `X-User-Id` header stands in for a verified session (use an OIDC/JWT login in a real system).
Role, MFA status and device posture are read from the server database, never from the request.
Seed users: aman (developer), priya (hr), root (admin, non-compliant device), ravi (intern), sam (disabled), neha (hr, no MFA).
Try: POST /access-request?resource=hr_db with headers X-User-Id: priya, X-Device-Id: d-priya  -> ALLOW

## Policies in OPA (Phase 2)
Rego lives in `policies/` (rules in `authorization.rego`, policy data in `data.json`). Set `OPA_URL` and the backend asks OPA;
if OPA is unreachable or returns anything invalid, access is denied (fail closed). Without `OPA_URL` a Python fallback is used.

    opa test policies/ -v                      # Rego unit tests
    cd infrastructure && docker compose up --build
    # dashboard/API: http://127.0.0.1:8000/   (OPA bound to 127.0.0.1:8181)
`policies/data.json` must match `SEED_POLICIES` in `backend/app/main.py` (a test checks this).

## Deploy on Render (free web service, Docker)
1. Push this folder to GitHub (repo root must contain `Dockerfile` and `render.yaml`).
2. Render dashboard: New > Blueprint > pick the repo. It builds the Dockerfile (OPA + FastAPI in one container).
3. Open the service > Environment, copy the generated `ADMIN_KEY`. Paste it into the dashboard's key box and view as `root`.
Notes: free services sleep after ~15 min idle, and the SQLite file is wiped on restart. Identity is still the demo header; replace with Keycloak/OIDC before real use.

## React dashboard
    cd frontend && npm install
    npm run typecheck          # TypeScript check
    npm run dev                # http://localhost:5173 (proxies API to FastAPI on :8000; run the backend too)
    npm run build              # writes backend/static; FastAPI then serves it at http://127.0.0.1:8000/
Without a build, the plain-HTML dashboard is served instead. The Docker image builds the React app automatically.

## Debugging a deployed instance
- Build log shows `PYTEST FAILED` / `REGO TESTS FAILED` lines if checks fail (build still completes).
- Runtime log shows `[zeroguard] policy engine: opa`, or `!!! OPA did not start`.
- `GET /health/policy` reports whether OPA is reachable. `GET /health` is the Render health check.
- Optional env `DB_PATH` moves the SQLite file (needs a paid persistent disk to survive restarts).
