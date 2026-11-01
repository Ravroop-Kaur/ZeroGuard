# ZeroGuard — Zero Trust Access Policy Tracker

ZeroGuard decides whether a user may access a resource using **identity status, role, MFA state and device posture**, enforces that decision at the resource, and records every decision with the policy ID and version that produced it. Policies are written in **Rego** and evaluated by **Open Policy Agent (OPA)**.

> Portfolio prototype, not a production-certified system. Device posture is **simulated**, and identity is a **demo header** (see [Known limitations](#known-limitations)).

**Live demo:** `<your-render-url>` (free tier: first load after idle takes ~1 minute; data resets on restart) · **Demo walkthrough:** [docs/demo-script.md](docs/demo-script.md) · **Threat model:** [docs/threat-model.md](docs/threat-model.md)

## What it demonstrates
- **Policy as code:** rules live in `policies/` (Rego + data), separate from application code, with 10 Rego unit tests.
- **Deny by default, deterministic precedence:** `DENY > STEP_UP_AUTHENTICATION > ALLOW`; missing or malformed input is denied.
- **Real enforcement:** `GET /resources/{name}` returns data only on `ALLOW` (403 on deny, 401 on step-up). The frontend cannot bypass it.
- **Trusted context:** role, MFA and device posture are read from the server database, never from the request.
- **Fail closed:** if OPA is down, times out or returns something invalid, access is denied (`POLICY_ENGINE_UNAVAILABLE`).
- **Audit evidence:** each decision stores user, resource, device, reason, policy ID and version in a **hash-chained log**; `/audit/verify` detects edits.
- **Admin dashboard (React + TypeScript):** overview charts, repeated-denial flags, searchable audit log with CSV export, policy list, request simulator.

## Architecture
```mermaid
flowchart LR
  U[Browser: React dashboard] -->|HTTPS| API[FastAPI]
  API -->|server-side lookup| DB[(SQLite: users, devices, resources, policies, audit_log)]
  API -->|structured input| OPA[OPA + Rego policies]
  OPA -->|ALLOW / DENY / STEP_UP + reason + policy version| API
  API --> PEP{{Policy Enforcement Point<br/>GET /resources/name}}
  PEP -->|data only on ALLOW| U
  API -->|hash-chained record| DB
```
One Docker container runs FastAPI (public) and OPA (listening on `127.0.0.1` only). The React build is served by FastAPI.

## Decision flow
1. Request arrives with a user ID, optional device ID and a resource name.
2. FastAPI looks up the user, device and resource in the database and builds the OPA input.
3. OPA evaluates `data.zeroguard.policies` and returns `{effect, reason, policy_id, policy_version}`.
4. The backend validates the answer (allow-listed effects). Any error becomes `DENY`.
5. The PEP enforces it, and the decision is appended to the audit log.

## Policies (seed data in `policies/data.json`)
| ID | Effect | Rule |
|---|---|---|
| P001 | ALLOW | HR → `hr_db` with MFA and a compliant device |
| P002 | DENY | Developers → `hr_db` |
| P003 | STEP_UP | High-sensitivity resource without MFA |
| P004 | DENY | Admin on a non-compliant device, sensitivity medium or higher |
| P005 | DENY | Interns → `source_code` |
| P006 | ALLOW | Developers/admins → `source_code` with MFA and compliant device |
| P007 | ALLOW | Anyone → `wiki` |

Seed users: `aman` (developer), `priya` (HR), `root` (admin, non-compliant device), `ravi` (intern), `sam` (HR, disabled), `neha` (HR, no MFA).

## API
| Method | Path | Purpose |
|---|---|---|
| POST | `/access-request?resource=…` | Evaluate and log a decision |
| GET | `/resources/{name}` | Protected resource (PEP) |
| GET | `/audit`, `/audit/verify`, `/stats`, `/policies` | Admin only (signed token with the admin role) |
| POST | `/auth/login`, `/auth/step-up`, `/simulate` (admin) | Sign in, upgrade MFA, evaluate as another user |
| GET | `/health`, `/health/policy` | Liveness and policy-engine reachability |

Interactive docs at `/docs`. Identity comes from a signed bearer token (`POST /auth/login`, `/auth/step-up`); `X-Device-Id` is the simulated device. `AUTH_MODE=header` (tests only) accepts `X-User-Id` instead.

## Run it
**Deploy (Docker, Render):** push the repo, create a Render Blueprint from `render.yaml`, Render creates a free PostgreSQL database and links it through `DATABASE_URL`. Copy `DEMO_PASSWORD` from the service environment and sign in as `root`. The build log runs the backend tests and Rego tests.

**Locally (no Docker):**
```
cd backend && pip install -r requirements.txt && python -m pytest -q
python -m uvicorn app.main:app --reload            # http://127.0.0.1:8000
cd ../frontend && npm install && npm run build      # optional: React UI served by FastAPI
opa test policies policies/tests -v                 # optional: Rego tests
```

## Testing
- 34 backend tests (pytest, also run against PostgreSQL): every policy outcome, enforcement, admin protection, tamper detection, OPA failure modes.
- 10 Rego tests (`opa test`): precedence, default deny, invalid input, disabled policies.
- Both run automatically in the Docker build and passed on Render.

## Known limitations
- **Login is built in (scrypt passwords, TOTP MFA, signed 30-minute tokens), not an enterprise identity provider.** All seeded demo users share one password, and `DEMO_MODE` shows MFA codes on the login page. Next step: OIDC (Keycloak or a hosted provider).
- **Device posture is simulated** (seeded flags), not from endpoint management.
- **Database:** PostgreSQL when `DATABASE_URL` is set (Render), SQLite otherwise (local, tests). The schema is created at startup; there are no Alembic migrations yet. Login lockout counters are in memory (reset on restart, not shared between instances).
- No sessions or revocation, risk scoring, rate limiting, or policy editing from the UI yet.
- The audit hash chain detects edits but does not stop someone with full database write access from rebuilding it.

## Roadmap
Alembic migrations → OIDC login → sessions and revocation → risk signals → policy versioning UI → rate limiting.
