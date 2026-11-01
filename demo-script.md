# Demo script (about 5 minutes)

Open the dashboard and sign in as `root` with the `DEMO_PASSWORD` from Render's Environment tab (use **Show demo MFA code** to verify MFA). Use the **Simulator** tab for each step, then check **Access monitoring**.

## Part 1: normal and blocked access
| Step | User / Device / Resource | Expected | Say |
|---|---|---|---|
| 1 | priya / d-priya / hr_db | ALLOW (P001) | HR with MFA on a compliant device is allowed. |
| 2 | aman / d-aman / hr_db | DENY (P002) | A developer asking for HR data is blocked by an explicit deny. |
| 3 | neha / d-neha / hr_db | STEP_UP (P003) | Same role as priya, but MFA is missing, so the system asks for stronger authentication. |
| 4 | root / d-root / source_code | DENY (P004) | Even an admin is denied on a non-compliant device. |
| 5 | ravi / d-ravi / source_code | DENY (P005) | Interns cannot reach source code. |
| 6 | ravi / d-ravi / wiki | ALLOW (P007) | Low-sensitivity resources stay easy to use. |
| 7 | sam / (any) / wiki | DENY | Disabled account. |
| 8 | priya / d-aman / hr_db | DENY (default) | A device that isn't the user's own counts as non-compliant. |

## Part 2: attack and defense
1. As `aman`, run `aman / d-aman / hr_db` **three more times** (an unauthorised user keeps trying).
2. Open **Overview**: *Repeated denials* now lists `aman → hr_db`.
3. Open **Access monitoring**, filter to DENY, search `aman`: every attempt shows time, reason, policy ID and version.
4. Click **Export CSV** to show the evidence can be handed to a reviewer.

## Part 3: enforcement is on the server
Open `/docs`. Run `POST /auth/login` as `aman` (password from Render, leave `otp` empty) and copy the `token`. In `GET /resources/{name}`, set `authorization` to `Bearer <token>`, `x-device-id` to `d-aman`, name `hr_db`: **403**. Change the name to `wiki`: **200**. Then say the dashboard has no special access: it calls the same API. Finally, send `x-user-id: root` with no token: **401**. A forged header is ignored.

## Part 4: real login and MFA
1. Sign out, then sign in as `priya` with the password only. The top bar shows **MFA not verified**.
2. In the Simulator, click **Request access** for `hr_db` with `d-priya`: **Step-up**. Same user, same device, but MFA was not proven in this session.
3. Click **Show demo MFA code** on the login page (or use an authenticator app), enter the code in the top bar and press **Verify**. Request `hr_db` again: **Allowed**.
4. Sign in as `aman`: the dashboard says *Administrators only*, and the denied admin call is logged.

## Part 5 (optional, local only): tamper detection
After running locally, edit the database directly:
```
python -c "import sqlite3;c=sqlite3.connect('zeroguard.db');c.execute(\"UPDATE audit_log SET decision='ALLOW' WHERE id=1\");c.commit()"
```
Refresh the dashboard: *Audit log integrity* reports tampering at event 1.

Take screenshots of Overview, Access monitoring and the Simulator result and put them in `docs/screenshots/`.
