# Demo script (about 5 minutes)

Open the dashboard, paste the admin key, view as `root`. Use the **Simulator** tab for each step, then check **Access monitoring**.

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
Open `/docs`, expand `GET /resources/{name}`, click *Try it out*, set `x-user-id: aman`, `x-device-id: d-aman`, name `hr_db`: **403**. Change the name to `wiki`: **200**. Then say the dashboard has no role in this: the resource itself checks the policy.

## Part 4: admin protection
Switch **Viewing as** to `aman`: admin data fails with 403, and the denied attempt is also logged.

## Part 5 (optional, local only): tamper detection
After running locally, edit the database directly:
```
python -c "import sqlite3;c=sqlite3.connect('zeroguard.db');c.execute(\"UPDATE audit_log SET decision='ALLOW' WHERE id=1\");c.commit()"
```
Refresh the dashboard: *Audit log integrity* reports tampering at event 1.

Take screenshots of Overview, Access monitoring and the Simulator result and put them in `docs/screenshots/`.
