package zeroguard.authorization_test

import data.zeroguard.authorization as authz
import rego.v1

mk(role, status, mfa, comp, res, sens) := {
	"user": {"id": "u", "role": role, "status": status},
	"resource": {"name": res, "sensitivity": sens},
	"device": {"compliant": comp},
	"authentication": {"mfa_verified": mfa},
}

test_hr_allowed if {
	d := authz.decision with input as mk("hr", "active", true, true, "hr_db", "high")
	d.effect == "ALLOW"
	d.policy_id == "P001"
}

test_developer_denied_hr_db if {
	d := authz.decision with input as mk("developer", "active", true, true, "hr_db", "high")
	d.effect == "DENY"
	d.policy_id == "P002"
}

test_missing_mfa_steps_up if {
	d := authz.decision with input as mk("hr", "active", false, true, "hr_db", "high")
	d.effect == "STEP_UP_AUTHENTICATION"
}

test_admin_noncompliant_denied if {
	d := authz.decision with input as mk("admin", "active", true, false, "source_code", "high")
	d.policy_id == "P004"
}

test_intern_denied_source_code if {
	d := authz.decision with input as mk("intern", "active", true, true, "source_code", "high")
	d.policy_id == "P005"
}

test_default_deny if {
	d := authz.decision with input as mk("intern", "active", true, true, "hr_db", "high")
	d.effect == "DENY"
	d.policy_id == null
}

test_inactive_and_noncompliant_has_single_decision if {
	d := authz.decision with input as mk("hr", "disabled", true, false, "hr_db", "high")
	d.reason == "Inactive or unknown account"
}

test_missing_device_fails_closed if {
	bad := {"user": {"id": "u", "role": "hr", "status": "active"}, "resource": {"name": "wiki", "sensitivity": "low"}, "authentication": {"mfa_verified": true}}
	d := authz.decision with input as bad
	d.reason == "INVALID_INPUT"
}

test_deny_beats_allow if {
	pols := [
		{"id": "A", "name": "allow all", "effect": "ALLOW", "roles": [], "resources": [], "status": "active", "version": 1},
		{"id": "B", "name": "deny all", "effect": "DENY", "roles": [], "resources": [], "status": "active", "version": 2},
	]
	d := authz.decision with input as mk("hr", "active", true, true, "wiki", "low") with data.zeroguard.policies as pols
	d.effect == "DENY"
	d.policy_version == 2
}

test_disabled_policy_ignored if {
	pols := [{"id": "A", "name": "allow all", "effect": "ALLOW", "roles": [], "resources": [], "status": "disabled", "version": 1}]
	d := authz.decision with input as mk("hr", "active", true, true, "wiki", "low") with data.zeroguard.policies as pols
	d.effect == "DENY"
}
