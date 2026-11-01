package zeroguard.authorization

import rego.v1

# Precedence: DENY > STEP_UP_AUTHENTICATION > ALLOW. Default DENY. Invalid input fails closed.
# Policies are data (data.zeroguard.policies); the same model the dashboard lists.

sens := {"low": 1, "medium": 2, "high": 3}

default decision := {
	"effect": "DENY",
	"reason": "No applicable allow policy (default deny)",
	"policy_id": null,
	"policy_version": null,
}

valid_input if {
	is_string(input.user.role)
	is_string(input.user.status)
	is_string(input.resource.name)
	sens[input.resource.sensitivity]
	is_boolean(input.device.compliant)
	is_boolean(input.authentication.mfa_verified)
}

role_ok(p) if count(p.roles) == 0

role_ok(p) if input.user.role in p.roles

res_ok(p) if count(p.resources) == 0

res_ok(p) if input.resource.name in p.resources

mfa_ok(p) if object.get(p, "mfa_verified", null) == null

mfa_ok(p) if p.mfa_verified == input.authentication.mfa_verified

dev_ok(p) if object.get(p, "device_compliant", null) == null

dev_ok(p) if p.device_compliant == input.device.compliant

sens_ok(p) if object.get(p, "min_sensitivity", null) == null

sens_ok(p) if sens[input.resource.sensitivity] >= p.min_sensitivity

applies(p) if {
	p.status == "active"
	role_ok(p)
	res_ok(p)
	mfa_ok(p)
	dev_ok(p)
	sens_ok(p)
}

matched := {p.id: p | some p in data.zeroguard.policies; applies(p)}

effects := {p.effect | some p in matched}

chosen := "DENY" if "DENY" in effects else := "STEP_UP_AUTHENTICATION" if "STEP_UP_AUTHENTICATION" in effects else := "ALLOW" if "ALLOW" in effects

# lowest policy id wins among policies with the chosen effect, so output is deterministic
winner(effect) := ids[0] if ids := sort([p.id | some p in matched; p.effect == effect])

decision := {"effect": "DENY", "reason": "INVALID_INPUT", "policy_id": null, "policy_version": null} if not valid_input

decision := {"effect": "DENY", "reason": "Inactive or unknown account", "policy_id": null, "policy_version": null} if {
	valid_input
	input.user.status != "active"
}

decision := d if {
	valid_input
	input.user.status == "active"
	chosen
	p := matched[winner(chosen)]
	d := {"effect": chosen, "reason": p.name, "policy_id": p.id, "policy_version": p.version}
}
