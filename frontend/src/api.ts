export type Decision = "ALLOW" | "DENY" | "STEP_UP_AUTHENTICATION";
export interface AuditRow { id: number; ts: string; user_id: string; resource: string; device_id: string | null;
  decision: Decision; reason: string; policy_id: string | null; policy_version: number | null }
export interface Policy { id: string; name: string; effect: Decision; roles: string[]; resources: string[]; status: string; version: number }
export interface Stats { by_decision: Record<string, number>; repeated_denials: { user_id: string; resource: string; n: number }[] }
export interface AccessResult { decision: Decision; reason: string; policy_id: string | null; policy_version: number | null }

// Demo identity: the server derives role/MFA/device from its own database. Replaced by OIDC tokens in the next phase.
export const session = { user: "root", key: "" };

export async function api<T>(path: string, init: RequestInit = {}, asUser?: string, device?: string): Promise<T> {
  const headers: Record<string, string> = { "X-User-Id": asUser ?? session.user };
  if (session.key) headers["X-Admin-Key"] = session.key;
  if (device) headers["X-Device-Id"] = device;
  const r = await fetch(path, { ...init, headers });
  const j: unknown = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${r.status}: ${(j as { detail?: string }).detail ?? "error"}`);
  return j as T;
}
