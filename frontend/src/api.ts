export type Decision = "ALLOW" | "DENY" | "STEP_UP_AUTHENTICATION";
export interface AuditRow { id: number; ts: string; user_id: string; resource: string; device_id: string | null;
  decision: Decision; reason: string; policy_id: string | null; policy_version: number | null }
export interface Policy { id: string; name: string; effect: Decision; roles: string[]; resources: string[]; status: string; version: number }
export interface Stats { by_decision: Record<string, number>; repeated_denials: { user_id: string; resource: string; n: number }[] }
export interface AccessResult { decision: Decision; reason: string; policy_id: string | null; policy_version: number | null }
export interface Me { id: string; name: string; role: string; mfa: boolean }
export interface Session { token: string; user: Me }

// Short-lived signed token kept for this browser tab only. The server derives identity, role and MFA state from it.
const KEY = "zg_token";
export const getToken = () => sessionStorage.getItem(KEY) ?? "";
export const setToken = (t: string) => (t ? sessionStorage.setItem(KEY, t) : sessionStorage.removeItem(KEY));

export async function api<T>(path: string, init: RequestInit = {}, device?: string): Promise<T> {
  const headers: Record<string, string> = {};
  const t = getToken();
  if (t) headers.Authorization = `Bearer ${t}`;
  if (device) headers["X-Device-Id"] = device;
  if (init.body) headers["Content-Type"] = "application/json";
  const r = await fetch(path, { ...init, headers });
  const j: unknown = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${r.status}: ${(j as { detail?: string }).detail ?? "error"}`);
  return j as T;
}
export const login = (username: string, password: string, otp?: string) =>
  api<Session>("/auth/login", { method: "POST", body: JSON.stringify({ username, password, otp: otp || null }) });
export const stepUp = (otp: string) => api<Session>("/auth/step-up", { method: "POST", body: JSON.stringify({ otp }) });
