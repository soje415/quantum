// PHANTOM SHIELD — Batch 1: shared gate logic for Supabase Edge Functions (Deno).
// Single source of truth for identifier normalisation, keyed hashing, OTP
// lifecycle, token-bound scan grants, and rate limiting. Imported by
// issue-challenge / verify-challenge / scan functions.

import { createClient, SupabaseClient } from "jsr:@supabase/supabase-js@2";

// --- normalisation: MUST match ps_hash() input expectations exactly ---------
export function normaliseEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

// Nigeria-only. Canonicalise to +234XXXXXXXXXX (10-digit national number).
export function normalisePhone(raw: string): string {
  let d = raw.replace(/[^\d+]/g, "");
  if (d.startsWith("+234")) d = d.slice(4);
  else if (d.startsWith("234")) d = d.slice(3);
  else if (d.startsWith("0")) d = d.slice(1);
  return "+234" + d;
}

// Reject anything that isn't a plausible Nigerian mobile number BEFORE issuing
// an OTP — stops garbage and out-of-region numbers from being hashed/charged.
export function isValidNigerianPhone(normalised: string): boolean {
  return /^\+234[789]\d{9}$/.test(normalised);
}

export function isValidEmail(normalised: string): boolean {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalised);
}

// --- keyed hash: HMAC-SHA256(pepper, normalised). MUST mirror ps_hash() in SQL.
// The pepper (PS_HASH_PEPPER) must equal the Vault secret 'hash_pepper'.
let cachedKey: CryptoKey | null = null;
async function hmacKey(): Promise<CryptoKey> {
  if (cachedKey) return cachedKey;
  const pepper = Deno.env.get("PS_HASH_PEPPER");
  if (!pepper) throw new Error("PS_HASH_PEPPER is not set");
  cachedKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pepper),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return cachedKey;
}

export async function psHash(normalised: string): Promise<string> {
  const sig = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(),
    new TextEncoder().encode(normalised),
  );
  return toHex(sig);
}

// Plain SHA-256 — used only for high-entropy values (the grant token) where a
// pepper buys nothing because there is nothing to brute-force.
async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return toHex(buf);
}

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function admin(): SupabaseClient {
  return createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { persistSession: false } },
  );
}

// --- rate limiting: sliding window over rate_events -------------------------
export async function rateLimited(
  db: SupabaseClient, bucketKey: string, maxInWindow: number, windowSeconds: number,
): Promise<boolean> {
  const since = new Date(Date.now() - windowSeconds * 1000).toISOString();
  const { count } = await db
    .from("rate_events")
    .select("*", { count: "exact", head: true })
    .eq("bucket_key", bucketKey)
    .gte("occurred_at", since);
  if ((count ?? 0) >= maxInWindow) return true;
  await db.from("rate_events").insert({ bucket_key: bucketKey });
  return false;
}

// --- OTP lifecycle ----------------------------------------------------------
function genCode(): string {
  // 6-digit numeric; cryptographically random.
  return (crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000)
    .toString().padStart(6, "0");
}

function genGrantToken(): string {
  // 256-bit opaque token, returned once to the verifying client.
  return toHex(crypto.getRandomValues(new Uint8Array(32)).buffer);
}

export interface IssueResult { ok: boolean; reason?: string; }

export async function issueChallenge(
  db: SupabaseClient,
  identifierHash: string,
  kind: "email" | "phone",
  channel: "email" | "sms",
  ttlSeconds = 600,
): Promise<{ result: IssueResult; code?: string }> {
  // Per-identifier OTP rate limit: max 3 per 15 min.
  if (await rateLimited(db, `otp:${identifierHash}`, 3, 900)) {
    return { result: { ok: false, reason: "rate_limited" } };
  }
  // Void any prior live challenge for this identifier so the partial unique
  // index (consumed_at IS NULL AND voided_at IS NULL) admits the new row.
  await db.from("verification_challenges")
    .update({ voided_at: new Date().toISOString() })
    .is("consumed_at", null)
    .is("voided_at", null)
    .eq("identifier_hash", identifierHash);

  const code = genCode();
  const codeHash = await psHash(code);
  const { error } = await db.from("verification_challenges").insert({
    identifier_hash: identifierHash,
    kind, channel,
    code_hash: codeHash,
    expires_at: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
  });
  if (error) return { result: { ok: false, reason: "insert_failed" } };
  // Caller dispatches `code` via Resend (email) or SMS provider. Never logged.
  return { result: { ok: true }, code };
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
  scanGrantExpiresAt?: string;
  scanGrantToken?: string; // returned ONCE; the scan call must present it
}

export async function verifyChallenge(
  db: SupabaseClient,
  identifierHash: string,
  kind: "email" | "phone",
  submittedCode: string,
  scanGrantSeconds = 1800,
): Promise<VerifyResult> {
  const { data: ch } = await db.from("verification_challenges")
    .select("*")
    .eq("identifier_hash", identifierHash)
    .is("consumed_at", null)
    .is("voided_at", null)
    .gt("expires_at", new Date().toISOString())
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!ch) return { ok: false, reason: "no_live_challenge" };
  if (ch.attempts >= ch.max_attempts) return { ok: false, reason: "too_many_attempts" };

  const submittedHash = await psHash(submittedCode);
  if (submittedHash !== ch.code_hash) {
    await db.from("verification_challenges")
      .update({ attempts: ch.attempts + 1 }).eq("id", ch.id);
    return { ok: false, reason: "bad_code" };
  }

  const grantToken = genGrantToken();
  const grantTokenHash = await sha256Hex(grantToken);
  const grantExpiry = new Date(Date.now() + scanGrantSeconds * 1000).toISOString();
  await db.from("verification_challenges")
    .update({ consumed_at: new Date().toISOString() }).eq("id", ch.id);
  await db.from("verified_identifiers").insert({
    identifier_hash: identifierHash, kind, challenge_id: ch.id,
    grant_token_hash: grantTokenHash,
    scan_grant_expires_at: grantExpiry,
  });
  return { ok: true, scanGrantExpiresAt: grantExpiry, scanGrantToken: grantToken };
}

// --- the gate check the scan function calls before doing ANYTHING -----------
// Requires BOTH the identifier_hash and the one-time token returned at verify
// time, so knowing an identifier is not enough to ride an open grant window.
export async function hasActiveScanGrant(
  db: SupabaseClient, identifierHash: string, grantToken: string,
): Promise<boolean> {
  if (!grantToken) return false;
  const grantTokenHash = await sha256Hex(grantToken);
  const { data } = await db.from("verified_identifiers")
    .select("id")
    .eq("identifier_hash", identifierHash)
    .eq("grant_token_hash", grantTokenHash)
    .gt("scan_grant_expires_at", new Date().toISOString())
    .limit(1)
    .maybeSingle();
  return !!data;
}
