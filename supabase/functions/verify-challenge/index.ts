// PHANTOM SHIELD — Batch 2: POST /verify-challenge
// Step 2 of the gate. Consumes an OTP and, on success, mints a ONE-TIME scan
// grant token. The raw token is returned exactly once; only its hash is stored.
// The client must present this token to /scan to see any exposure data.
//
// Body: { identifier: string, code: string, kind?: "email" | "phone" }
// 200  { ok: true, scanGrantToken, scanGrantExpiresAt }
// 400  { ok: false, reason }
// 401  { ok: false, reason: "bad_code" | "no_live_challenge" | "too_many_attempts" }

import {
  admin, isValidEmail, isValidNigerianPhone,
  normaliseEmail, normalisePhone, psHash, verifyChallenge,
} from "../_shared/gate.ts";
import { json, preflight } from "../_shared/http.ts";

Deno.serve(async (req) => {
  const pf = preflight(req);
  if (pf) return pf;
  if (req.method !== "POST") return json({ ok: false, reason: "method_not_allowed" }, 405);

  let body: { identifier?: string; code?: string; kind?: string };
  try { body = await req.json(); } catch { return json({ ok: false, reason: "bad_json" }, 400); }

  const raw = (body.identifier ?? "").trim();
  const code = (body.code ?? "").trim();
  if (!raw || !code) return json({ ok: false, reason: "missing_fields" }, 400);

  const kind: "email" | "phone" = (body.kind as "email" | "phone") ?? (raw.includes("@") ? "email" : "phone");

  let normalised: string;
  if (kind === "email") {
    normalised = normaliseEmail(raw);
    if (!isValidEmail(normalised)) return json({ ok: false, reason: "invalid_email" }, 400);
  } else {
    normalised = normalisePhone(raw);
    if (!isValidNigerianPhone(normalised)) return json({ ok: false, reason: "invalid_phone" }, 400);
  }

  const db = admin();
  const identifierHash = await psHash(normalised);
  const result = await verifyChallenge(db, identifierHash, kind, code);

  if (!result.ok) {
    const status = result.reason === "bad_code" ||
      result.reason === "no_live_challenge" ||
      result.reason === "too_many_attempts" ? 401 : 400;
    return json({ ok: false, reason: result.reason }, status);
  }

  return json({
    ok: true,
    scanGrantToken: result.scanGrantToken,
    scanGrantExpiresAt: result.scanGrantExpiresAt,
  });
});
