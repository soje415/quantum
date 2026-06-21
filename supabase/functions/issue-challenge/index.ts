// PHANTOM SHIELD — Batch 2: POST /issue-challenge
// Step 1 of the gate. Takes a raw email/phone, validates + rate-limits, issues
// an OTP, and dispatches it. Returns NOTHING about the target's exposure — the
// existence of a challenge is the only signal, by design (anti-lookup).
//
// Body: { identifier: string, kind?: "email" | "phone" }
// 200  { ok: true, channel }          OTP issued + dispatched
// 400  { ok: false, reason }          bad input
// 429  { ok: false, reason: "rate_limited" }
// 502  { ok: false, reason: "dispatch_failed" | "dispatch_not_configured" }

import {
  admin, issueChallenge, isValidEmail, isValidNigerianPhone,
  normaliseEmail, normalisePhone, psHash, rateLimited,
} from "../_shared/gate.ts";
import { dispatchOtp } from "../_shared/dispatch.ts";
import { clientIp, json, preflight } from "../_shared/http.ts";

Deno.serve(async (req) => {
  const pf = preflight(req);
  if (pf) return pf;
  if (req.method !== "POST") return json({ ok: false, reason: "method_not_allowed" }, 405);

  let body: { identifier?: string; kind?: string };
  try { body = await req.json(); } catch { return json({ ok: false, reason: "bad_json" }, 400); }

  const raw = (body.identifier ?? "").trim();
  if (!raw) return json({ ok: false, reason: "missing_identifier" }, 400);

  // Infer kind from shape unless explicitly given.
  const looksEmail = raw.includes("@");
  const kind: "email" | "phone" = (body.kind as "email" | "phone") ?? (looksEmail ? "email" : "phone");

  let normalised: string;
  if (kind === "email") {
    normalised = normaliseEmail(raw);
    if (!isValidEmail(normalised)) return json({ ok: false, reason: "invalid_email" }, 400);
  } else {
    normalised = normalisePhone(raw);
    if (!isValidNigerianPhone(normalised)) return json({ ok: false, reason: "invalid_phone" }, 400);
  }

  const db = admin();

  // Per-IP throttle so the free scan can't be scripted into bulk enumeration.
  const ipHash = await psHash(clientIp(req));
  if (await rateLimited(db, `ip:${ipHash}`, 10, 900)) {
    return json({ ok: false, reason: "rate_limited" }, 429);
  }

  const identifierHash = await psHash(normalised);
  const channel: "email" | "sms" = kind === "email" ? "email" : "sms";

  const { result, code } = await issueChallenge(db, identifierHash, kind, channel);
  if (!result.ok) {
    const status = result.reason === "rate_limited" ? 429 : 400;
    return json({ ok: false, reason: result.reason }, status);
  }

  const dispatch = await dispatchOtp(channel, normalised, code!);
  if (!dispatch.delivered) {
    const reason = dispatch.reason === "not_configured" ? "dispatch_not_configured" : "dispatch_failed";
    return json({ ok: false, reason }, 502);
  }

  // Dev-only escape hatch: return the OTP in the response when explicitly
  // enabled, so the flow is testable before Resend/Sendchamp are wired.
  const debug = Deno.env.get("PS_DEBUG_RETURN_OTP") === "true"
    ? { debug_code: code } : {};
  return json({ ok: true, channel, ...debug });
});
