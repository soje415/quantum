// PHANTOM SHIELD — Batch 2: POST /scan
// Step 3 — the only place exposure data is computed. It runs ONLY after the
// gate confirms a live scan grant (identifier_hash + one-time token). Without
// that it returns 403 and reveals nothing. This is the anti-lookup guarantee
// from migration 0001 enforced in code.
//
// Body: { identifier, grantToken, kind? }
// 200  { ok: true, exposureScore, risk, summary, findings }
// 403  { ok: false, reason: "no_active_grant" }   -> client must (re)verify
//
// Note: per migration 0001, third-party (HIBP/DeHashed) results for a
// non-subscriber are REQUEST-SCOPED and are NOT written to scan_cache. Caching
// is reserved for subscriber-owned scans (added when accounts exist in Batch 3).

import {
  admin, hasActiveScanGrant, isValidEmail, isValidNigerianPhone,
  normaliseEmail, normalisePhone, psHash,
} from "../_shared/gate.ts";
import {
  dehashedLookup, Finding, hibpLookup, nigeriaIndexLookup, RiskLevel,
} from "../_shared/providers.ts";
import { json, preflight } from "../_shared/http.ts";

Deno.serve(async (req) => {
  const pf = preflight(req);
  if (pf) return pf;
  if (req.method !== "POST") return json({ ok: false, reason: "method_not_allowed" }, 405);

  let body: { identifier?: string; grantToken?: string; kind?: string };
  try { body = await req.json(); } catch { return json({ ok: false, reason: "bad_json" }, 400); }

  const raw = (body.identifier ?? "").trim();
  const grantToken = (body.grantToken ?? "").trim();
  if (!raw || !grantToken) return json({ ok: false, reason: "missing_fields" }, 400);

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

  // THE GATE. Nothing below runs without a valid, unexpired, token-bound grant.
  if (!(await hasActiveScanGrant(db, identifierHash, grantToken))) {
    return json({ ok: false, reason: "no_active_grant" }, 403);
  }

  const email = kind === "email" ? normalised : null;
  const phone = kind === "phone" ? normalised : null;

  // Fan out to every provider in parallel; each degrades gracefully if unwired.
  const [hibp, dehashed, nigeria] = await Promise.all([
    email ? hibpLookup(email) : Promise.resolve({ available: false, findings: [] }),
    dehashedLookup(email, phone),
    nigeriaIndexLookup(identifierHash),
  ]);

  const findings: Finding[] = [...hibp.findings, ...dehashed.findings, ...nigeria.findings];
  const exposureScore = scoreFrom(findings);

  return json({
    ok: true,
    exposureScore,
    risk: bandFromScore(exposureScore),
    summary: {
      total: findings.length,
      globalBreaches: findings.filter((f) => f.sourceType === "global_breach").length,
      nigerianSources: findings.filter((f) => f.sourceType !== "global_breach").length,
      providersUnavailable: [
        !hibp.available && email ? "hibp" : null,
        !dehashed.available ? "dehashed" : null,
        !nigeria.available ? "nigeria_index" : null,
      ].filter(Boolean),
    },
    findings,
  });
});

// Exposure score: 0 (clean) -> 100 (critical). Higher is worse.
function scoreFrom(findings: Finding[]): number {
  const weight: Record<RiskLevel, number> = { low: 6, medium: 14, high: 24, critical: 40 };
  const sum = findings.reduce((acc, f) => acc + weight[f.risk], 0);
  return Math.min(100, sum);
}

function bandFromScore(score: number): RiskLevel {
  if (score >= 75) return "critical";
  if (score >= 45) return "high";
  if (score >= 20) return "medium";
  return "low";
}
