// PHANTOM SHIELD — Batch 2: exposure-lookup providers used by the scan function.
//
// Each provider is ENV-GATED: if its credentials are absent it reports
// available:false and contributes nothing, so the scan still completes
// coherently before every integration is wired. This lets the gate/flow ship
// and be tested now, with real data switched on per-provider later.
//
// IMPORTANT (per the Supabase skill's "verify against current docs" rule):
// the DeHashed and Nigeria-Index endpoints below are scaffolds. Confirm the
// exact request shape against current provider docs before enabling in prod.
// HIBP v3 is stable and implemented for real.

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface Finding {
  source: string;          // human-readable source name
  sourceType: "global_breach" | "loan_shark" | "telegram" | "paste_site" | "banned_app";
  dataClasses: string[];   // what leaked: email, password, phone, bvn, address...
  risk: RiskLevel;
  occurredAt?: string;     // ISO date if known
}

export interface ProviderResult {
  available: boolean;      // false => credentials missing / not yet wired
  findings: Finding[];
}

// --- [A] HIBP — email only, real implementation ----------------------------
export async function hibpLookup(email: string): Promise<ProviderResult> {
  const key = Deno.env.get("HIBP_API_KEY");
  if (!key) return { available: false, findings: [] };

  const res = await fetch(
    `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
    { headers: { "hibp-api-key": key, "user-agent": "PhantomShield" } },
  );
  if (res.status === 404) return { available: true, findings: [] }; // clean
  if (!res.ok) return { available: false, findings: [] };

  const breaches = await res.json() as Array<{
    Name: string; BreachDate?: string; DataClasses?: string[];
  }>;
  return {
    available: true,
    findings: breaches.map((b) => ({
      source: b.Name,
      sourceType: "global_breach" as const,
      dataClasses: (b.DataClasses ?? []).map((d) => d.toLowerCase()),
      risk: riskFromClasses(b.DataClasses ?? []),
      occurredAt: b.BreachDate,
    })),
  };
}

// --- [B] DeHashed — email + phone deep lookup (SCAFFOLD — verify endpoint) --
export async function dehashedLookup(
  _email: string | null, _phone: string | null,
): Promise<ProviderResult> {
  const key = Deno.env.get("DEHASHED_API_KEY");
  if (!key) return { available: false, findings: [] };
  // TODO(verify-docs): wire the current DeHashed search API and map entries to
  // Finding[]. Left unavailable until the exact request shape is confirmed so
  // we never ship a confidently-wrong API call.
  return { available: false, findings: [] };
}

// --- [C] Nigeria Exposure Index — proprietary, phone/email/nin hash lookup --
// Queried by KEYED HASH only (never raw identifiers). Reads an internal table
// that does not exist yet; returns empty until that index is built.
export async function nigeriaIndexLookup(
  _identifierHash: string,
): Promise<ProviderResult> {
  // TODO(batch-3): query the Nigeria Exposure Index table by identifier_hash.
  return { available: false, findings: [] };
}

function riskFromClasses(classes: string[]): RiskLevel {
  const c = classes.map((x) => x.toLowerCase());
  const has = (...needles: string[]) => needles.some((n) => c.some((x) => x.includes(n)));
  if (has("bank", "bvn", "credit", "financial")) return "critical";
  if (has("password")) return "high";
  if (has("phone", "address", "physical")) return "medium";
  return "low";
}
