// PHANTOM SHIELD — Batch 2: OTP delivery. The RAW (normalised) identifier is
// used here and ONLY here at request time; it is never persisted — only its
// keyed hash is. The 6-digit code is never logged.
//
// Channels:
//   email -> Resend     (RESEND_API_KEY, PS_OTP_EMAIL_FROM)
//   sms   -> Sendchamp   (SENDCHAMP_API_KEY, SENDCHAMP_SENDER)
//
// If a provider key is absent the dispatch is treated as "not configured": we
// surface that to the caller rather than silently dropping the OTP.

export interface DispatchResult {
  delivered: boolean;
  reason?: "not_configured" | "provider_error";
}

export async function dispatchOtp(
  channel: "email" | "sms",
  rawNormalisedTarget: string,
  code: string,
): Promise<DispatchResult> {
  return channel === "email"
    ? await sendEmail(rawNormalisedTarget, code)
    : await sendSms(rawNormalisedTarget, code);
}

async function sendEmail(to: string, code: string): Promise<DispatchResult> {
  const key = Deno.env.get("RESEND_API_KEY");
  const from = Deno.env.get("PS_OTP_EMAIL_FROM") ?? "Phantom Shield <noreply@phantomshield.ng>";
  if (!key) return { delivered: false, reason: "not_configured" };

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from,
      to: [to],
      subject: `${code} is your Phantom Shield verification code`,
      html: otpEmailHtml(code),
    }),
  });
  return res.ok ? { delivered: true } : { delivered: false, reason: "provider_error" };
}

async function sendSms(to: string, code: string): Promise<DispatchResult> {
  const key = Deno.env.get("SENDCHAMP_API_KEY");
  const sender = Deno.env.get("SENDCHAMP_SENDER") ?? "PhantomShd";
  if (!key) return { delivered: false, reason: "not_configured" };

  // Sendchamp expects the number without the leading "+".
  const msisdn = to.replace(/^\+/, "");
  const res = await fetch("https://api.sendchamp.com/api/v1/sms/send", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      to: [msisdn],
      message: `Your Phantom Shield code is ${code}. It expires in 10 minutes. We will never call to ask for it.`,
      sender_name: sender,
      route: "dnd",
    }),
  });
  return res.ok ? { delivered: true } : { delivered: false, reason: "provider_error" };
}

function otpEmailHtml(code: string): string {
  return `
  <div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto">
    <h2 style="margin:0 0 8px">Confirm it's you</h2>
    <p style="color:#444;margin:0 0 16px">
      Someone asked to scan this contact for data-leak exposure. If it was you,
      enter the code below. We won't show anyone's exposure without this step.
    </p>
    <div style="font-size:32px;font-weight:700;letter-spacing:6px;padding:16px;
                background:#0f172a;color:#fff;text-align:center;border-radius:8px">
      ${code}
    </div>
    <p style="color:#888;font-size:13px;margin:16px 0 0">
      This code expires in 10 minutes. If you didn't request it, ignore this email.
    </p>
  </div>`;
}
