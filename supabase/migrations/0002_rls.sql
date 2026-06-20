-- PHANTOM SHIELD — Batch 1: Row Level Security
-- The gate tables (verification_challenges, verified_identifiers, rate_events),
-- scan_cache, and the review queue are SERVER-ONLY — touched exclusively by the
-- service_role inside edge functions. The anon/authenticated client can never
-- read another person's findings, and can never read target data without having
-- gone through an edge function that checked the gate.

alter table verification_challenges enable row level security;
alter table verified_identifiers    enable row level security;
alter table rate_events             enable row level security;
alter table users                   enable row level security;
alter table scan_cache              enable row level security;
alter table threat_indicators       enable row level security;
alter table notice_drafts           enable row level security;
alter table notice_dispatch_log     enable row level security;
alter table monitoring_alerts       enable row level security;
alter table dpo_directory           enable row level security;
alter table breach_sources          enable row level security;

-- --- GATE TABLES: no client access at all. service_role bypasses RLS, so the
--     absence of any permissive policy means anon/authenticated get nothing. ---
-- (intentionally no policies on verification_challenges / verified_identifiers / rate_events)

-- --- USERS: a signed-in user sees only their own row. ---
create policy users_self_select on users
  for select using (auth.uid() = id);
create policy users_self_update on users
  for update using (auth.uid() = id);

-- --- THREAT INDICATORS: subscriber sees only their own findings. ---
create policy threat_self_select on threat_indicators
  for select using (auth.uid() = user_id);

-- --- NOTICE DRAFTS: subscriber may SEE their notices' status, never edit. ---
create policy notice_self_select on notice_drafts
  for select using (auth.uid() = user_id);

-- --- DISPATCH LOG: subscriber sees dispatch records for their own drafts. ---
create policy dispatch_self_select on notice_dispatch_log
  for select using (
    exists (select 1 from notice_drafts d
            where d.id = notice_dispatch_log.draft_id and d.user_id = auth.uid())
  );

-- --- MONITORING ALERTS: subscriber-scoped. ---
create policy alerts_self_select on monitoring_alerts
  for select using (auth.uid() = user_id);

-- --- DPO DIRECTORY + BREACH SOURCES: readable reference data, no PII. ---
create policy dpo_public_read    on dpo_directory   for select using (true);
create policy sources_public_read on breach_sources for select using (true);

-- scan_cache has NO client policy: it is read/written only by edge functions
-- (service_role) during a gated scan. Clients receive results in the function
-- response, never by querying the table directly.
