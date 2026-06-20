-- PHANTOM SHIELD — Batch 1: Database Foundation
-- Includes the two non-negotiable guardrails as first-class schema:
--   1. Verification gate  -> verification_challenges + verified_identifiers
--   2. Review queue        -> notice_drafts (status), notice_dispatch_log
-- Conventions: snake_case, UUID PKs, KEYED-hashed identifiers only (never raw
-- phone/email in queryable columns), RLS on every user-facing table.

create extension if not exists "pgcrypto";   -- gen_random_uuid(), digest(), hmac()
create extension if not exists "citext";     -- case-insensitive email where needed
create extension if not exists "supabase_vault"; -- pepper storage for ps_hash()
create extension if not exists "pg_cron";    -- TTL reaper for ephemeral tables

-- ---------------------------------------------------------------------------
-- ENUMS
-- ---------------------------------------------------------------------------
create type subscription_status as enum ('free', 'active', 'past_due', 'cancelled');
create type identifier_kind     as enum ('email', 'phone');
create type source_type         as enum ('global_breach','loan_shark','telegram','paste_site','banned_app');
create type risk_level          as enum ('low','medium','high','critical');
create type letter_type         as enum ('ndpa','fccpc','hard_copy');
create type notice_status       as enum ('draft','in_review','approved','rejected','dispatched','responded','resolved');
create type challenge_channel   as enum ('email','sms');

-- ---------------------------------------------------------------------------
-- HASH HELPER  (KEYED hash — the anti-reversal guarantee)
-- A plain SHA-256 of a phone/email is trivially reversible (low entropy), so a
-- DB leak would expose every identifier. We use HMAC-SHA256 with a server-side
-- pepper held in Vault. The SAME pepper string must be set as the edge-function
-- secret PS_HASH_PEPPER so ps_hash() (SQL) and psHash() (gate.ts) agree byte-for-byte.
--
-- One-time setup (run once per project, value kept out of source control):
--   select vault.create_secret('<your-long-random-pepper>', 'hash_pepper');
-- and:  supabase secrets set PS_HASH_PEPPER=<the same value>
--
-- STABLE (not IMMUTABLE): it reads the pepper from Vault at call time. It is
-- therefore intentionally NOT used in any index predicate.
-- ---------------------------------------------------------------------------
create or replace function ps_hash(p_normalised text)
returns text language plpgsql stable as $$
declare
  v_pepper text;
begin
  select decrypted_secret into v_pepper
  from vault.decrypted_secrets
  where name = 'hash_pepper'
  limit 1;

  if v_pepper is null then
    raise exception 'ps_hash: vault secret "hash_pepper" is not set';
  end if;

  return encode(hmac(p_normalised, v_pepper, 'sha256'), 'hex');
end;
$$;

-- ===========================================================================
-- 1. VERIFICATION GATE  (Batch 1 — the anti-lookup guarantee)
-- ===========================================================================

-- A challenge is an OTP issued to a normalised identifier. NO target data is ever
-- computed or returned until a matching challenge is consumed. This table is the
-- chokepoint the whole product depends on.
-- Liveness = consumed_at IS NULL AND voided_at IS NULL AND expires_at > now().
--   consumed_at -> set when successfully verified.
--   voided_at   -> set when superseded by a newer challenge for the same identifier.
create table verification_challenges (
  id              uuid primary key default gen_random_uuid(),
  identifier_hash text        not null,
  kind            identifier_kind not null,
  channel         challenge_channel not null,
  code_hash       text        not null,            -- OTP is keyed-hashed, never stored raw
  attempts        smallint    not null default 0,
  max_attempts    smallint    not null default 5,
  consumed_at     timestamptz,                     -- set when successfully verified
  voided_at       timestamptz,                     -- set when superseded by a newer issue
  expires_at      timestamptz not null,            -- short, e.g. now()+10min
  created_at      timestamptz not null default now()
);
-- Only one NON-RETIRED challenge per identifier. Predicate is IMMUTABLE (no now()):
-- expiry is enforced in the query WHERE clause, supersession sets voided_at.
create unique index uq_live_challenge
  on verification_challenges (identifier_hash)
  where consumed_at is null and voided_at is null;
create index ix_challenge_lookup on verification_challenges (identifier_hash, created_at desc);

-- A successful verification grants a short-lived right to scan THIS identifier.
-- The grant is bound to a one-time token: verify-challenge returns the raw token
-- to the verifying client, and only its hash is stored here. The scan path must
-- present that token AND match the identifier_hash, so a third party who merely
-- knows the identifier cannot ride someone else's open grant window.
create table verified_identifiers (
  id              uuid primary key default gen_random_uuid(),
  identifier_hash text        not null,
  kind            identifier_kind not null,
  challenge_id    uuid        not null references verification_challenges(id),
  grant_token_hash text       not null,            -- sha256 of the one-time grant token
  user_id         uuid,                            -- linked once an account exists
  verified_at     timestamptz not null default now(),
  scan_grant_expires_at timestamptz not null,      -- e.g. now()+30min; reveal must occur within
  created_at      timestamptz not null default now()
);
-- No now() in the predicate; expiry is checked in the query WHERE clause.
create index ix_verified_active on verified_identifiers (identifier_hash, grant_token_hash);

-- Rate limiting: bounded by identifier AND by client fingerprint (ip hash).
-- Prevents the free scan being scripted into a bulk enumeration tool.
create table rate_events (
  id              uuid primary key default gen_random_uuid(),
  bucket_key      text        not null,            -- e.g. 'otp:<identifier_hash>' or 'ip:<ip_hash>'
  occurred_at     timestamptz not null default now()
);
create index ix_rate_bucket on rate_events (bucket_key, occurred_at desc);

-- ===========================================================================
-- 2. USERS
-- INVARIANT: users.id is set to the Supabase auth uid at signup, so the RLS
-- policy auth.uid() = id holds. Batch 2 must create the row with id = auth.uid().
-- ===========================================================================
create table users (
  id                  uuid primary key default gen_random_uuid(),
  email_hash          text unique,                 -- keyed-hashed; raw email lives only in auth/Resend payloads
  phone_hash          text,
  name_revealed       text,                        -- display name surfaced at reveal (subscriber-owned)
  subscription_status subscription_status not null default 'free',
  privacy_score       smallint,
  paystack_customer   text,
  created_at          timestamptz not null default now(),
  last_scanned        timestamptz
);
create index ix_users_phone on users (phone_hash);

-- ===========================================================================
-- 3. SCAN CACHE  (TTL 24h — applies to subscriber-owned scans only)
-- Non-subscriber third-party data is request-scoped in app code and never written here.
-- ===========================================================================
create table scan_cache (
  identifier_hash   text primary key,
  scan_results_json jsonb       not null,
  haiku_narrative   text,
  created_at        timestamptz not null default now(),
  expires_at        timestamptz not null
);
create index ix_scan_cache_expiry on scan_cache (expires_at);

-- ===========================================================================
-- 4. BREACH SOURCES  (catalogue/reference, not personal data)
-- ===========================================================================
create table breach_sources (
  id           uuid primary key default gen_random_uuid(),
  source_name  text not null,
  source_type  source_type not null,
  country      text,
  last_updated timestamptz
);

-- ===========================================================================
-- 5. THREAT INDICATORS  (subscriber-scoped findings only)
-- Tied to a user; non-subscriber matches are never persisted here.
-- ===========================================================================
create table threat_indicators (
  id                     uuid primary key default gen_random_uuid(),
  user_id                uuid not null references users(id) on delete cascade,
  breach_source_id       uuid references breach_sources(id),
  data_categories_exposed text[] not null default '{}',
  risk                   risk_level not null,
  detected_at            timestamptz not null default now()
);
create index ix_threat_user on threat_indicators (user_id);

-- ===========================================================================
-- 6. DPO DIRECTORY  (the real moat — verified, response-rate-tracked)
-- ===========================================================================
create table dpo_directory (
  id              uuid primary key default gen_random_uuid(),
  institution_name text not null,
  domain          text,
  dpo_email       citext,
  compliance_email citext,
  physical_address text,
  verified        boolean not null default false,   -- ZeroBounce / manual confirmation
  is_priority     boolean not null default false,   -- banks, telcos, CBN-regulated -> always human review
  source          text,                             -- 'ndpc_registry' | 'qwen_pattern' | 'manual'
  response_rate   numeric(5,2),                      -- proprietary intelligence over time
  last_checked    timestamptz,
  created_at      timestamptz not null default now()
);
create unique index uq_dpo_domain_email on dpo_directory (domain, dpo_email);
create index ix_dpo_priority on dpo_directory (is_priority) where is_priority;

-- ===========================================================================
-- 7. NOTICE DRAFTS + DISPATCH LOG  (Batch 1 — the review queue)
-- Generation and dispatch are SEPARATE actions. An LLM may draft; only an
-- approved row may be dispatched. is_priority or low-confidence => must be reviewed.
-- ===========================================================================
create table notice_drafts (
  id                uuid primary key default gen_random_uuid(),
  user_id           uuid not null references users(id) on delete cascade,
  institution_id    uuid references dpo_directory(id),
  letter_type       letter_type not null,
  status            notice_status not null default 'draft',
  body_rendered     text,                            -- statutory constants hardcoded; LLM fills variables only
  match_confidence  numeric(5,2),                    -- drives auto-approve lane later
  requires_review   boolean not null default true,   -- default TRUE; auto-approve is opt-in per rule
  mandate_granted_at timestamptz,                     -- when the subject authorised dispatch on their behalf
  reviewed_by       text,
  reviewed_at       timestamptz,
  reject_reason     text,
  created_at        timestamptz not null default now()
);
create index ix_notice_queue on notice_drafts (status, requires_review, created_at);
create index ix_notice_user on notice_drafts (user_id);

-- Append-only record of what actually left the building, under whose name.
create table notice_dispatch_log (
  id              uuid primary key default gen_random_uuid(),
  draft_id        uuid not null references notice_drafts(id),
  dispatched_to   citext not null,
  dispatched_at   timestamptz not null default now(),
  channel         text not null default 'email',    -- email | hard_copy
  response_received boolean not null default false,
  resolved        boolean not null default false
);
create index ix_dispatch_draft on notice_dispatch_log (draft_id);

-- ===========================================================================
-- 8. MONITORING ALERTS  (subscriber-scoped)
-- ===========================================================================
create table monitoring_alerts (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references users(id) on delete cascade,
  new_source    text,
  detected_at   timestamptz not null default now(),
  alert_sent    boolean not null default false,
  letter_triggered boolean not null default false
);
create index ix_alerts_user on monitoring_alerts (user_id);

-- ===========================================================================
-- 9. TTL REAPER  (the ephemeral tables accumulate; pg_cron sweeps them)
-- ===========================================================================
create or replace function ps_reap() returns void language plpgsql as $$
begin
  -- keep retired challenges briefly for abuse forensics, then drop
  delete from verification_challenges where expires_at < now() - interval '1 day';
  delete from rate_events           where occurred_at < now() - interval '1 day';
  delete from scan_cache            where expires_at < now();
  delete from verified_identifiers  where scan_grant_expires_at < now() - interval '1 day';
end;
$$;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    -- unschedule first so re-running the migration is idempotent
    perform cron.unschedule('ps-reap') where exists
      (select 1 from cron.job where jobname = 'ps-reap');
    perform cron.schedule('ps-reap', '*/15 * * * *', $j$select ps_reap()$j$);
  end if;
end$$;

-- ---------------------------------------------------------------------------
-- GATE ENFORCEMENT NOTE (documented as SQL comment so it survives in the repo):
-- The scan edge function MUST, before computing or returning any target data:
--   1. confirm a verified_identifiers row exists for the identifier_hash whose
--      grant_token_hash matches the presented one-time token AND
--      scan_grant_expires_at > now();
--   2. otherwise return 403 and issue/refresh a challenge instead.
-- No code path may render name, score, "records found", or any per-target
-- signal prior to step 1 succeeding. This is the anti-lookup guarantee.
-- ---------------------------------------------------------------------------
