-- audit-log schema. Safe to run repeatedly.
--
-- The guarantees this package makes are constraints here, not conventions in
-- application code: one entry per position in a tenant's chain, no two entries
-- claiming the same predecessor, and no UPDATE or DELETE at all.

create table if not exists audit_entry (
  tenant      text not null,
  seq         bigint not null,
  -- Millisecond precision, because the hash covers a millisecond ISO-8601 string.
  -- A column that kept microseconds would eventually store a time a JavaScript
  -- Date cannot hold, and an honest row would then verify as tampered.
  recorded_at timestamptz(3) not null,
  actor       text not null,
  action      text not null,
  resource    text not null,
  -- Canonical JSON text, not jsonb. jsonb re-orders keys, drops duplicates and
  -- normalises numbers, so the bytes that went in are not the bytes that come
  -- back and the hash stops matching. Query it with payload::jsonb.
  payload     text not null,
  prev_hash   text not null,
  hash        text not null,

  -- The position is the identity. This is what stops two concurrent appends from
  -- both becoming entry 5; the loser gets a unique violation and is retried.
  primary key (tenant, seq),
  constraint audit_entry_seq_positive check (seq > 0),
  -- A chain, not a tree: no two entries may claim the same predecessor. It also
  -- makes a second genesis impossible, since both would carry the all-zero
  -- prev_hash for the same tenant.
  constraint audit_entry_no_fork unique (tenant, prev_hash),
  constraint audit_entry_hash_unique unique (tenant, hash),
  constraint audit_entry_hash_hex check (hash ~ '^[0-9a-f]{64}$'),
  constraint audit_entry_prev_hash_hex check (prev_hash ~ '^[0-9a-f]{64}$')
);

-- Append-only, enforced by the database rather than by reviewers noticing.
--
-- This stops application bugs and careless fixes, which is most of what actually
-- edits an audit table. It does not stop whoever owns the table: they can disable
-- the trigger. That is why the hash chain exists, and why you keep an anchor
-- somewhere this database cannot reach.
create or replace function audit_entry_append_only() returns trigger
language plpgsql as $$
begin
  raise exception 'audit_entry is append-only: % is not permitted', tg_op;
end;
$$;

drop trigger if exists audit_entry_no_change on audit_entry;
create trigger audit_entry_no_change
  before update or delete on audit_entry
  for each row execute function audit_entry_append_only();

-- TRUNCATE does not fire row triggers, so it needs a statement-level one of its own.
drop trigger if exists audit_entry_no_truncate on audit_entry;
create trigger audit_entry_no_truncate
  before truncate on audit_entry
  for each statement execute function audit_entry_append_only();
