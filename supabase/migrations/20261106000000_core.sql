-- Core multi-tenant schema. A user's tenant comes from the `tenant_id` claim in
-- their JWT app_metadata (set server-side; user_metadata is user-editable).

create type public.tenant_tier as enum ('community', 'pro', 'enterprise');

create table public.tenants (
    id                     uuid primary key default gen_random_uuid(),
    name                   text not null,
    polar_organization_id  text,
    tier                   public.tenant_tier not null default 'community',
    created_at             timestamptz not null default now()
);

create table public.agent_identities (
    id           uuid primary key default gen_random_uuid(),
    tenant_id    uuid not null references public.tenants (id) on delete cascade,
    -- SHA-256 hex of the agent's bearer token; the plaintext token is never stored.
    agent_token  text not null unique check (agent_token ~ '^[0-9a-f]{64}$'),
    created_at   timestamptz not null default now()
);

create index agent_identities_tenant_idx on public.agent_identities (tenant_id);

create table public.audit_logs (
    id         uuid primary key default gen_random_uuid(),
    tenant_id  uuid not null references public.tenants (id) on delete restrict,
    action     text not null,
    status     text not null check (status in ('allowed', 'approved', 'denied', 'expired', 'error')),
    timestamp  timestamptz not null default now()
);

create index audit_logs_tenant_time_idx on public.audit_logs (tenant_id, timestamp desc);

-- Append-only: triggers also apply to service_role, which bypasses RLS.
create function public.reject_audit_log_change() returns trigger
language plpgsql set search_path = '' as $$
begin
    raise exception 'audit_logs is append-only';
end;
$$;

create trigger audit_logs_no_update_delete
    before update or delete on public.audit_logs
    for each row execute function public.reject_audit_log_change();

create trigger audit_logs_no_truncate
    before truncate on public.audit_logs
    for each statement execute function public.reject_audit_log_change();

-- Row Level Security

create function public.current_tenant_id() returns uuid
language sql stable set search_path = '' as $$
    select nullif(auth.jwt() -> 'app_metadata' ->> 'tenant_id', '')::uuid
$$;

alter table public.tenants          enable row level security;
alter table public.agent_identities enable row level security;
alter table public.audit_logs       enable row level security;

revoke all on public.tenants, public.agent_identities, public.audit_logs from anon;

-- tenants: read own row; may rename it, but tier/billing columns are backend-only.
revoke insert, update, delete, truncate on public.tenants from authenticated;
grant update (name) on public.tenants to authenticated;

create policy tenants_select_own on public.tenants
    for select to authenticated
    using (id = public.current_tenant_id());

create policy tenants_update_own on public.tenants
    for update to authenticated
    using (id = public.current_tenant_id())
    with check (id = public.current_tenant_id());

-- agent_identities: full CRUD within the user's tenant.
create policy agent_identities_select_own on public.agent_identities
    for select to authenticated
    using (tenant_id = public.current_tenant_id());

create policy agent_identities_insert_own on public.agent_identities
    for insert to authenticated
    with check (tenant_id = public.current_tenant_id());

create policy agent_identities_update_own on public.agent_identities
    for update to authenticated
    using (tenant_id = public.current_tenant_id())
    with check (tenant_id = public.current_tenant_id());

create policy agent_identities_delete_own on public.agent_identities
    for delete to authenticated
    using (tenant_id = public.current_tenant_id());

-- audit_logs: tenants read their own; only the proxy (service_role) writes, so logs can't be forged.
revoke insert, update, delete, truncate on public.audit_logs from authenticated;

create policy audit_logs_select_own on public.audit_logs
    for select to authenticated
    using (tenant_id = public.current_tenant_id());
