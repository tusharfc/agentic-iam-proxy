-- Per-tenant request policies, evaluated by the proxy in ascending priority.

create table public.tenant_policies (
    id           uuid primary key default gen_random_uuid(),
    tenant_id    uuid not null references public.tenants (id) on delete cascade,
    name         text not null check (char_length(name) between 1 and 100),
    priority     integer not null default 100,
    method       text not null default '*' check (method ~ '^([A-Z]{1,10}|\*)$'),
    -- Python `regex` syntax, matched against scheme://host/path (no query string).
    url_pattern  text not null check (char_length(url_pattern) between 1 and 500),
    action       text not null check (action in ('allow', 'deny', 'requires_approval')),
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now()
);

create index tenant_policies_tenant_priority_idx on public.tenant_policies (tenant_id, priority);

create trigger tenant_policies_updated_at
    before update on public.tenant_policies
    for each row execute function public.set_updated_at();

alter table public.tenant_policies enable row level security;

revoke all on public.tenant_policies from anon;

create policy tenant_policies_select_own on public.tenant_policies
    for select to authenticated
    using (tenant_id = public.current_tenant_id());

create policy tenant_policies_insert_own on public.tenant_policies
    for insert to authenticated
    with check (tenant_id = public.current_tenant_id());

create policy tenant_policies_update_own on public.tenant_policies
    for update to authenticated
    using (tenant_id = public.current_tenant_id())
    with check (tenant_id = public.current_tenant_id());

create policy tenant_policies_delete_own on public.tenant_policies
    for delete to authenticated
    using (tenant_id = public.current_tenant_id());
