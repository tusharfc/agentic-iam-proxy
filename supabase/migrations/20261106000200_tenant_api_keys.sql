-- Downstream API credentials per tenant, Fernet-encrypted by the backend
-- (VAULT_ENCRYPTION_KEY never reaches the database).

create table public.tenant_api_keys (
    id                 uuid primary key default gen_random_uuid(),
    tenant_id          uuid not null references public.tenants (id) on delete cascade,
    service_name       text not null check (service_name ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    encrypted_api_key  text not null,
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now(),
    unique (tenant_id, service_name)
);

create trigger tenant_api_keys_updated_at
    before update on public.tenant_api_keys
    for each row execute function public.set_updated_at();

alter table public.tenant_api_keys enable row level security;

-- Only the backend (service_role) reads ciphertext or writes keys: clients can't encrypt anyway.
revoke all on public.tenant_api_keys from anon, authenticated;

-- Dashboard users may list which services their tenant has configured, never the ciphertext.
grant select (id, tenant_id, service_name, created_at, updated_at) on public.tenant_api_keys to authenticated;

create policy tenant_api_keys_select_own on public.tenant_api_keys
    for select to authenticated
    using (tenant_id = public.current_tenant_id());
