-- Management control plane: developer-facing tokens and agent display names.

alter table public.agent_identities
    add column name text check (char_length(name) between 1 and 100);

-- Separate from agent_identities so an agent token can never call the management API.
-- Bootstrap the first token per tenant with the service role, e.g.:
--   insert into management_tokens (tenant_id, token_hash, name) values ('<tenant>', '<sha256 hex of token>', 'admin');
create table public.management_tokens (
    id          uuid primary key default gen_random_uuid(),
    tenant_id   uuid not null references public.tenants (id) on delete cascade,
    token_hash  text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
    name        text check (char_length(name) between 1 and 100),
    created_at  timestamptz not null default now()
);

create index management_tokens_tenant_idx on public.management_tokens (tenant_id);

alter table public.management_tokens enable row level security;

-- No policies: only the backend (service_role) reads or writes management tokens.
revoke all on public.management_tokens from anon, authenticated;
