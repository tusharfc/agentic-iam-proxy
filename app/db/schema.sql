-- Applied by the proxy on every startup, so every statement must be idempotent. Needs Postgres 14+.

do $$ begin
    create type public.tenant_tier as enum ('community', 'pro', 'enterprise');
exception when duplicate_object then null;
end $$;

create or replace function public.set_updated_at() returns trigger
language plpgsql set search_path = '' as $$
begin
    new.updated_at := now();
    return new;
end;
$$;

create table if not exists public.tenants (
    id                     uuid primary key default gen_random_uuid(),
    name                   text not null,
    polar_organization_id  text,
    tier                   public.tenant_tier not null default 'community',
    created_at             timestamptz not null default now()
);

create table if not exists public.agent_identities (
    id           uuid primary key default gen_random_uuid(),
    tenant_id    uuid not null references public.tenants (id) on delete cascade,
    name         text check (char_length(name) between 1 and 100),
    -- SHA-256 hex of the agent's bearer token; the plaintext token is never stored.
    agent_token  text not null unique check (agent_token ~ '^[0-9a-f]{64}$'),
    created_at   timestamptz not null default now()
);

create index if not exists agent_identities_tenant_idx on public.agent_identities (tenant_id);

-- Separate from agent_identities so an agent token can never call the management API.
create table if not exists public.management_tokens (
    id          uuid primary key default gen_random_uuid(),
    tenant_id   uuid not null references public.tenants (id) on delete cascade,
    token_hash  text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
    name        text check (char_length(name) between 1 and 100),
    created_at  timestamptz not null default now()
);

create index if not exists management_tokens_tenant_idx on public.management_tokens (tenant_id);

-- Fernet-encrypted by the proxy; VAULT_ENCRYPTION_KEY never reaches the database.
create table if not exists public.tenant_api_keys (
    id                 uuid primary key default gen_random_uuid(),
    tenant_id          uuid not null references public.tenants (id) on delete cascade,
    service_name       text not null check (service_name ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    encrypted_api_key  text not null,
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now(),
    unique (tenant_id, service_name)
);

create or replace trigger tenant_api_keys_updated_at
    before update on public.tenant_api_keys
    for each row execute function public.set_updated_at();

-- Evaluated by the proxy in ascending priority.
create table if not exists public.tenant_policies (
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

create index if not exists tenant_policies_tenant_priority_idx on public.tenant_policies (tenant_id, priority);

create or replace trigger tenant_policies_updated_at
    before update on public.tenant_policies
    for each row execute function public.set_updated_at();

-- Billing state per tenant, written only from verified Polar webhooks.
create table if not exists public.tenant_billing (
    tenant_id                 uuid primary key references public.tenants (id) on delete cascade,
    billing_provider          text not null default 'polar' check (billing_provider in ('polar', 'stripe')),
    polar_customer_id         text unique,
    polar_subscription_id     text unique,
    polar_product_id          text,
    polar_license_key_id      text unique,  -- Polar's key ID, never the key itself
    stripe_customer_id        text unique,
    subscription_status       text,
    current_period_end        timestamptz,
    cancel_at_period_end      boolean not null default false,
    subscription_modified_at  timestamptz,
    created_at                timestamptz not null default now(),
    updated_at                timestamptz not null default now()
);

create or replace trigger tenant_billing_updated_at
    before update on public.tenant_billing
    for each row execute function public.set_updated_at();

-- Webhook deliveries are at-least-once; record message IDs to process each only once.
create table if not exists public.billing_events (
    provider     text not null check (provider in ('polar', 'stripe')),
    event_id     text not null,
    event_type   text not null,
    tenant_id    uuid references public.tenants (id) on delete set null,
    received_at  timestamptz not null default now(),
    primary key (provider, event_id)
);

create index if not exists billing_events_tenant_idx on public.billing_events (tenant_id, received_at desc);

-- Applies one Polar subscription event atomically: dedupes by message ID, drops
-- out-of-order events, and sets tenants.tier. Returns what it did.
create or replace function public.apply_polar_subscription(
    p_event_id              text,
    p_event_type            text,
    p_tenant_id             uuid,
    p_subscription_id       text,
    p_customer_id           text,
    p_product_id            text,
    p_tier                  public.tenant_tier,
    p_status                text,
    p_current_period_end    timestamptz,
    p_cancel_at_period_end  boolean,
    p_modified_at           timestamptz
) returns text
language plpgsql set search_path = '' as $$
declare
    billing    public.tenant_billing%rowtype;
    is_paid    boolean := p_status in ('active', 'trialing');
begin
    -- Row lock serialises concurrent events for the same tenant.
    perform 1 from public.tenants where id = p_tenant_id for update;
    if not found then
        return 'unknown_tenant';
    end if;

    insert into public.billing_events (provider, event_id, event_type, tenant_id)
    values ('polar', p_event_id, p_event_type, p_tenant_id)
    on conflict do nothing;
    if not found then
        return 'duplicate';
    end if;

    select * into billing from public.tenant_billing where tenant_id = p_tenant_id;
    if found then
        if billing.polar_subscription_id = p_subscription_id
           and billing.subscription_modified_at >= p_modified_at then
            return 'stale';
        end if;
        -- An ended subscription must not downgrade a tenant who has a different live one.
        if billing.polar_subscription_id <> p_subscription_id
           and billing.subscription_status in ('active', 'trialing')
           and not is_paid then
            return 'ignored';
        end if;
    end if;

    insert into public.tenant_billing (
        tenant_id, billing_provider, polar_customer_id, polar_subscription_id, polar_product_id,
        subscription_status, current_period_end, cancel_at_period_end, subscription_modified_at
    ) values (
        p_tenant_id, 'polar', p_customer_id, p_subscription_id, p_product_id,
        p_status, p_current_period_end, p_cancel_at_period_end, p_modified_at
    )
    on conflict (tenant_id) do update set
        billing_provider         = excluded.billing_provider,
        polar_customer_id        = excluded.polar_customer_id,
        polar_subscription_id    = excluded.polar_subscription_id,
        polar_product_id         = excluded.polar_product_id,
        subscription_status      = excluded.subscription_status,
        current_period_end       = excluded.current_period_end,
        cancel_at_period_end     = excluded.cancel_at_period_end,
        subscription_modified_at = excluded.subscription_modified_at;

    update public.tenants
    set tier = case when is_paid then p_tier else 'community'::public.tenant_tier end
    where id = p_tenant_id;

    return 'applied';
end;
$$;
