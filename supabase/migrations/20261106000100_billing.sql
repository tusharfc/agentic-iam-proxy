-- Billing state per tenant. Written only by the backend (service_role) from
-- Polar/Stripe webhooks; tenants can read their own row. Tier lives on tenants.

create table public.tenant_billing (
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

-- Webhook deliveries are at-least-once; record message IDs to process each only once.
create table public.billing_events (
    provider     text not null check (provider in ('polar', 'stripe')),
    event_id     text not null,
    event_type   text not null,
    tenant_id    uuid references public.tenants (id) on delete set null,
    received_at  timestamptz not null default now(),
    primary key (provider, event_id)
);

create index billing_events_tenant_idx on public.billing_events (tenant_id, received_at desc);

create function public.set_updated_at() returns trigger
language plpgsql set search_path = '' as $$
begin
    new.updated_at := now();
    return new;
end;
$$;

create trigger tenant_billing_updated_at
    before update on public.tenant_billing
    for each row execute function public.set_updated_at();

alter table public.tenant_billing enable row level security;
alter table public.billing_events enable row level security;

revoke all on public.tenant_billing, public.billing_events from anon;
revoke all on public.billing_events from authenticated;
revoke insert, update, delete, truncate on public.tenant_billing from authenticated;

create policy tenant_billing_select_own on public.tenant_billing
    for select to authenticated
    using (tenant_id = public.current_tenant_id());

-- Applies one Polar subscription event atomically: dedupes by message ID, drops
-- out-of-order events, and sets tenants.tier. Returns what it did.
create function public.apply_polar_subscription(
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

revoke all on function public.apply_polar_subscription from public, anon, authenticated;
grant execute on function public.apply_polar_subscription to service_role;
