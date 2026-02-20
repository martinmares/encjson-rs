create table if not exists key_access_log (
    id bigserial primary key,
    public_hex text not null,
    tenant text not null,
    subject text,
    reason text,
    created_at timestamptz not null default now()
);

create index if not exists key_access_log_public_hex_idx on key_access_log (public_hex);
create index if not exists key_access_log_tenant_idx on key_access_log (tenant);
