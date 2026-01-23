-- Encjson vault server schema (v1)

create table if not exists tenants (
    id bigserial primary key,
    name text not null unique,
    created_at timestamptz not null default now()
);

create table if not exists keys (
    public_hex text primary key,
    tenant text not null,
    status text not null,
    note text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists keys_tenant_idx on keys (tenant);
create index if not exists keys_status_idx on keys (status);

create table if not exists requests (
    id bigserial primary key,
    public_hex text not null,
    tenant text not null,
    note text not null,
    tags text[] not null default '{}',
    status text not null default 'pending',
    requested_by text,
    requested_at timestamptz not null default now(),
    decided_by text,
    decided_at timestamptz,
    decision_note text
);

create index if not exists requests_status_idx on requests (status);
create index if not exists requests_public_hex_idx on requests (public_hex);

