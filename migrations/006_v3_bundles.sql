alter table keys
    add column if not exists key_id text;

alter table keys
    add column if not exists bundle_version integer;

alter table keys
    add column if not exists algorithm text;

alter table keys
    add column if not exists public_bundle jsonb;

alter table keys
    add column if not exists private_bundle text;

create unique index if not exists keys_key_id_idx
    on keys (key_id)
    where key_id is not null;

alter table requests
    add column if not exists key_id text;

alter table requests
    add column if not exists bundle_version integer;

alter table requests
    add column if not exists algorithm text;

alter table requests
    add column if not exists public_bundle jsonb;

alter table requests
    add column if not exists private_bundle text;

create index if not exists requests_key_id_idx on requests (key_id);
