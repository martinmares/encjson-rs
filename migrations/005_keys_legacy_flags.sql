alter table keys
    add column if not exists legacy_mode boolean not null default false;

alter table keys
    add column if not exists pair_consistent boolean not null default true;

alter table keys
    add column if not exists legacy_reason text;

create index if not exists keys_legacy_mode_idx on keys (legacy_mode);
