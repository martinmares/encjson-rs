-- Add tags to keys

alter table keys
    add column if not exists tags text[] not null default '{}';

create index if not exists keys_tags_idx on keys using gin (tags);
