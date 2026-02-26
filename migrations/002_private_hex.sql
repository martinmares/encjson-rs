-- Add private key storage for keys sync

alter table keys
    add column if not exists private_hex text;

alter table requests
    add column if not exists private_hex text;
