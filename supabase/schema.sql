-- ============================================================================
-- WAKeep Database Schema
-- Run this script in your Supabase SQL Editor
-- ============================================================================

-- Enable pgcrypto extension for secure UUIDs if needed
create extension if not exists "pgcrypto";

-- ----------------------------------------------------------------------------
-- Table 1: wa_auth_vault
-- Stores AES-256-GCM encrypted session credentials and signal keys
-- ----------------------------------------------------------------------------
create table if not exists public.wa_auth_vault (
    id text primary key,
    encrypted_payload text not null,
    updated_at timestamptz not null default timezone('utc'::text, now())
);

-- Index for fast lookup by key id
create index if not exists idx_wa_auth_vault_updated_at on public.wa_auth_vault (updated_at desc);

-- Auto-update updated_at timestamp on row modification
create or replace function public.touch_updated_at()
returns trigger as $$
begin
    new.updated_at = timezone('utc'::text, now());
    return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_touch_wa_auth_vault on public.wa_auth_vault;
create trigger trigger_touch_wa_auth_vault
    before update on public.wa_auth_vault
    for each row
    execute function public.touch_updated_at();

-- ----------------------------------------------------------------------------
-- Table 2: wa_recent_messages
-- Lightweight cache for the Web UI to render recent chat history instantly
-- ----------------------------------------------------------------------------
create table if not exists public.wa_recent_messages (
    id uuid primary key default gen_random_uuid(),
    message_id text unique not null,
    chat_jid text not null,
    sender_jid text not null,
    sender_name text,
    from_me boolean not null default false,
    text_content text not null default '',
    message_timestamp bigint not null default 0,
    created_at timestamptz not null default timezone('utc'::text, now())
);

-- Indexes for lightning-fast queries
create index if not exists idx_wa_messages_chat on public.wa_recent_messages (chat_jid);
create index if not exists idx_wa_messages_timestamp on public.wa_recent_messages (message_timestamp desc);
create index if not exists idx_wa_messages_created_at on public.wa_recent_messages (created_at desc);

-- Function to prune old messages keeping only recent 200 items to conserve database storage
create or replace function public.prune_old_wa_messages()
returns trigger as $$
begin
    delete from public.wa_recent_messages
    where id in (
        select id from public.wa_recent_messages
        order by created_at desc
        offset 200
    );
    return null;
end;
$$ language plpgsql;

drop trigger if exists trigger_prune_wa_messages on public.wa_recent_messages;
create trigger trigger_prune_wa_messages
    after insert on public.wa_recent_messages
    execute function public.prune_old_wa_messages();

-- Enable Row Level Security (RLS)
alter table public.wa_auth_vault enable row level security;
alter table public.wa_recent_messages enable row level security;

-- Policies:
-- Service role key has full access automatically.
-- For standard anon key with proper setup:
create policy "Service role has full access to auth vault"
    on public.wa_auth_vault
    for all
    using (auth.role() = 'service_role');

create policy "Service role has full access to messages"
    on public.wa_recent_messages
    for all
    using (auth.role() = 'service_role');
