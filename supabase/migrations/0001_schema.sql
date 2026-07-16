-- 0001_schema.sql
-- Base schema for the membership-club demo: a profiles table (one row per
-- auth.users row, holding the app-level role) and an announcements table
-- (club posts with a tiered visibility level). RLS is deliberately NOT
-- enabled here — see 0002_rls.sql for the security layer. Splitting schema
-- from policy makes it easy to point at this file and say "here's the data
-- model" without also reading every WITH CHECK clause at the same time.

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text not null default 'New member',
  role text not null default 'member' check (role in ('member', 'admin')),
  created_at timestamptz not null default now()
);

comment on table public.profiles is
  'One row per auth.users row. role drives every access-control decision in this app — see 0002_rls.sql.';
comment on column public.profiles.role is
  'member | admin. Never set by the client directly — see the profiles_update_own policy in 0002_rls.sql for why.';

create table if not exists public.announcements (
  id bigint generated always as identity primary key,
  title text not null,
  body text not null,
  visibility text not null default 'members' check (visibility in ('public', 'members', 'admins')),
  created_at timestamptz not null default now()
);

comment on table public.announcements is
  'Club posts with a tiered visibility: public (anon-visible), members (signed-in only), admins (admin-only).';
comment on column public.announcements.visibility is
  'public | members | admins. Enforced by RLS policies in 0002_rls.sql, not by application code.';

-- Auto-create a profile row whenever a new auth.users row is created, so the
-- app never has to handle "authenticated user with no profile row" as a
-- special case. Runs as the function owner (security definer) because the
-- newly-created user does not yet have a session that could satisfy an RLS
-- insert policy on public.profiles.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, display_name)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'display_name', split_part(new.email, '@', 1)));
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
