-- 0002_rls.sql
-- Row-Level Security is the actual access-control boundary for this app.
-- The Next.js middleware in src/middleware.ts is a UX nicety that redirects
-- obviously-unauthorized visitors before a page renders -- it is NOT trusted
-- for security. Every policy below documents the specific attack it stops,
-- because "RLS enabled" alone tells you nothing about what it actually
-- allows; the WITH CHECK / USING clauses are the whole story.
--
-- Gotcha worth knowing before reading further: Supabase's default schema
-- setup grants broad table privileges (SELECT/INSERT/UPDATE/DELETE) to the
-- `anon` and `authenticated` roles on every table created in `public` --
-- RLS is what narrows that back down. A table with RLS enabled and zero
-- policies for a given command is a hard deny for that command, for every
-- role except the table owner and any role with BYPASSRLS (service_role).

-- ---------------------------------------------------------------------------
-- Helper: is_admin()
-- ---------------------------------------------------------------------------
-- A profiles policy that reads profiles.role in its own USING clause (e.g.
-- "select 1 from profiles where id = auth.uid() and role = 'admin'") causes
-- Postgres to raise "infinite recursion detected in policy for relation
-- profiles" -- the subquery re-triggers RLS on the same table it's a policy
-- for. The documented fix (Supabase's own recursive-RLS guidance) is a
-- SECURITY DEFINER function: it runs as the function owner (postgres, which
-- has BYPASSRLS in a Supabase project), so the internal lookup doesn't
-- re-enter policy evaluation.
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.profiles where id = auth.uid() and role = 'admin'
  );
$$;

comment on function public.is_admin() is
  'SECURITY DEFINER to avoid infinite-recursion when a profiles RLS policy needs to check the caller''s own role. Returns false (not an error) for an unauthenticated caller, since auth.uid() is null for anon.';

-- ---------------------------------------------------------------------------
-- profiles
-- ---------------------------------------------------------------------------
alter table public.profiles enable row level security;

create policy profiles_select_own
on public.profiles
for select
to authenticated
using (auth.uid() = id);
-- Blocks: a signed-in member reading ANOTHER member's profile row -- by id,
-- by a `.select().neq('id', me)` query, by anything. Without this filter a
-- member could enumerate every other member's display name by id.

create policy profiles_select_admin_all
on public.profiles
for select
to authenticated
using (public.is_admin());
-- Grants: the one broadening rule in this file. Only a caller whose OWN
-- profiles.role is 'admin' matches this policy, so it only ever widens
-- access for admins, never for members (is_admin() is false for them).
-- This is what makes the /admin roster page possible without a service key.

create policy profiles_update_own
on public.profiles
for update
to authenticated
using (auth.uid() = id)
with check (auth.uid() = id);
-- Blocks: a member updating anyone else's row. Does NOT by itself stop a
-- member from trying to set their own role to 'admin' -- Postgres RLS
-- policies can't express "this column may only take its previous value"
-- cleanly and correctly for concurrent UPDATEs. Privilege escalation is
-- blocked below at the column-grant level instead, which is unambiguous.

revoke update on public.profiles from authenticated;
grant update (display_name) on public.profiles to authenticated;
-- Blocks: role self-escalation. `authenticated` can update ONLY the
-- display_name column now -- an UPDATE payload that includes `role` fails
-- with a Postgres permission error (42501) before RLS is even consulted,
-- regardless of whose row it targets. Changing a member to admin (or an
-- admin to member) requires the service_role key, which never reaches the
-- browser -- it's a server-only operation (see test/rls.integration.test.ts
-- for how the test suite provisions an admin: via the admin API + a direct
-- service-role update, not through the app).

-- No INSERT or DELETE policy exists on profiles for anon/authenticated --
-- rows are created exclusively by the handle_new_user() trigger (0001) and
-- deleted via `on delete cascade` from auth.users. A client-side INSERT or
-- DELETE against profiles is denied outright.

-- ---------------------------------------------------------------------------
-- announcements
-- ---------------------------------------------------------------------------
alter table public.announcements enable row level security;

create policy announcements_select_public
on public.announcements
for select
to anon, authenticated
using (visibility = 'public');
-- Grants: public-tier announcements are visible to anonymous visitors too
-- (e.g. a landing-page teaser). Intentional, not an oversight -- confirmed
-- by the "to anon, authenticated" scope rather than a bare "to public".

create policy announcements_select_members
on public.announcements
for select
to authenticated
using (visibility in ('public', 'members'));
-- Blocks: an anonymous (not-signed-in) caller seeing members-tier posts --
-- this policy only applies `to authenticated`. Multiple permissive SELECT
-- policies on the same table are OR'd by Postgres, so a signed-in member's
-- effective visibility is the union of this policy and the public one
-- above: public + members tiers, nothing from admins.

create policy announcements_select_admins
on public.announcements
for select
to authenticated
using (public.is_admin());
-- Grants: admins see every row, because is_admin() is true for them
-- regardless of the row's visibility value, and permissive policies OR
-- together. Blocks: a non-admin never matches this policy, so admins-tier
-- posts stay invisible to members no matter how the query is shaped.

revoke insert, update, delete on public.announcements from anon, authenticated;
-- Belt-and-suspenders: no INSERT/UPDATE/DELETE policy exists for these
-- roles either, so this is redundant with RLS's default-deny -- but an
-- explicit revoke means a future migration can't accidentally reopen write
-- access by adding a permissive policy without someone also noticing the
-- table grants still say "no".
