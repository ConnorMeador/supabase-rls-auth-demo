-- 0003_explicit_grants.sql
-- CI caught this one: on a fresh `supabase start` database the integration
-- suite failed with "permission denied for table profiles" -- for the
-- SERVICE-ROLE client, which is supposed to bypass RLS entirely.
--
-- Root cause: BYPASSRLS only skips row-level policies. It does nothing for
-- table-level privileges, and this schema relied on the platform's ALTER
-- DEFAULT PRIVILEGES to hand out grants on newly created tables. That
-- assumption doesn't hold on every stack that runs these migrations (it
-- didn't in CI), so the tables ended up with no grants for the API roles at
-- all. Lesson: migrations should state their own grants explicitly instead
-- of inheriting whatever defaults the host database happens to have.

grant usage on schema public to anon, authenticated, service_role;

-- service_role is the server-only key: full table privileges. RLS bypass
-- alone is useless to it without these.
grant all privileges on public.profiles to service_role;
grant all privileges on public.announcements to service_role;

-- The API roles get exactly the surface the policies in 0002 narrow down.
grant select on public.profiles to authenticated;
grant select on public.announcements to anon, authenticated;

-- Re-assert the column-level escalation blocker from 0002 so this file is
-- safe to run standalone AND doesn't accidentally widen what 0002 narrowed:
-- authenticated may update display_name only, never role.
revoke update on public.profiles from authenticated;
grant update (display_name) on public.profiles to authenticated;
