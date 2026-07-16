# Supabase RLS Auth Demo

A small "membership club" app built to demonstrate one specific thing well:
**Postgres Row-Level Security policies that are actually proven to work by an
automated test, not just assumed to work because the SQL looks right.**

Stack: Next.js (App Router) + `@supabase/ssr` for auth, Postgres RLS for
authorization, Vitest for both structural SQL checks and live-database
integration tests.

This is a portfolio sample. It's a generic "membership club" — not a real
business, no real client data, no real API keys anywhere in this repo.

## What this is

Three roles' worth of access to two tables:

- `profiles` — one row per signed-up user, with a `role` of `member` or `admin`
- `announcements` — club posts, each tagged `public`, `members`, or `admins`

Three pages:

- `/` — public landing page, anyone can load it
- `/member` — signed-in members see their own profile + `public`/`members`-tier announcements
- `/admin` — admins see a full member roster + every announcement, regardless of tier

The access rules exist in **two places**, on purpose:

1. `src/middleware.ts` — redirects obviously-unauthorized visitors before a page renders. This is a UX convenience.
2. `supabase/migrations/0002_rls.sql` — Postgres RLS policies. This is the actual security boundary.

If the middleware had a bug tomorrow, the RLS policies would still hold. The
tests in this repo only test layer 2, because layer 2 is the one that
matters if layer 1 fails.

## Threat model

| Actor | Action | Expected outcome | Enforced by |
|---|---|---|---|
| Anonymous (not signed in) | Read `/` landing page | Allowed | No auth required |
| Anonymous | Read `public`-tier announcements | Allowed | `announcements_select_public` |
| Anonymous | Read `members`- or `admins`-tier announcements | Denied (0 rows) | `announcements_select_members` / `announcements_select_admins` are `to authenticated` only |
| Anonymous | Read any `profiles` row | Denied (0 rows) | No `anon` policy exists on `profiles` at all |
| Member | Read own `profiles` row | Allowed | `profiles_select_own` |
| Member | Read **another member's** `profiles` row | Denied (0 rows, not an error) | `profiles_select_own` filters `id = auth.uid()` |
| Member | Read `admins`-tier announcements | Denied (0 rows) | `announcements_select_admins` requires `is_admin()` |
| Member | Update own `display_name` | Allowed | `profiles_update_own` + column grant |
| Member | Update own `role` to `'admin'` | Denied (Postgres permission error) | column-level `revoke update ... grant update (display_name)` |
| Member | List all `profiles` (the admin roster query) | Returns only their own row, not an error | `profiles_select_own` is the only policy that applies to them |
| Admin | Read any `profiles` row | Allowed | `profiles_select_admin_all` via `is_admin()` |
| Admin | Read announcements at every tier | Allowed | `announcements_select_admins` via `is_admin()` |
| Anyone (member or admin) | Insert/update/delete an `announcement` | Denied | no INSERT/UPDATE/DELETE policy exists, and table grants are explicitly revoked |
| Server (service_role key) | Anything | Allowed, bypasses RLS entirely | by design — this key never reaches the browser |

The integration test suite (`test/rls.integration.test.ts`) exercises every
row of this table that involves a signed-in `member` or `admin`, against a
real local Postgres instance.

## Policy walkthrough

Full text and comments live in `supabase/migrations/0002_rls.sql`; the short
version:

> ```sql
> create policy profiles_select_own
> on public.profiles for select to authenticated
> using (auth.uid() = id);
> ```
> Stops a signed-in member from reading any other member's profile row by id,
> by listing, or any other query shape. Without this filter, any member could
> enumerate every other member's name.

> ```sql
> create policy profiles_select_admin_all
> on public.profiles for select to authenticated
> using (public.is_admin());
> ```
> The one broadening rule in the file — only widens access for callers whose
> *own* `role` is `'admin'`, via a `security definer` helper function (see
> below). Never widens access for a member, because `is_admin()` is false
> for them.

> ```sql
> revoke update on public.profiles from authenticated;
> grant update (display_name) on public.profiles to authenticated;
> ```
> Stops privilege escalation. `authenticated` can update *only* the
> `display_name` column now — an `UPDATE` that includes `role` fails with a
> Postgres permission error before RLS is even consulted. This is a
> column-level grant, not an RLS policy, because RLS's `WITH CHECK` clause
> can't cleanly express "this column may only keep its previous value"
> across a concurrent update — the column grant is unambiguous instead.

> ```sql
> create policy announcements_select_members
> on public.announcements for select to authenticated
> using (visibility in ('public', 'members'));
> ```
> Stops an anonymous visitor from seeing `members`-tier posts (this policy is
> scoped `to authenticated`, not `to public`). Multiple permissive `SELECT`
> policies on the same table are OR'd together by Postgres, so a member's
> effective visibility ends up being the union of this policy and
> `announcements_select_public` — public + members tiers, nothing from
> `admins`.

> ```sql
> create or replace function public.is_admin()
> returns boolean language sql security definer set search_path = public stable
> as $$ select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'); $$;
> ```
> Exists to dodge a specific Postgres error: a `profiles` policy whose
> `USING` clause queries `profiles` for the caller's own role causes
> "infinite recursion detected in policy for relation profiles" — the
> subquery re-triggers the very policy it's part of. `security definer`
> runs the function as its owner (`postgres`, which has `BYPASSRLS` in a
> Supabase project), so the internal lookup doesn't re-enter policy
> evaluation.

## Running it locally

Requires the [Supabase CLI](https://supabase.com/docs/guides/local-development/cli/getting-started) and Docker.

```bash
pnpm install --ignore-workspace   # only needed if this sits inside another pnpm workspace
supabase start                    # applies supabase/migrations/*.sql + seed.sql to a local Postgres
```

`supabase start` prints an API URL, an anon key, and a service role key.
Copy `.env.example` to `.env.local` (not committed — this repo has no real
example values, just the variable names) and fill in the printed values for
`NEXT_PUBLIC_SUPABASE_URL` / `NEXT_PUBLIC_SUPABASE_ANON_KEY`:

```bash
pnpm dev
```

To run the RLS integration tests locally, export the same three values as
`SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY`, then:

```bash
pnpm test
```

Without those three env vars, `pnpm test` still runs — it just skips the
integration suite and runs only the structural SQL checks
(`test/policies.unit.test.ts`), so contributors without Docker running can
still get a green test run.

`.github/workflows/test.yml` runs both: a typecheck+unit job that always
runs, and a second job that provisions a real local Supabase stack via
`supabase/setup-cli` and runs the full integration suite in CI.

## Bugs I actually hit building the production version of this

Three lessons from building a real (private, client) version of this same
pattern, generalized here without any client specifics:

1. **A cached-role cookie is a stale-role bug waiting to happen.** An early
   draft of the middleware set a plain cookie with the user's role at login
   time and trusted that cookie on every later request instead of
   re-checking the database. Promote or demote someone and the cookie stays
   correct only until they log out — which for an admin session could be
   days. The fix is boring: re-read `profiles.role` from the database on
   every request that hits a gated route (see `src/middleware.ts`). It's
   one extra query per request; it's worth it.

2. **RLS returns zero rows, not an error — so a "passing" test can hide a
   broken policy.** The first version of my test suite asserted
   `expect(error).toBeNull()` and stopped there. That's true whether the
   policy correctly filtered out a row *or* whether someone had accidentally
   dropped the policy entirely and Postgres was returning zero rows for an
   unrelated reason (e.g. the table was just empty). The tests in this repo
   assert on the actual row **count** and **contents**
   (`expect(data).toEqual([])`, `expect(titles).not.toContain(...)`) instead
   of just "no error came back."

3. **Forgetting `to authenticated` quietly grants `anon` in some setups.**
   A policy written `using (visibility in ('public', 'members'))` with no
   `to` clause defaults to `to public` in Postgres, which in RLS terms means
   *every* role, including `anon`. I did this once, on a policy that was
   supposed to be members-only, and didn't notice until a coworker loaded
   the members page in an incognito window and it worked. Every policy in
   `supabase/migrations/0002_rls.sql` is explicit about which role(s) it
   applies to, and `test/policies.unit.test.ts` has a guardrail
   (`never grants a profiles policy 'to public'`) specifically so this
   can't silently regress again.

## Project layout

```
src/
  app/
    page.tsx            # public landing page
    login/page.tsx       # magic-link login (client component)
    member/page.tsx       # member-only server component
    admin/page.tsx        # admin-only server component
  lib/supabase/
    client.ts             # browser Supabase client (anon key)
    server.ts              # server Supabase client (anon key, cookie-backed session)
  middleware.ts             # role gate (UX only — not the security boundary)
supabase/
  migrations/
    0001_schema.sql          # tables + auto-profile trigger
    0002_rls.sql               # RLS policies — the actual security boundary
  seed.sql                     # documents the admin-API test-user approach
  config.toml                   # local Supabase CLI config
test/
  policies.unit.test.ts          # parses the SQL migrations, always runs
  rls.integration.test.ts         # the centerpiece — proves RLS against real Postgres
.github/workflows/test.yml         # typecheck+unit always; RLS integration via supabase/setup-cli
```

## License

MIT — see `LICENSE`.
