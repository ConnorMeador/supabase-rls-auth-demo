import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Cheap, always-on guardrails. These don't need a running database -- they
 * just parse the two migration files as text and assert the invariants that
 * matter most for RLS to do its job. They're not a substitute for
 * test/rls.integration.test.ts (which proves the policies actually behave
 * correctly against a real Postgres instance) -- they're a fast tripwire
 * that catches "someone deleted a policy" or "someone re-added `to public`"
 * in a code review, without needing `supabase start`.
 */

const migrationsDir = join(__dirname, '..', 'supabase', 'migrations');
const schemaSql = readFileSync(join(migrationsDir, '0001_schema.sql'), 'utf8');
const rlsSql = readFileSync(join(migrationsDir, '0002_rls.sql'), 'utf8');

describe('0001_schema.sql', () => {
  it('defines profiles with a role check constraint limited to member/admin', () => {
    expect(schemaSql).toMatch(/create table if not exists public\.profiles/i);
    expect(schemaSql).toMatch(/check \(role in \('member', 'admin'\)\)/i);
  });

  it('defines announcements with a visibility check constraint for all three tiers', () => {
    expect(schemaSql).toMatch(/create table if not exists public\.announcements/i);
    expect(schemaSql).toMatch(/check \(visibility in \('public', 'members', 'admins'\)\)/i);
  });

  it('creates the auto-profile trigger on auth.users', () => {
    expect(schemaSql).toMatch(/create trigger on_auth_user_created/i);
    expect(schemaSql).toMatch(/after insert on auth\.users/i);
  });
});

describe('0002_rls.sql', () => {
  it('enables RLS on both tables', () => {
    expect(rlsSql).toMatch(/alter table public\.profiles enable row level security/i);
    expect(rlsSql).toMatch(/alter table public\.announcements enable row level security/i);
  });

  it('defines the expected profiles policies', () => {
    for (const policyName of [
      'profiles_select_own',
      'profiles_select_admin_all',
      'profiles_update_own',
    ]) {
      expect(rlsSql).toContain(`create policy ${policyName}`);
    }
  });

  it('defines the expected announcements policies', () => {
    for (const policyName of [
      'announcements_select_public',
      'announcements_select_members',
      'announcements_select_admins',
    ]) {
      expect(rlsSql).toContain(`create policy ${policyName}`);
    }
  });

  it('never grants a profiles policy `to public`', () => {
    // A bare `to public` on a profiles policy means "applies to every role,
    // including anon" -- the specific footgun documented in the README.
    // Every profiles policy in this file must scope `to authenticated`
    // instead.
    const profilesPolicyBlocks = rlsSql
      .split(/create policy /i)
      .filter((block) => block.startsWith('profiles_'));

    expect(profilesPolicyBlocks.length).toBeGreaterThan(0);

    for (const block of profilesPolicyBlocks) {
      expect(block).not.toMatch(/\bto public\b/i);
      expect(block).toMatch(/\bto authenticated\b/i);
    }
  });

  it('restricts the update grant on profiles to display_name only', () => {
    expect(rlsSql).toMatch(/revoke update on public\.profiles from authenticated/i);
    expect(rlsSql).toMatch(/grant update \(display_name\) on public\.profiles to authenticated/i);
  });

  it('uses a SECURITY DEFINER helper to avoid recursive RLS on profiles', () => {
    expect(rlsSql).toMatch(/create or replace function public\.is_admin\(\)/i);
    expect(rlsSql).toMatch(/security definer/i);
  });
});
