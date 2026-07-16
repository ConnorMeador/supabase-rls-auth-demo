import { randomUUID } from 'node:crypto';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * The centerpiece of this repo.
 *
 * Everything else here (the Next.js pages, the middleware role gate) is
 * scaffolding. This file is the proof: it stands up two real user accounts
 * against a real local Postgres instance (via `supabase start`), signs in
 * as each, and asserts that the RLS policies in
 * supabase/migrations/0002_rls.sql actually do what their comments claim.
 *
 * Requires SUPABASE_URL, SUPABASE_ANON_KEY, and SUPABASE_SERVICE_ROLE_KEY in
 * the environment (all three are printed by `supabase start`). Without
 * them, this whole suite is skipped -- not failed -- so `pnpm test` stays
 * green on a laptop with no local Supabase running. CI provisions the real
 * thing; see .github/workflows/test.yml.
 */

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const hasLocalSupabase = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY && SUPABASE_SERVICE_ROLE_KEY);

describe.skipIf(!hasLocalSupabase)('RLS policies (requires `supabase start`)', () => {
  let admin: SupabaseClient;
  let memberClient: SupabaseClient;
  let adminClient: SupabaseClient;

  let memberUserId: string;
  let adminUserId: string;

  const runId = randomUUID().slice(0, 8);
  const memberEmail = `member-${runId}@example.test`;
  const adminEmail = `admin-${runId}@example.test`;
  const password = `test-password-${runId}!`;

  let publicAnnouncementTitle: string;
  let membersAnnouncementTitle: string;
  let adminsAnnouncementTitle: string;

  beforeAll(async () => {
    // service_role bypasses RLS entirely -- this client stands in for
    // "trusted server-side code", never the browser. It's how the test
    // provisions fixtures without depending on the very policies it's
    // trying to test.
    admin = createClient(SUPABASE_URL as string, SUPABASE_SERVICE_ROLE_KEY as string, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: memberUser, error: memberCreateError } = await admin.auth.admin.createUser({
      email: memberEmail,
      password,
      email_confirm: true,
    });
    if (memberCreateError || !memberUser.user) {
      throw new Error(`failed to create member fixture user: ${memberCreateError?.message}`);
    }
    memberUserId = memberUser.user.id;

    const { data: adminUser, error: adminCreateError } = await admin.auth.admin.createUser({
      email: adminEmail,
      password,
      email_confirm: true,
    });
    if (adminCreateError || !adminUser.user) {
      throw new Error(`failed to create admin fixture user: ${adminCreateError?.message}`);
    }
    adminUserId = adminUser.user.id;

    // Promoting to admin via the service-role client is the ONLY supported
    // path -- see the profiles_update_own + column-grant policies in
    // 0002_rls.sql. There is deliberately no app-level "make me an admin"
    // button.
    const { error: promoteError } = await admin
      .from('profiles')
      .update({ role: 'admin' })
      .eq('id', adminUserId);
    if (promoteError) {
      throw new Error(`failed to promote fixture user to admin: ${promoteError.message}`);
    }

    publicAnnouncementTitle = `Public notice ${runId}`;
    membersAnnouncementTitle = `Members-only notice ${runId}`;
    adminsAnnouncementTitle = `Admins-only notice ${runId}`;

    const { error: seedError } = await admin.from('announcements').insert([
      { title: publicAnnouncementTitle, body: 'visible to everyone', visibility: 'public' },
      { title: membersAnnouncementTitle, body: 'visible to signed-in members', visibility: 'members' },
      { title: adminsAnnouncementTitle, body: 'visible to admins only', visibility: 'admins' },
    ]);
    if (seedError) {
      throw new Error(`failed to seed announcements fixture: ${seedError.message}`);
    }

    // Anon-key clients, signed in as each fixture user -- these are what
    // actually exercise RLS, exactly like the app's browser/server clients
    // do. (The app signs users in via magic link; password sign-in here is
    // just the fastest way for a test harness to get an authenticated
    // session -- RLS doesn't care which auth method produced it.)
    memberClient = createClient(SUPABASE_URL as string, SUPABASE_ANON_KEY as string, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { error: memberSignInError } = await memberClient.auth.signInWithPassword({
      email: memberEmail,
      password,
    });
    if (memberSignInError) {
      throw new Error(`member fixture sign-in failed: ${memberSignInError.message}`);
    }

    adminClient = createClient(SUPABASE_URL as string, SUPABASE_ANON_KEY as string, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { error: adminSignInError } = await adminClient.auth.signInWithPassword({
      email: adminEmail,
      password,
    });
    if (adminSignInError) {
      throw new Error(`admin fixture sign-in failed: ${adminSignInError.message}`);
    }
  });

  afterAll(async () => {
    // Best-effort cleanup so repeated local runs don't accumulate fixture
    // users. Admin API delete cascades to the profiles row via the
    // `on delete cascade` foreign key in 0001_schema.sql.
    if (memberUserId) await admin.auth.admin.deleteUser(memberUserId);
    if (adminUserId) await admin.auth.admin.deleteUser(adminUserId);
    if (publicAnnouncementTitle) {
      await admin
        .from('announcements')
        .delete()
        .in('title', [publicAnnouncementTitle, membersAnnouncementTitle, adminsAnnouncementTitle]);
    }
  });

  it("a member cannot read another member's profile row", async () => {
    const { data, error } = await memberClient.from('profiles').select('*').eq('id', adminUserId);

    // This is the sharpest edge in the whole demo: RLS does not raise an
    // error for a denied row. The query succeeds and returns an EMPTY
    // ARRAY, indistinguishable at the client from "no row with that id
    // exists". A test (or a developer) that only checks `!error` would see
    // this pass even if the policy were silently broken -- you have to
    // assert on the row COUNT, not just the absence of an error.
    expect(error).toBeNull();
    expect(data).toEqual([]);
  });

  it('a member CAN read their own profile row', async () => {
    const { data, error } = await memberClient.from('profiles').select('*').eq('id', memberUserId);

    expect(error).toBeNull();
    expect(data).toHaveLength(1);
    expect(data?.[0]?.id).toBe(memberUserId);
    expect(data?.[0]?.role).toBe('member');
  });

  it('a member sees public and members-tier announcements but not admins-tier', async () => {
    const { data, error } = await memberClient
      .from('announcements')
      .select('title, visibility')
      .in('title', [publicAnnouncementTitle, membersAnnouncementTitle, adminsAnnouncementTitle]);

    expect(error).toBeNull();
    const titles = (data ?? []).map((row) => row.title);

    expect(titles).toContain(publicAnnouncementTitle);
    expect(titles).toContain(membersAnnouncementTitle);
    expect(titles).not.toContain(adminsAnnouncementTitle);
    expect(data).toHaveLength(2);
  });

  it('a member cannot escalate their own role to admin', async () => {
    const { error: updateError } = await memberClient
      .from('profiles')
      .update({ role: 'admin' })
      .eq('id', memberUserId);

    // The column-level grant restriction in 0002_rls.sql (`grant update
    // (display_name) ...`) makes this fail outright with a Postgres
    // permission error rather than silently no-op-ing.
    expect(updateError).not.toBeNull();

    // Re-check with the service-role client (bypasses RLS) that the row
    // genuinely never changed -- don't just trust the error message.
    const { data: verifyRow } = await admin
      .from('profiles')
      .select('role')
      .eq('id', memberUserId)
      .single();
    expect(verifyRow?.role).toBe('member');
  });

  it('an admin can list every member profile', async () => {
    const { data, error } = await adminClient
      .from('profiles')
      .select('id, role')
      .in('id', [memberUserId, adminUserId]);

    expect(error).toBeNull();
    expect(data).toHaveLength(2);
    const roleById = new Map((data ?? []).map((row) => [row.id, row.role]));
    expect(roleById.get(memberUserId)).toBe('member');
    expect(roleById.get(adminUserId)).toBe('admin');
  });

  it('an admin sees announcements at every visibility tier', async () => {
    const { data, error } = await adminClient
      .from('announcements')
      .select('title')
      .in('title', [publicAnnouncementTitle, membersAnnouncementTitle, adminsAnnouncementTitle]);

    expect(error).toBeNull();
    expect(data).toHaveLength(3);
  });
});
