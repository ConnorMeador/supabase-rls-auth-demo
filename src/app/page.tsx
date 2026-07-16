import Link from 'next/link';

export default function HomePage() {
  return (
    <div>
      <span className="badge">Portfolio sample</span>
      <h1>Membership Club</h1>
      <p>
        This is a demo membership app. Anyone can read this landing page. Members get a private
        area with club announcements. Admins get a roster of every member. The interesting part
        isn&apos;t the UI — it&apos;s that the access rules are enforced twice: once in Next.js
        middleware (fast, convenient, easy to get wrong) and once in Postgres Row-Level Security
        (slow to bypass, hard to forget about, the actual security boundary).
      </p>
      <div className="card">
        <p>
          <strong>Read the code, not just this page:</strong> <code>supabase/migrations/</code>{' '}
          has the RLS policies, and <code>test/rls.integration.test.ts</code> proves — with a real
          local Postgres instance — that a member account genuinely cannot read another member&apos;s
          profile, cannot see admin-only announcements, and cannot promote itself to admin.
        </p>
      </div>
      <p>
        <Link href="/login">Log in</Link> to see the member or admin views (requires a local
        Supabase instance — see the README).
      </p>
    </div>
  );
}
