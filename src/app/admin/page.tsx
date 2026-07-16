import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';

export default async function AdminPage() {
  const supabase = await createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect('/login?redirectTo=/admin');
  }

  // Middleware already redirected non-admins away from /admin, but this
  // page does not rely on that for security — it relies on the
  // `profiles_select_admin_all` RLS policy. A member who somehow reached
  // this page (bug in middleware, direct API call, whatever) still only
  // gets their own single row back from this query, not the full roster.
  const { data: members, error } = await supabase
    .from('profiles')
    .select('id, display_name, role')
    .order('display_name', { ascending: true });

  return (
    <div>
      <span className="badge">Admin — all members</span>
      <h1>Member roster</h1>
      {error && (
        <div className="card">
          <p>Could not load the roster: {error.message}</p>
        </div>
      )}
      {members && members.length > 0 ? (
        members.map((member) => (
          <div className="card" key={member.id}>
            <p>
              <strong>{member.display_name}</strong> — <code>{member.role}</code>
            </p>
          </div>
        ))
      ) : (
        <p>No members found — either the roster is empty, or (if you&apos;re not actually an
          admin) RLS just silently filtered every row out. That silent-filtering behavior is
          exactly what <code>test/rls.integration.test.ts</code> asserts on.</p>
      )}
    </div>
  );
}
