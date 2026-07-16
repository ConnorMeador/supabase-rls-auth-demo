import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';

export default async function MemberPage() {
  const supabase = await createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect('/login?redirectTo=/member');
  }

  // RLS restricts this to the caller's own row (see the `profiles_select_own`
  // policy in supabase/migrations/0002_rls.sql) — no `.eq('id', user.id)`
  // filter is required for correctness, only for readability. Even without
  // it, a member cannot receive another member's row back from Postgres.
  const { data: profile } = await supabase
    .from('profiles')
    .select('display_name, role')
    .eq('id', user.id)
    .single();

  // RLS filters this to rows with visibility in ('public', 'members') for a
  // signed-in non-admin caller. Admin-only announcements are invisible here
  // even though the query doesn't mention visibility at all.
  const { data: announcements } = await supabase
    .from('announcements')
    .select('id, title, body, visibility')
    .order('id', { ascending: true });

  return (
    <div>
      <span className="badge">Member area</span>
      <h1>Welcome{profile?.display_name ? `, ${profile.display_name}` : ''}</h1>
      <div className="card">
        <p>
          Signed in as <strong>{user.email}</strong> — role: <code>{profile?.role ?? 'member'}</code>
        </p>
      </div>
      <h2>Club announcements</h2>
      {announcements && announcements.length > 0 ? (
        announcements.map((announcement) => (
          <div className="card" key={announcement.id}>
            <p>
              <strong>{announcement.title}</strong>{' '}
              <span className="badge">{announcement.visibility}</span>
            </p>
            <p>{announcement.body}</p>
          </div>
        ))
      ) : (
        <p>No announcements yet.</p>
      )}
    </div>
  );
}
