import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

/**
 * Role gate for /member and /admin.
 *
 * This middleware is a UX convenience, NOT the security boundary. It reads
 * the session and the caller's `role` (from the `profiles` table, looked up
 * by the authenticated user's id — never trusted from a client-supplied
 * cookie or header) and redirects obviously-unauthorized visitors before a
 * page even renders. The real boundary is Postgres RLS: even if this
 * middleware had a bug and let someone through, the `profiles` and
 * `announcements` queries on the /member and /admin pages would still
 * return zero rows for a caller whose role doesn't match — see
 * `supabase/migrations/0002_rls.sql`.
 *
 * Bug I actually hit building the real version of this: an earlier draft
 * cached the role in a plain cookie set at login and never re-checked it
 * against the database on subsequent requests. Promote someone to admin (or
 * demote them) and the cookie was stale until they logged out — a user
 * could keep member access to admin-gated UI chrome after being demoted.
 * This version re-reads `profiles.role` from the database on every request
 * to /member and /admin instead of trusting anything client-supplied.
 */
export async function middleware(request: NextRequest) {
  const response = NextResponse.next({ request });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL as string,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY as string,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
          cookiesToSet.forEach(({ name, value, options }) =>
            response.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  const {
    data: { user },
  } = await supabase.auth.getUser();

  const path = request.nextUrl.pathname;
  const isMemberRoute = path.startsWith('/member');
  const isAdminRoute = path.startsWith('/admin');

  if (!isMemberRoute && !isAdminRoute) {
    return response;
  }

  if (!user) {
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('redirectTo', path);
    return NextResponse.redirect(loginUrl);
  }

  // Role comes from the database, looked up by the verified user id — never
  // from a request header or cookie the caller could forge.
  const { data: profile } = await supabase
    .from('profiles')
    .select('role')
    .eq('id', user.id)
    .single();

  const role = profile?.role ?? 'member';

  if (isAdminRoute && role !== 'admin') {
    return NextResponse.redirect(new URL('/member', request.url));
  }

  return response;
}

export const config = {
  matcher: ['/member/:path*', '/admin/:path*'],
};
