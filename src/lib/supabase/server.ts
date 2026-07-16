import { cookies } from 'next/headers';
import { createServerClient } from '@supabase/ssr';

/**
 * Server-side Supabase client for Server Components, Route Handlers, and
 * Server Actions. Reads/writes the auth session via cookies. Like the
 * browser client, it uses the anon key — RLS is the enforcement boundary,
 * not this key.
 *
 * `cookies()` is async in the App Router (Next.js 15+), so this helper is
 * async too. Server Component `set` calls are no-ops by design (a Server
 * Component can't write response cookies); session refresh happens in
 * `src/middleware.ts` instead.
 */
export async function createClient() {
  const cookieStore = await cookies();

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL as string,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY as string,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) => {
              cookieStore.set(name, value, options);
            });
          } catch {
            // Called from a Server Component — cookies can't be written
            // here. Session refresh is handled by middleware instead.
          }
        },
      },
    }
  );
}
