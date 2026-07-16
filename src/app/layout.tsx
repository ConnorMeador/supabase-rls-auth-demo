import type { Metadata } from 'next';
import Link from 'next/link';
import './globals.css';

export const metadata: Metadata = {
  title: 'Membership Club — RLS Demo',
  description:
    'A minimal Next.js + Supabase membership app demonstrating role-based access enforced by Postgres Row-Level Security.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <nav>
          <Link href="/">Home</Link>
          <Link href="/login">Login</Link>
          <Link href="/member">Member area</Link>
          <Link href="/admin">Admin</Link>
        </nav>
        <main>{children}</main>
      </body>
    </html>
  );
}
