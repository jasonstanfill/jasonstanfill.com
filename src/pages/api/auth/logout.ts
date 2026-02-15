import type { APIRoute } from 'astro';
import { verifyCookie, deleteSession } from '../../../lib/auth';

export const POST: APIRoute = async ({ locals, cookies, url }) => {
  const db = locals.runtime.env.DB;
  const secret = locals.runtime.env.SESSION_SECRET;

  const signedSession = cookies.get('session')?.value;
  if (signedSession) {
    const sessionId = await verifyCookie(signedSession, secret);
    if (sessionId) {
      await deleteSession(db, sessionId);
    }
  }

  const isSecure = url.protocol === 'https:';
  cookies.delete('session', {
    path: '/',
    httpOnly: true,
    secure: isSecure,
    sameSite: 'lax',
  });

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};
