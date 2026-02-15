import { defineMiddleware } from 'astro:middleware';
import { verifyCookie, getSession } from './lib/auth';

const PUBLIC_PATHS = ['/login', '/api/auth/'];

function isPublic(pathname: string): boolean {
  return PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p));
}

export const onRequest = defineMiddleware(async (context, next) => {
  const { cookies, redirect, url } = context;
  const env = context.locals.runtime.env;
  const db = env.DB;
  const secret = env.SESSION_SECRET;

  // Default to unauthenticated
  context.locals.user = null;

  const signedSession = cookies.get('session')?.value;
  if (signedSession) {
    const sessionId = await verifyCookie(signedSession, secret);
    if (sessionId) {
      const session = await getSession(db, sessionId);
      if (session) {
        context.locals.user = {
          id: session.user_id,
          username: session.username,
        };
      }
    }
  }

  if (!context.locals.user && !isPublic(url.pathname)) {
    return redirect('/login', 302);
  }

  return next();
});
