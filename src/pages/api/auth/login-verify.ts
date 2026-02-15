import type { APIRoute } from 'astro';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import {
  getUser,
  getCredentialById,
  updateCredentialCounter,
  consumeChallenge,
  createSession,
  signCookie,
  sessionCookieOptions,
  base64urlDecode,
} from '../../../lib/auth';

export const POST: APIRoute = async ({ locals, request, url, cookies }) => {
  const db = locals.runtime.env.DB;
  const secret = locals.runtime.env.SESSION_SECRET;

  const body = await request.json();
  const { assertion, challengeId } = body;

  const expectedChallenge = await consumeChallenge(db, challengeId);
  if (!expectedChallenge) {
    return new Response(JSON.stringify({ error: 'Challenge expired or invalid' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const credentialId = assertion.id;
  const credential = await getCredentialById(db, credentialId);
  if (!credential) {
    return new Response(JSON.stringify({ error: 'Unknown credential' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const rpID = url.hostname;
  const origin = url.origin;

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: base64urlDecode(credential.id),
        publicKey: new Uint8Array(credential.public_key),
        counter: credential.counter,
        transports: credential.transports
          ? JSON.parse(credential.transports)
          : undefined,
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Verification failed';
    return new Response(JSON.stringify({ error: message }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (!verification.verified) {
    return new Response(JSON.stringify({ error: 'Verification failed' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  await updateCredentialCounter(
    db,
    credential.id,
    verification.authenticationInfo.newCounter,
  );

  const user = await getUser(db);
  if (!user) {
    return new Response(JSON.stringify({ error: 'User not found' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const sessionId = await createSession(db, user.id);
  const signed = await signCookie(sessionId, secret);
  const isSecure = url.protocol === 'https:';
  cookies.set('session', signed, sessionCookieOptions(isSecure));

  return new Response(JSON.stringify({ verified: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};
