import type { APIRoute } from 'astro';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import {
  generateId,
  getCredentialCount,
  consumeChallenge,
  createUser,
  createCredential,
  createSession,
  signCookie,
  sessionCookieOptions,
  base64urlEncode,
} from '../../../lib/auth';

export const POST: APIRoute = async ({ locals, request, url, cookies }) => {
  const db = locals.runtime.env.DB;
  const secret = locals.runtime.env.SESSION_SECRET;

  const count = await getCredentialCount(db);
  if (count > 0) {
    return new Response(JSON.stringify({ error: 'Registration is closed' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const body = await request.json();
  const { attestation, challengeId, webauthnUserId } = body;

  const expectedChallenge = await consumeChallenge(db, challengeId);
  if (!expectedChallenge) {
    return new Response(JSON.stringify({ error: 'Challenge expired or invalid' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const rpID = url.hostname;
  const origin = url.origin;

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: attestation,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Verification failed';
    return new Response(JSON.stringify({ error: message }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (!verification.verified || !verification.registrationInfo) {
    return new Response(JSON.stringify({ error: 'Verification failed' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { credential, credentialDeviceType, credentialBackedUp } =
    verification.registrationInfo;

  const userId = generateId();
  await createUser(db, {
    id: userId,
    username: 'admin',
    webauthn_user_id: webauthnUserId,
  });

  await createCredential(db, {
    id: base64urlEncode(credential.id),
    user_id: userId,
    public_key: new Uint8Array(credential.publicKey),
    counter: credential.counter,
    device_type: credentialDeviceType,
    backed_up: credentialBackedUp,
    transports: credential.transports,
  });

  const sessionId = await createSession(db, userId);
  const signed = await signCookie(sessionId, secret);
  const isSecure = url.protocol === 'https:';
  cookies.set('session', signed, sessionCookieOptions(isSecure));

  return new Response(JSON.stringify({ verified: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};
