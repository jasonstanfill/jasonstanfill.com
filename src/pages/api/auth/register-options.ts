import type { APIRoute } from 'astro';
import { generateRegistrationOptions } from '@simplewebauthn/server';
import {
  getCredentialCount,
  createChallenge,
  base64urlEncode,
} from '../../../lib/auth';

export const POST: APIRoute = async ({ locals, url }) => {
  const db = locals.runtime.env.DB;

  const count = await getCredentialCount(db);
  if (count > 0) {
    return new Response(JSON.stringify({ error: 'Registration is closed' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const rpID = url.hostname;
  const userIdBytes = new Uint8Array(32);
  crypto.getRandomValues(userIdBytes);

  const options = await generateRegistrationOptions({
    rpName: 'Jason Stanfill',
    rpID,
    userName: 'admin',
    userDisplayName: 'Admin',
    userID: userIdBytes,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  const challengeId = await createChallenge(db, options.challenge);

  return new Response(
    JSON.stringify({
      options,
      challengeId,
      webauthnUserId: base64urlEncode(userIdBytes),
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
};
