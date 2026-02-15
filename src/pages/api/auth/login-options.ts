import type { APIRoute } from 'astro';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import {
  getUser,
  getCredentialsByUserId,
  createChallenge,
  base64urlDecode,
} from '../../../lib/auth';

export const POST: APIRoute = async ({ locals, url }) => {
  const db = locals.runtime.env.DB;

  const user = await getUser(db);
  if (!user) {
    return new Response(JSON.stringify({ error: 'No registered user' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const credentials = await getCredentialsByUserId(db, user.id);
  const rpID = url.hostname;

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: credentials.map((cred) => ({
      id: base64urlDecode(cred.id),
      transports: cred.transports ? JSON.parse(cred.transports) : undefined,
    })),
    userVerification: 'preferred',
  });

  const challengeId = await createChallenge(db, options.challenge);

  return new Response(JSON.stringify({ options, challengeId }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};
