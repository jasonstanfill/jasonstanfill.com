type D1Database = import('@cloudflare/workers-types').D1Database;

// --- Constants ---

export const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
export const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const SESSION_COOKIE = 'session';

// --- Base64url helpers ---

export function base64urlEncode(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// --- HMAC Cookie Signing ---

async function getSigningKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

export async function signCookie(value: string, secret: string): Promise<string> {
  const key = await getSigningKey(secret);
  const enc = new TextEncoder();
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(value));
  return `${value}.${base64urlEncode(sig)}`;
}

export async function verifyCookie(
  signed: string,
  secret: string,
): Promise<string | null> {
  const lastDot = signed.lastIndexOf('.');
  if (lastDot === -1) return null;
  const value = signed.slice(0, lastDot);
  const sig = base64urlDecode(signed.slice(lastDot + 1));
  const key = await getSigningKey(secret);
  const enc = new TextEncoder();
  const valid = await crypto.subtle.verify('HMAC', key, sig, enc.encode(value));
  return valid ? value : null;
}

// --- Session helpers ---

export function generateId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

export function sessionCookieOptions(secure: boolean) {
  return {
    name: SESSION_COOKIE,
    httpOnly: true,
    secure,
    sameSite: 'lax' as const,
    path: '/',
    maxAge: SESSION_DURATION_MS / 1000,
  };
}

// --- D1 query helpers ---

export interface DbUser {
  id: string;
  username: string;
  webauthn_user_id: string;
}

export interface DbCredential {
  id: string;
  user_id: string;
  public_key: ArrayBuffer;
  counter: number;
  device_type: string;
  backed_up: number;
  transports: string | null;
}

export interface DbSession {
  id: string;
  user_id: string;
  expires_at: string;
}

// Users

export async function getUser(db: D1Database): Promise<DbUser | null> {
  const row = await db.prepare('SELECT * FROM users LIMIT 1').first<DbUser>();
  return row ?? null;
}

export async function createUser(
  db: D1Database,
  user: DbUser,
): Promise<void> {
  await db
    .prepare('INSERT INTO users (id, username, webauthn_user_id) VALUES (?, ?, ?)')
    .bind(user.id, user.username, user.webauthn_user_id)
    .run();
}

// Credentials

export async function getCredentialCount(db: D1Database): Promise<number> {
  const row = await db
    .prepare('SELECT COUNT(*) as count FROM credentials')
    .first<{ count: number }>();
  return row?.count ?? 0;
}

export async function getCredentialById(
  db: D1Database,
  id: string,
): Promise<DbCredential | null> {
  const row = await db
    .prepare('SELECT * FROM credentials WHERE id = ?')
    .bind(id)
    .first<DbCredential>();
  return row ?? null;
}

export async function getCredentialsByUserId(
  db: D1Database,
  userId: string,
): Promise<DbCredential[]> {
  const { results } = await db
    .prepare('SELECT * FROM credentials WHERE user_id = ?')
    .bind(userId)
    .all<DbCredential>();
  return results;
}

export async function createCredential(
  db: D1Database,
  cred: {
    id: string;
    user_id: string;
    public_key: Uint8Array;
    counter: number;
    device_type: string;
    backed_up: boolean;
    transports?: string[];
  },
): Promise<void> {
  await db
    .prepare(
      'INSERT INTO credentials (id, user_id, public_key, counter, device_type, backed_up, transports) VALUES (?, ?, ?, ?, ?, ?, ?)',
    )
    .bind(
      cred.id,
      cred.user_id,
      cred.public_key as unknown as ArrayBuffer,
      cred.counter,
      cred.device_type,
      cred.backed_up ? 1 : 0,
      cred.transports ? JSON.stringify(cred.transports) : null,
    )
    .run();
}

export async function updateCredentialCounter(
  db: D1Database,
  id: string,
  counter: number,
): Promise<void> {
  await db
    .prepare('UPDATE credentials SET counter = ? WHERE id = ?')
    .bind(counter, id)
    .run();
}

// Sessions

export async function createSession(
  db: D1Database,
  userId: string,
): Promise<string> {
  const id = generateId();
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();
  await db
    .prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(id, userId, expiresAt)
    .run();
  return id;
}

export async function getSession(
  db: D1Database,
  id: string,
): Promise<(DbSession & { username: string }) | null> {
  const row = await db
    .prepare(
      'SELECT sessions.*, users.username FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.id = ? AND sessions.expires_at > datetime(\'now\')',
    )
    .bind(id)
    .first<DbSession & { username: string }>();
  return row ?? null;
}

export async function deleteSession(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run();
}

// Challenges

export async function createChallenge(
  db: D1Database,
  challenge: string,
): Promise<string> {
  const id = generateId();
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();
  await db
    .prepare('INSERT INTO challenges (id, challenge, expires_at) VALUES (?, ?, ?)')
    .bind(id, challenge, expiresAt)
    .run();
  return id;
}

export async function consumeChallenge(
  db: D1Database,
  id: string,
): Promise<string | null> {
  const row = await db
    .prepare(
      'SELECT * FROM challenges WHERE id = ? AND expires_at > datetime(\'now\')',
    )
    .bind(id)
    .first<{ challenge: string }>();
  if (!row) return null;
  await db.prepare('DELETE FROM challenges WHERE id = ?').bind(id).run();
  return row.challenge;
}
