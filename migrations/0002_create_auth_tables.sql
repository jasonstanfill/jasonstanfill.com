-- Users table: single admin row
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  webauthn_user_id TEXT NOT NULL UNIQUE
);

-- WebAuthn credentials
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL DEFAULT 0,
  transports TEXT -- JSON array
);

-- Server-side sessions
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL
);

-- Temporary WebAuthn challenge storage
CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  challenge TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
