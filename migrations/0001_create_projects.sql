CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  url TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO projects (title, description, url)
VALUES (
  'jasonstanfill.com',
  'My personal website, built with Astro, Tailwind CSS, and Cloudflare D1.',
  'https://jasonstanfill.com'
);
