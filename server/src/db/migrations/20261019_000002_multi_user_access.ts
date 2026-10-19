import type { Db } from '../types.js';

export function up(db: Db): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS oidc_identities (
      issuer TEXT NOT NULL,
      subject TEXT NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (issuer, subject),
      UNIQUE (user_id, issuer)
    );

    CREATE TABLE IF NOT EXISTS user_api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      label TEXT NOT NULL DEFAULT 'Default',
      token_hash TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_used_at_ms INTEGER,
      revoked_at_ms INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_user_api_keys_user ON user_api_keys(user_id, revoked_at_ms);

    CREATE TABLE IF NOT EXISTS user_token_limits (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      tokens_per_minute INTEGER NOT NULL DEFAULT 60000 CHECK (tokens_per_minute >= 0)
    );

    CREATE TABLE IF NOT EXISTS user_token_usage (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      window_start_ms INTEGER NOT NULL,
      reserved_tokens INTEGER NOT NULL,
      PRIMARY KEY (user_id, window_start_ms)
    );
    CREATE INDEX IF NOT EXISTS idx_user_token_usage_window ON user_token_usage(window_start_ms);

    CREATE TABLE IF NOT EXISTS oidc_exchange_codes (
      code_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at_ms INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS oidc_auth_states (
      state_hash TEXT PRIMARY KEY,
      nonce TEXT NOT NULL,
      code_verifier TEXT NOT NULL,
      expires_at_ms INTEGER NOT NULL
    );
  `);
}

export function down(db: Db): void {
  db.exec(`
    DROP TABLE IF EXISTS oidc_auth_states;
    DROP TABLE IF EXISTS oidc_exchange_codes;
    DROP TABLE IF EXISTS user_token_usage;
    DROP TABLE IF EXISTS user_token_limits;
    DROP TABLE IF EXISTS user_api_keys;
    DROP TABLE IF EXISTS oidc_identities;
  `);
}
