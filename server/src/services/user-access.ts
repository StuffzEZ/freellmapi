import crypto from 'node:crypto';
import { getIdentityDb } from '../db/index.js';

export const DEFAULT_TOKENS_PER_MINUTE = 60_000;

export interface UserApiKey {
  id: number;
  label: string;
  prefix: string;
  createdAt: string;
  lastUsedAt: number | null;
  revokedAt: number | null;
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function resolveUserApiKey(token: string | undefined): number | null {
  if (!token || !token.startsWith('flm_user_')) return null;
  const db = getIdentityDb();
  const row = db.prepare(`
    SELECT id, user_id FROM user_api_keys
    WHERE token_hash = ? AND revoked_at_ms IS NULL
  `).get(hashToken(token)) as { id: number; user_id: number } | undefined;
  if (!row) return null;
  db.prepare('UPDATE user_api_keys SET last_used_at_ms = ? WHERE id = ?')
    .run(Date.now(), row.id);
  return row.user_id;
}

export function createUserApiKey(userId: number, label: string): { id: number; token: string } {
  const token = `flm_user_${crypto.randomBytes(32).toString('base64url')}`;
  const result = getIdentityDb().prepare(
    'INSERT INTO user_api_keys (user_id, label, token_hash) VALUES (?, ?, ?)',
  ).run(userId, label.trim() || 'Default', hashToken(token));
  return { id: Number(result.lastInsertRowid), token };
}

export function listUserApiKeys(userId: number): UserApiKey[] {
  const rows = getIdentityDb().prepare(`
    SELECT id, label, token_hash, created_at, last_used_at_ms, revoked_at_ms
    FROM user_api_keys WHERE user_id = ? ORDER BY id DESC
  `).all(userId) as Array<{
    id: number;
    label: string;
    token_hash: string;
    created_at: string;
    last_used_at_ms: number | null;
    revoked_at_ms: number | null;
  }>;
  return rows.map(row => ({
    id: row.id,
    label: row.label,
    prefix: `flm_user_…${row.token_hash.slice(-6)}`,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at_ms,
    revokedAt: row.revoked_at_ms,
  }));
}

export function revokeUserApiKey(userId: number, keyId: number): boolean {
  const result = getIdentityDb().prepare(`
    UPDATE user_api_keys SET revoked_at_ms = ?
    WHERE id = ? AND user_id = ? AND revoked_at_ms IS NULL
  `).run(Date.now(), keyId, userId);
  return result.changes > 0;
}

export function getTokenLimit(userId: number): number {
  const row = getIdentityDb().prepare(
    'SELECT tokens_per_minute FROM user_token_limits WHERE user_id = ?',
  ).get(userId) as { tokens_per_minute: number } | undefined;
  return row?.tokens_per_minute ?? DEFAULT_TOKENS_PER_MINUTE;
}

export function setTokenLimit(userId: number, tokensPerMinute: number): void {
  getIdentityDb().prepare(`
    INSERT INTO user_token_limits (user_id, tokens_per_minute) VALUES (?, ?)
    ON CONFLICT(user_id) DO UPDATE SET tokens_per_minute = excluded.tokens_per_minute
  `).run(userId, tokensPerMinute);
}

export interface TokenReservation {
  allowed: boolean;
  limit: number;
  used: number;
  retryAfterSeconds: number;
}

/** Reserve the estimated prompt+maximum completion tokens atomically. */
export function reserveUserTokens(userId: number, tokens: number, now = Date.now()): TokenReservation {
  const windowStart = Math.floor(now / 60_000) * 60_000;
  const retryAfterSeconds = Math.max(1, Math.ceil((windowStart + 60_000 - now) / 1000));
  const db = getIdentityDb();
  const reserve = db.transaction(() => {
    const limit = getTokenLimit(userId);
    const current = db.prepare(
      'SELECT reserved_tokens FROM user_token_usage WHERE user_id = ? AND window_start_ms = ?',
    ).get(userId, windowStart) as { reserved_tokens: number } | undefined;
    const used = current?.reserved_tokens ?? 0;
    if (tokens > limit - used) return { allowed: false, limit, used };
    db.prepare(`
      INSERT INTO user_token_usage (user_id, window_start_ms, reserved_tokens)
      VALUES (?, ?, ?)
      ON CONFLICT(user_id, window_start_ms)
      DO UPDATE SET reserved_tokens = reserved_tokens + excluded.reserved_tokens
    `).run(userId, windowStart, tokens);
    return { allowed: true, limit, used: used + tokens };
  });
  const result = reserve();
  db.prepare('DELETE FROM user_token_usage WHERE window_start_ms < ?').run(windowStart - 60_000);
  return { ...result, retryAfterSeconds };
}
