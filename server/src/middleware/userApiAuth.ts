import type { Request, Response, NextFunction } from 'express';
import { getIdentityDb, runWithUserDatabase } from '../db/index.js';
import { resolveUserApiKey } from '../services/user-access.js';
import type { SessionUser } from '../services/auth.js';
import { resolveAuth } from '../lib/system-prompt.js';

function bearer(req: Request): string | undefined {
  const value = req.headers.authorization;
  return value?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
}

/** Select the database belonging to a managed user API key before proxy work. */
export function userApiAuth(req: Request, _res: Response, next: NextFunction): void {
  const token = bearer(req);
  let userId = resolveUserApiKey(token);
  if (userId == null && token && resolveAuth(token)) {
    const owner = getIdentityDb().prepare('SELECT id FROM users ORDER BY id LIMIT 1').get() as { id: number } | undefined;
    userId = owner?.id ?? null;
  }
  if (userId == null) {
    next();
    return;
  }
  const user = { userId, email: '' } satisfies SessionUser;
  (req as Request & { user?: SessionUser }).user = user;
  runWithUserDatabase(userId, () => next());
}
