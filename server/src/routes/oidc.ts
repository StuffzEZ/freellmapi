import crypto from 'node:crypto';
import { Router } from 'express';
import type { Request, Response } from 'express';
import { z } from 'zod';
import {
  consumeOidcExchangeCode,
  createOidcExchangeCode,
  createSession,
  findOrCreateOidcUser,
} from '../services/auth.js';
import {
  consumeOidcState,
  createOidcState,
  exchangeOidcCode,
  getAuthorizationUrl,
  getOidcConfig,
} from '../services/oidc.js';
import { getIdentityDb } from '../db/index.js';

export const oidcRouter = Router();

const STATE_COOKIE = 'fl_oidc_state';

function cookieValue(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const entry of header.split(';')) {
    const separator = entry.indexOf('=');
    if (separator < 0 || entry.slice(0, separator).trim() !== name) continue;
    return entry.slice(separator + 1).trim();
  }
  return undefined;
}

function setStateCookie(res: Response, state: string, secure: boolean): void {
  res.setHeader(
    'Set-Cookie',
    `${STATE_COOKIE}=${state}; Path=/api/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=300${secure ? '; Secure' : ''}`,
  );
}

function clearStateCookie(res: Response, secure: boolean): void {
  res.setHeader(
    'Set-Cookie',
    `${STATE_COOKIE}=; Path=/api/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=0${secure ? '; Secure' : ''}`,
  );
}

function safeEqual(left: string, right: string): boolean {
  const key = Buffer.alloc(32);
  return crypto.timingSafeEqual(
    crypto.createHmac('sha256', key).update(left).digest(),
    crypto.createHmac('sha256', key).update(right).digest(),
  );
}

oidcRouter.get('/login', async (_req: Request, res: Response) => {
  const config = getOidcConfig();
  if (!config) {
    res.status(404).json({ error: { message: 'Authentik OIDC is not configured', type: 'oidc_not_configured' } });
    return;
  }
  const flow = createOidcState();
  const url = await getAuthorizationUrl(config, flow.state, flow.nonce, flow.codeVerifier);
  setStateCookie(res, flow.state, new URL(config.redirectUri).protocol === 'https:');
  res.redirect(302, url);
});

oidcRouter.get('/callback', async (req: Request, res: Response) => {
  const config = getOidcConfig();
  if (!config) {
    res.status(404).json({ error: { message: 'Authentik OIDC is not configured', type: 'oidc_not_configured' } });
    return;
  }
  const secure = new URL(config.redirectUri).protocol === 'https:';
  const cookieState = cookieValue(req, STATE_COOKIE);
  const returnedState = typeof req.query.state === 'string' ? req.query.state : '';
  const code = typeof req.query.code === 'string' ? req.query.code : '';
  clearStateCookie(res, secure);
  if (!cookieState || !returnedState || !safeEqual(cookieState, returnedState)) {
    res.status(400).json({ error: { message: 'OIDC state validation failed', type: 'authentication_error' } });
    return;
  }
  const flow = consumeOidcState(returnedState);
  if (!flow || !code) {
    res.status(400).json({ error: { message: 'OIDC login expired or was rejected', type: 'authentication_error' } });
    return;
  }
  const identity = await exchangeOidcCode(config, code, flow.nonce, flow.codeVerifier);
  const user = findOrCreateOidcUser(config.issuer, identity.subject, identity.email);
  const exchangeCode = createOidcExchangeCode(user.userId);
  res.redirect(303, `/#oidc_code=${encodeURIComponent(exchangeCode)}`);
});

oidcRouter.post('/exchange', (req: Request, res: Response) => {
  const parsed = z.object({ code: z.string().min(1).max(128) }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: 'A valid OIDC exchange code is required', type: 'invalid_request_error' } });
    return;
  }
  const userId = consumeOidcExchangeCode(parsed.data.code);
  if (userId == null) {
    res.status(401).json({ error: { message: 'OIDC exchange code is invalid or expired', type: 'authentication_error' } });
    return;
  }
  const user = getIdentityDb().prepare('SELECT email FROM users WHERE id = ?')
    .get(userId) as { email: string } | undefined;
  if (!user) {
    res.status(401).json({ error: { message: 'OIDC account no longer exists', type: 'authentication_error' } });
    return;
  }
  res.json({ token: createSession(userId), email: user.email });
});
