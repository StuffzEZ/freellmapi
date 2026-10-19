import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Express } from 'express';
import { createApp } from '../../app.js';
import { initDb } from '../../db/index.js';
import { loadConfig } from '../../lib/config.js';
import { createSession, createUser } from '../../services/auth.js';
import { createUserApiKey, setTokenLimit } from '../../services/user-access.js';

describe('multi-user dashboard and inference isolation', () => {
  let app: Express;
  let server: ReturnType<Express['listen']>;
  let origin: string;
  let ownerSession: string;
  let userSession: string;
  let userApiKey: string;

  beforeAll(async () => {
    process.env.ENCRYPTION_KEY = '0'.repeat(64);
    process.env.PROXY_RATE_LIMIT_RPM = '0';
    initDb(':memory:');
    const owner = createUser('owner@example.com', 'owner-password');
    const user = createUser('user@example.com', 'user-password');
    ownerSession = createSession(owner.userId);
    userSession = createSession(user.userId);
    userApiKey = createUserApiKey(user.userId, 'user-client').token;
    setTokenLimit(user.userId, 1);

    app = createApp({ ...loadConfig(), serveStaticAssets: false });
    server = app.listen(0, '127.0.0.1');
    if (!server.listening) await new Promise<void>(resolve => server.once('listening', resolve));
    const address = server.address() as AddressInfo;
    origin = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await new Promise<void>(resolve => server.close(() => resolve()));
  });

  async function call(path: string, token: string, init?: RequestInit): Promise<Response> {
    return fetch(`${origin}${path}`, {
      ...init,
      headers: {
        ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
        Authorization: `Bearer ${token}`,
        ...init?.headers,
      },
    });
  }

  it('keeps dashboard API-key settings separate per signed-in user', async () => {
    const ownerResponse = await call('/api/settings/api-key', ownerSession);
    const userResponse = await call('/api/settings/api-key', userSession);
    expect(ownerResponse.status).toBe(200);
    expect(userResponse.status).toBe(200);
    const owner = await ownerResponse.json() as { apiKey: string };
    const user = await userResponse.json() as { apiKey: string };
    expect(owner.apiKey).not.toBe(user.apiKey);

    const accessResponse = await call('/api/account/access', userSession);
    expect(accessResponse.status).toBe(200);
    const access = await accessResponse.json() as {
      tokensPerMinute: number;
      apiKeys: Array<{ prefix: string; revokedAt: number | null }>;
    };
    expect(access.tokensPerMinute).toBe(1);
    expect(access.apiKeys).toHaveLength(1);
    expect(access.apiKeys[0].revokedAt).toBeNull();
    expect(access.apiKeys[0].prefix).toContain('…');
  });

  it('accepts the per-user Bearer key and applies that user’s token cap', async () => {
    const models = await call('/v1/models', userApiKey);
    expect(models.status).toBe(200);

    const response = await call('/v1/chat/completions', userApiKey, {
      method: 'POST',
      body: JSON.stringify({
        model: 'auto',
        messages: [{ role: 'user', content: 'hello' }],
        max_tokens: 0,
      }),
    });
    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBeTruthy();
    expect(await response.json()).toMatchObject({
      error: { type: 'rate_limit_error', code: 'user_token_limit_exceeded' },
    });
  });
});
