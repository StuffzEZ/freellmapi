import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { connectDb } from '../../db/index.js';
import { runMigrationsSync } from '../../db/migrate/runner.js';
import type { Db } from '../../db/types.js';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import {
  consumeOidcState,
  createOidcState,
  exchangeOidcCode,
  getOidcConfig,
} from '../../services/oidc.js';

describe('OIDC configuration and one-time login state', () => {
  let db: Db;

  beforeEach(() => {
    db = connectDb(':memory:');
    runMigrationsSync(db, 'up');
    vi.stubEnv('OIDC_ISSUER', '');
    vi.stubEnv('OIDC_CLIENT_ID', '');
    vi.stubEnv('OIDC_CLIENT_SECRET', '');
    vi.stubEnv('OIDC_REDIRECT_URI', '');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    db.close?.();
  });

  it('leaves OIDC optional when none of its settings are configured', () => {
    expect(getOidcConfig()).toBeNull();
  });

  it('rejects incomplete or insecure OIDC configuration', () => {
    vi.stubEnv('OIDC_ISSUER', 'https://auth.example.com/application/o/freellmapi/');
    expect(() => getOidcConfig()).toThrow(/requires OIDC_ISSUER/);

    vi.stubEnv('OIDC_CLIENT_ID', 'freellmapi');
    vi.stubEnv('OIDC_CLIENT_SECRET', 'secret');
    vi.stubEnv('OIDC_REDIRECT_URI', 'http://dashboard.example.com/api/auth/oidc/callback');
    expect(() => getOidcConfig()).toThrow(/must use HTTPS/);
  });

  it('accepts localhost HTTP callbacks for development', () => {
    vi.stubEnv('OIDC_ISSUER', 'http://auth.local/application/o/freellmapi/');
    vi.stubEnv('OIDC_CLIENT_ID', 'freellmapi');
    vi.stubEnv('OIDC_CLIENT_SECRET', 'secret');
    vi.stubEnv('OIDC_REDIRECT_URI', 'http://localhost:3001/api/auth/oidc/callback');
    expect(getOidcConfig()).toMatchObject({
      issuer: 'http://auth.local/application/o/freellmapi/',
      redirectUri: 'http://localhost:3001/api/auth/oidc/callback',
    });
  });

  it('consumes login state exactly once', () => {
    const state = createOidcState();
    expect(consumeOidcState(state.state)).toEqual({
      nonce: state.nonce,
      codeVerifier: state.codeVerifier,
    });
    expect(consumeOidcState(state.state)).toBeNull();
  });

  it('verifies the Authentik ID-token signature, issuer, audience, nonce, and email', async () => {
    const issuer = 'https://auth.example.test/application/o/tenant-check/';
    const clientId = 'freellmapi-test';
    const nonce = 'nonce-value';
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const jwk = await exportJWK(publicKey);
    Object.assign(jwk, { kid: 'test-key', alg: 'RS256', use: 'sig' });
    const idToken = await new SignJWT({
      nonce,
      email: 'person@example.test',
      email_verified: true,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(issuer)
      .setAudience(clientId)
      .setSubject('authentik-subject')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    const metadata = {
      issuer,
      authorization_endpoint: `${issuer}authorize/`,
      token_endpoint: `${issuer}token/`,
      jwks_uri: `${issuer}jwks/`,
    };
    vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('.well-known/openid-configuration')) {
        return new Response(JSON.stringify(metadata), { status: 200 });
      }
      if (url === metadata.token_endpoint) {
        return new Response(JSON.stringify({ id_token: idToken }), { status: 200 });
      }
      if (url === metadata.jwks_uri) {
        return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
      }
      return new Response('', { status: 404 });
    });

    const result = await exchangeOidcCode({
      issuer,
      clientId,
      clientSecret: 'test-secret',
      redirectUri: 'https://service.example.test/api/auth/oidc/callback',
    }, 'authorization-code', nonce, 'pkce-verifier');
    expect(result).toEqual({ subject: 'authentik-subject', email: 'person@example.test' });
  });
});
