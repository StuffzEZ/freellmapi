import crypto from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { getIdentityDb } from '../db/index.js';

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

interface OidcMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

interface OidcIdentity {
  subject: string;
  email: string;
}

interface OidcState {
  nonce: string;
  codeVerifier: string;
}

interface OidcStateRow {
  nonce: string;
  code_verifier: string;
  expires_at_ms: number;
}

let metadataCache: { issuer: string; metadata: OidcMetadata } | undefined;
let jwksCache: { uri: string; keys: ReturnType<typeof createRemoteJWKSet> } | undefined;

export function getOidcConfig(): OidcConfig | null {
  const values = {
    issuer: process.env.OIDC_ISSUER?.trim(),
    clientId: process.env.OIDC_CLIENT_ID?.trim(),
    clientSecret: process.env.OIDC_CLIENT_SECRET?.trim(),
    redirectUri: process.env.OIDC_REDIRECT_URI?.trim(),
  };
  if (Object.values(values).every(value => !value)) return null;
  if (Object.values(values).some(value => !value)) {
    throw new Error('OIDC requires OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_REDIRECT_URI.');
  }
  const issuer = new URL(values.issuer!);
  const redirect = new URL(values.redirectUri!);
  if (!['http:', 'https:'].includes(issuer.protocol) || !['http:', 'https:'].includes(redirect.protocol)) {
    throw new Error('OIDC issuer and redirect URI must use http or https.');
  }
  if (redirect.protocol !== 'https:' && redirect.hostname !== 'localhost' && redirect.hostname !== '127.0.0.1') {
    throw new Error('OIDC_REDIRECT_URI must use HTTPS except on localhost.');
  }
  return {
    issuer: values.issuer!,
    clientId: values.clientId!,
    clientSecret: values.clientSecret!,
    redirectUri: values.redirectUri!,
  };
}

export function oidcEnabled(): boolean {
  return getOidcConfig() !== null;
}

async function getMetadata(config: OidcConfig): Promise<OidcMetadata> {
  if (metadataCache?.issuer === config.issuer) return metadataCache.metadata;
  const issuerBase = config.issuer.endsWith('/') ? config.issuer : `${config.issuer}/`;
  const discoveryUrl = new URL('.well-known/openid-configuration', issuerBase);
  const response = await fetch(discoveryUrl, { signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error(`OIDC discovery returned HTTP ${response.status}`);
  const metadata = await response.json() as Partial<OidcMetadata>;
  const normalizeIssuer = (value: string) => value.trim().replace(/\/+$/, '');
  if (
    typeof metadata.issuer !== 'string' ||
    normalizeIssuer(metadata.issuer) !== normalizeIssuer(config.issuer) ||
    typeof metadata.authorization_endpoint !== 'string' ||
    typeof metadata.token_endpoint !== 'string' ||
    typeof metadata.jwks_uri !== 'string'
  ) {
    throw new Error('OIDC discovery metadata is incomplete or has a mismatched issuer.');
  }
  metadataCache = { issuer: config.issuer, metadata: metadata as OidcMetadata };
  return metadataCache.metadata;
}

function sha256(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function createOidcState(): { state: string; nonce: string; codeVerifier: string } {
  const state = crypto.randomBytes(32).toString('base64url');
  const nonce = crypto.randomBytes(32).toString('base64url');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const db = getIdentityDb();
  db.prepare('DELETE FROM oidc_auth_states WHERE expires_at_ms <= ?').run(Date.now());
  db.prepare(`
    INSERT INTO oidc_auth_states (state_hash, nonce, code_verifier, expires_at_ms)
    VALUES (?, ?, ?, ?)
  `).run(sha256(state), nonce, codeVerifier, Date.now() + 5 * 60_000);
  return { state, nonce, codeVerifier };
}

export function consumeOidcState(state: string): OidcState | null {
  const db = getIdentityDb();
  const consume = db.transaction(() => {
    const hash = sha256(state);
    const row = db.prepare(`
      SELECT nonce, code_verifier, expires_at_ms FROM oidc_auth_states WHERE state_hash = ?
    `).get(hash) as OidcStateRow | undefined;
    db.prepare('DELETE FROM oidc_auth_states WHERE state_hash = ?').run(hash);
    return row && row.expires_at_ms > Date.now()
      ? { nonce: row.nonce, codeVerifier: row.code_verifier }
      : null;
  });
  return consume();
}

export async function getAuthorizationUrl(
  config: OidcConfig,
  state: string,
  nonce: string,
  codeVerifier: string,
): Promise<string> {
  const metadata = await getMetadata(config);
  const challenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  const url = new URL(metadata.authorization_endpoint);
  url.search = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();
  return url.toString();
}

export async function exchangeOidcCode(
  config: OidcConfig,
  code: string,
  nonce: string,
  codeVerifier: string,
): Promise<OidcIdentity> {
  const metadata = await getMetadata(config);
  const basicAuth = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');
  const response = await fetch(metadata.token_endpoint, {
    method: 'POST',
    headers: {
      authorization: `Basic ${basicAuth}`,
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.redirectUri,
      code_verifier: codeVerifier,
    }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`OIDC token exchange returned HTTP ${response.status}`);
  const tokens = await response.json() as { id_token?: unknown };
  if (typeof tokens.id_token !== 'string') throw new Error('OIDC token response did not include an ID token.');

  if (jwksCache?.uri !== metadata.jwks_uri) {
    jwksCache = { uri: metadata.jwks_uri, keys: createRemoteJWKSet(new URL(metadata.jwks_uri)) };
  }
   const { payload } = await jwtVerify(tokens.id_token, jwksCache.keys, {
     issuer: [config.issuer, metadata.issuer].filter((value, index, items) => items.indexOf(value) === index),
     audience: config.clientId,
   });
  if (typeof payload.sub !== 'string' || typeof payload.nonce !== 'string' || payload.nonce !== nonce) {
    throw new Error('OIDC ID token subject or nonce is invalid.');
  }
  if (typeof payload.email !== 'string' || payload.email_verified !== true) {
    throw new Error('Authentik must return a verified email address in the ID token.');
  }
  return { subject: payload.sub, email: payload.email };
}
