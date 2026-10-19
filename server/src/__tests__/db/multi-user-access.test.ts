import { afterEach, describe, expect, it } from 'vitest';
import { connectDb, getDb, runWithUserDatabase } from '../../db/index.js';
import { runMigrationsSync } from '../../db/migrate/runner.js';
import type { Db } from '../../db/types.js';
import { createUser } from '../../services/auth.js';
import {
  createUserApiKey,
  getTokenLimit,
  reserveUserTokens,
  resolveUserApiKey,
  setTokenLimit,
} from '../../services/user-access.js';

describe('multi-user access and tenant databases', () => {
  let primary: Db | undefined;
  let tenant: Db | undefined;

  afterEach(() => {
    if (tenant && tenant !== primary) tenant.close?.();
    primary?.close?.();
    tenant = undefined;
    primary = undefined;
  });

  function initialize(): { ownerId: number; secondUserId: number } {
    primary = connectDb(':memory:');
    runMigrationsSync(primary, 'up');
    const owner = createUser('owner@example.com', 'owner-password');
    const second = createUser('second@example.com', 'second-password');
    return { ownerId: owner.userId, secondUserId: second.userId };
  }

  it('routes each dashboard request to its own SQLite database', () => {
    const { ownerId, secondUserId } = initialize();

    runWithUserDatabase(secondUserId, () => {
      tenant = getDb();
      getDb().prepare("INSERT INTO settings (key, value) VALUES ('private-setting', 'second-user')").run();
    });

    const ownerSetting = primary!.prepare("SELECT value FROM settings WHERE key = 'private-setting'").get();
    const secondSetting = runWithUserDatabase(secondUserId, () =>
      getDb().prepare("SELECT value FROM settings WHERE key = 'private-setting'").get(),
    );
    expect(ownerSetting).toBeUndefined();
    expect(secondSetting).toEqual({ value: 'second-user' });
    expect(runWithUserDatabase(ownerId, () => getDb())).toBe(primary);
  });

  it('issues independently revocable bearer keys and token budgets per user', () => {
    const { ownerId, secondUserId } = initialize();
    const ownerKey = createUserApiKey(ownerId, 'owner');
    const secondKey = createUserApiKey(secondUserId, 'second');

    expect(resolveUserApiKey(ownerKey.token)).toBe(ownerId);
    expect(resolveUserApiKey(secondKey.token)).toBe(secondUserId);
    expect(resolveUserApiKey(`${secondKey.token}x`)).toBeNull();

    setTokenLimit(secondUserId, 120);
    expect(getTokenLimit(ownerId)).toBe(60_000);
    expect(reserveUserTokens(secondUserId, 80, 120_000)).toMatchObject({
      allowed: true,
      limit: 120,
      used: 80,
    });
    expect(reserveUserTokens(secondUserId, 50, 120_001)).toMatchObject({
      allowed: false,
      limit: 120,
      used: 80,
    });
    expect(reserveUserTokens(ownerId, 50, 120_001).allowed).toBe(true);
  });
});
