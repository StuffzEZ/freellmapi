import { Router } from 'express';
import type { Request, Response } from 'express';
import { z } from 'zod';
import {
  createUserApiKey,
  getTokenLimit,
  listUserApiKeys,
  revokeUserApiKey,
  setTokenLimit,
} from '../services/user-access.js';

export const accountRouter = Router();

function userId(req: Request): number | null {
  return (req as Request & { user?: { userId: number } }).user?.userId ?? null;
}

accountRouter.get('/access', (req: Request, res: Response) => {
  const id = userId(req);
  if (id == null) {
    res.status(401).json({ error: { message: 'Authentication required', type: 'authentication_error' } });
    return;
  }
  res.json({ tokensPerMinute: getTokenLimit(id), apiKeys: listUserApiKeys(id) });
});

accountRouter.put('/access/token-limit', (req: Request, res: Response) => {
  const id = userId(req);
  if (id == null) {
    res.status(401).json({ error: { message: 'Authentication required', type: 'authentication_error' } });
    return;
  }
  const parsed = z.object({
    tokensPerMinute: z.number().int().min(0).max(1_000_000_000),
  }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: 'tokensPerMinute must be an integer between 0 and 1000000000', type: 'invalid_request_error' } });
    return;
  }
  setTokenLimit(id, parsed.data.tokensPerMinute);
  res.json({ tokensPerMinute: parsed.data.tokensPerMinute });
});

accountRouter.post('/access/keys', (req: Request, res: Response) => {
  const id = userId(req);
  if (id == null) {
    res.status(401).json({ error: { message: 'Authentication required', type: 'authentication_error' } });
    return;
  }
  const parsed = z.object({ label: z.string().trim().max(80).optional() }).safeParse(req.body ?? {});
  if (!parsed.success) {
    res.status(400).json({ error: { message: 'Key label must be 80 characters or fewer', type: 'invalid_request_error' } });
    return;
  }
  const key = createUserApiKey(id, parsed.data.label ?? 'Default');
  res.status(201).json(key);
});

accountRouter.delete('/access/keys/:id', (req: Request, res: Response) => {
  const id = userId(req);
  if (id == null) {
    res.status(401).json({ error: { message: 'Authentication required', type: 'authentication_error' } });
    return;
  }
  const keyId = Number(req.params.id);
  if (!Number.isSafeInteger(keyId) || keyId < 1) {
    res.status(400).json({ error: { message: 'Invalid API key id', type: 'invalid_request_error' } });
    return;
  }
  if (!revokeUserApiKey(id, keyId)) {
    res.status(404).json({ error: { message: 'API key not found', type: 'not_found_error' } });
    return;
  }
  res.status(204).end();
});
