import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

export interface TokenRecord {
  token: string;
  userId: string;
  clientIp: string;
  issuedAt: number;
  expiresAt: number;
  revoked: boolean;
}

const tokenStore = new Map<string, TokenRecord>();
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1_000;

export function issueRefreshToken(userId: string, clientIp: string): string {
  const token = crypto.randomBytes(48).toString('hex');
  const now = Date.now();
  tokenStore.set(token, {
    token,
    userId,
    clientIp: normaliseIp(clientIp),
    issuedAt: now,
    expiresAt: now + REFRESH_TTL_MS,
    revoked: false,
  });
  return token;
}

export function validateRefreshToken(token: string, requestIp: string): string {
  const r = tokenStore.get(token);
  if (!r)        throw new RefreshTokenError('TOKEN_NOT_FOUND');
  if (r.revoked) throw new RefreshTokenError('TOKEN_REVOKED');
  if (Date.now() > r.expiresAt) {
    revokeToken(token);
    throw new RefreshTokenError('TOKEN_EXPIRED');
  }
  if (r.clientIp !== normaliseIp(requestIp)) {
    console.warn(`[SECURITY] IP mismatch: stored=${r.clientIp} request=${normaliseIp(requestIp)} userId=${r.userId}`);
    revokeToken(token);
    throw new RefreshTokenError('IP_MISMATCH');
  }
  return r.userId;
}

export function revokeToken(token: string): void {
  const r = tokenStore.get(token);
  if (r) tokenStore.set(token, { ...r, revoked: true });
}

function normaliseIp(ip: string): string {
  return ip.replace(/^::ffff:/, '').trim();
}

export class RefreshTokenError extends Error {
  constructor(public readonly code: string) {
    super(`Refresh token error: ${code}`);
    this.name = 'RefreshTokenError';
  }
}

export function extractClientIp(req: Request): string {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return req.socket.remoteAddress ?? '0.0.0.0';
}

export function refreshTokenMiddleware(req: Request & { userId?: string }, res: Response, next: NextFunction): void {
  const token = req.cookies?.refreshToken ?? (req.body as any)?.refreshToken;
  if (!token) {
    res.status(401).json({ error: 'MISSING_REFRESH_TOKEN' });
    return;
  }
  try {
    req.userId = validateRefreshToken(token, extractClientIp(req));
    next();
  } catch (err) {
    res.status(401).json({ error: err instanceof RefreshTokenError ? err.code : 'UNKNOWN' });
  }
}
